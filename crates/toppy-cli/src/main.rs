use clap::{Parser, Subcommand};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use toppy_core::policy::{Decision, Policy, Target};

/// Toppy command-line interface
#[derive(Parser)]
#[command(name = "toppy", author, version, about = "Toppy CLI for managing MASQUE connections", long_about = None)]
struct Cli {
    /// Subcommands for the CLI
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run diagnostic checks and output a report in JSON
    Doctor {
        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Start a local TCP forwarder to an allowed target
    Up {
        /// Target to connect to (ip:port)
        #[arg(long)]
        target: String,
        /// Local listen address (ip:port)
        #[arg(long)]
        listen: String,
        /// Exit after a single connection
        #[arg(long)]
        once: bool,
    },
}

fn parse_socket_addr(label: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid {} {}: {}", label, value, e))
}

fn proxy_connection(mut inbound: TcpStream, target: SocketAddr) -> io::Result<()> {
    let mut outbound = TcpStream::connect(target)?;
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);

    let mut inbound_clone = inbound.try_clone()?;
    let mut outbound_clone = outbound.try_clone()?;

    let t1 = thread::spawn(move || io::copy(&mut inbound_clone, &mut outbound));
    let t2 = thread::spawn(move || io::copy(&mut outbound_clone, &mut inbound));

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn proxy_once(inbound: TcpStream, target: SocketAddr) -> io::Result<()> {
    let _ = inbound.set_nodelay(true);
    let outbound = TcpStream::connect(target)?;
    let _ = outbound.set_nodelay(true);
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Doctor { json }) => {
            // Invoke the doctor checks from toppy_core and print JSON
            let report = toppy_core::doctor::doctor_check();
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => println!("{}", json),
                    Err(e) => eprintln!("Failed to serialize doctor report: {}", e),
                }
            } else {
                println!("doctor: {}", report.overall);
                println!("version: {}", report.version);
                for check in report.checks {
                    println!("- [{}] {}: {}", check.status, check.id, check.summary);
                }
            }
        }
        Some(Commands::Up {
            target,
            listen,
            once,
        }) => {
            let (cfg, path) = match toppy_core::config::load_config() {
                Ok((cfg, path)) => (cfg, path),
                Err(err) => {
                    eprintln!("Failed to load config: {}", err);
                    std::process::exit(1);
                }
            };
            if let Err(err) = cfg.validate() {
                eprintln!("Config validation failed ({}): {}", path.display(), err);
                std::process::exit(1);
            }

            let target_addr = match parse_socket_addr("target", &target) {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };
            let listen_addr = match parse_socket_addr("listen", &listen) {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };

            let policy = match cfg.policy.as_ref() {
                Some(policy_cfg) => match Policy::from_config(policy_cfg) {
                    Ok(policy) => policy,
                    Err(err) => {
                        eprintln!("Policy config invalid: {}", err);
                        std::process::exit(1);
                    }
                },
                None => Policy { allow: Vec::new() },
            };
            let target_policy = Target {
                ip: target_addr.ip(),
                port: target_addr.port(),
            };
            match policy.evaluate(&target_policy) {
                Decision::Allow => {}
                Decision::Deny { reason } => {
                    eprintln!("Policy denied: {}", reason);
                    std::process::exit(2);
                }
            }

            let listener = match TcpListener::bind(listen_addr) {
                Ok(listener) => listener,
                Err(err) => {
                    eprintln!("Failed to bind {}: {}", listen_addr, err);
                    std::process::exit(1);
                }
            };
            let local_addr = match listener.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("Failed to read local addr: {}", err);
                    std::process::exit(1);
                }
            };
            println!("toppy up listening on {} -> {}", local_addr, target_addr);

            for stream in listener.incoming() {
                match stream {
                    Ok(inbound) => {
                        if once {
                            if let Err(err) = proxy_once(inbound, target_addr) {
                                eprintln!("proxy connection failed: {}", err);
                            }
                            break;
                        }
                        let target = target_addr;
                        thread::spawn(move || {
                            if let Err(err) = proxy_connection(inbound, target) {
                                eprintln!("proxy connection failed: {}", err);
                            }
                        });
                    }
                    Err(err) => {
                        eprintln!("accept failed: {}", err);
                        if once {
                            break;
                        }
                    }
                }
            }
        }
        None => {
            println!("No subcommand provided. Try `toppy doctor`.");
        }
    }
}
