use clap::{Parser, Subcommand};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use toppy_core::audit::{
    append_event, default_audit_log_path, now_unix_ms, verify_chain, AuditEvent,
};
use toppy_core::config::{ClientAuthConfig, SessionRateLimit};
use toppy_core::policy::{Decision, Policy, Target};

mod rate_copy;

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
    /// Acquire and cache an auth token (skeleton)
    Login {
        /// Print the resolved token to stdout (token mode only)
        #[arg(long)]
        print_token: bool,
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

    /// Audit log utilities
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Verify the local audit log hash chain
    Verify {
        /// Path to the audit JSONL file
        #[arg(long)]
        path: Option<String>,
    },
}

fn audit_log_path_from_env_or_config() -> Option<std::path::PathBuf> {
    if let Ok(value) = std::env::var("TOPPY_AUDIT_LOG") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed.into());
        }
    }
    if let Ok((cfg, _)) = toppy_core::config::load_config() {
        if let Some(p) = cfg.audit_log_path {
            let trimmed = p.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed.into());
            }
        }
    }
    None
}

fn current_actor() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn try_audit_event(action: &str, target: &str, allowed: bool, reason: Option<String>) {
    let path = audit_log_path_from_env_or_config().unwrap_or_else(default_audit_log_path);
    let event = AuditEvent {
        actor: current_actor(),
        action: action.to_string(),
        target: target.to_string(),
        allowed,
        reason,
    };
    if let Err(err) = append_event(path, now_unix_ms(), event) {
        eprintln!("audit log write failed: {}", err);
    }
}

fn parse_socket_addr(label: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid {} {}: {}", label, value, e))
}

fn proxy_connection(
    mut inbound: TcpStream,
    target: SocketAddr,
    limit: SessionRateLimit,
) -> io::Result<()> {
    let mut outbound = TcpStream::connect(target)?;
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);

    let mut inbound_clone = inbound.try_clone()?;
    let mut outbound_clone = outbound.try_clone()?;

    let t1 = thread::spawn(move || {
        rate_copy::copy_rate_limited(&mut inbound_clone, &mut outbound, limit)
    });
    let t2 = thread::spawn(move || {
        rate_copy::copy_rate_limited(&mut outbound_clone, &mut inbound, limit)
    });

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
            // Best-effort audit log: record the overall outcome.
            try_audit_event(
                "doctor",
                "doctor",
                report.overall != "fail",
                Some(format!("overall={}", report.overall)),
            );
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
        Some(Commands::Login { print_token }) => {
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

            match cfg.auth.as_ref() {
                None | Some(ClientAuthConfig::Token { .. }) => {
                    let token = cfg
                        .resolve_auth_token()
                        .map_err(|e| format!("failed to resolve auth token: {}", e));
                    match token {
                        Ok(Some(token)) => {
                            if print_token {
                                println!("{}", token);
                            } else {
                                println!(
                                    "auth: token mode (configured). Use `toppy up` / `toppy doctor`."
                                );
                            }
                        }
                        Ok(None) => {
                            eprintln!(
                                "auth: token mode requires a token. Set `auth_token = \"...\"` or `[auth] mode = \"token\"` with `token = \"...\"`."
                            );
                            std::process::exit(2);
                        }
                        Err(err) => {
                            eprintln!("auth: {}", err);
                            std::process::exit(1);
                        }
                    }
                }
                Some(ClientAuthConfig::OidcDeviceCode { .. }) => {
                    eprintln!("auth: OIDC device-code login is not implemented yet in this repo.");
                    eprintln!(
                        "For now, mint a JWT or shared token out-of-band and set `auth_token`."
                    );
                    std::process::exit(1);
                }
                Some(ClientAuthConfig::Saml { .. }) => {
                    eprintln!("auth: direct SAML login is not implemented yet in this repo.");
                    eprintln!(
                        "For now, use a SAML-to-OIDC broker (or mint a JWT) and set `auth_token`."
                    );
                    std::process::exit(1);
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
                    try_audit_event("up", &target, false, Some("config load failed".to_string()));
                    std::process::exit(1);
                }
            };
            if let Err(err) = cfg.validate() {
                eprintln!("Config validation failed ({}): {}", path.display(), err);
                try_audit_event(
                    "up",
                    &target,
                    false,
                    Some(format!("config validation failed: {}", err)),
                );
                std::process::exit(1);
            }

            let session_rate_limit = cfg.session_rate_limit();

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
                    try_audit_event("up", &target, false, Some(reason));
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

            // Record that the forwarder was started. Subsequent connection failures are still
            // reported to stderr by the proxy threads.
            try_audit_event(
                "up",
                &target,
                true,
                Some(format!("listening={}", local_addr)),
            );

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
                        let limit = session_rate_limit;
                        thread::spawn(move || {
                            if let Err(err) = proxy_connection(inbound, target, limit) {
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
        Some(Commands::Audit { command }) => match command {
            AuditCommands::Verify { path } => {
                let path = path
                    .map(std::path::PathBuf::from)
                    .or_else(audit_log_path_from_env_or_config)
                    .unwrap_or_else(default_audit_log_path);
                match verify_chain(&path) {
                    Ok(()) => {
                        println!("audit ok: {}", path.display());
                        std::process::exit(0);
                    }
                    Err(err) => {
                        eprintln!("audit invalid: {}: {}", path.display(), err);
                        std::process::exit(1);
                    }
                }
            }
        },
        None => {
            println!("No subcommand provided. Try `toppy doctor`.");
        }
    }
}
