use clap::{Parser, Subcommand};

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
        None => {
            println!("No subcommand provided. Try `toppy doctor`.");
        }
    }
}
