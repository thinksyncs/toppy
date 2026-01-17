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
    Doctor,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Doctor) => {
            // Invoke the doctor checks from toppy_core and print JSON
            let report = toppy_core::doctor::doctor_check();
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Failed to serialize doctor report: {}", e),
            }
        }
        None => {
            println!("No subcommand provided. Try `toppy doctor`.");
        }
    }
}