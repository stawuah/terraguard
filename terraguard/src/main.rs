mod rules;
mod types;
mod report;
mod monitor;
mod monitor_cli;

use crate::report::print_report;
use crate::monitor_cli::run_monitor_cli;
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::fs;
use std::process;

#[derive(Parser)]
#[clap(name = "terraguard", about = "Lightweight, blazing-fast Rust CLI tool to detect Terraform security drifts")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a Terraform plan for security issues
    #[clap(name = "validate")]
    Validate {
        /// Input Terraform plan JSON file
        #[clap(name = "INPUT")]
        input: String,
    },
    
    /// Run continuous security monitoring
    #[clap(name = "monitor")]
    Monitor,
}

fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Validate { input } => {
            run_validation(input);
        },
        Commands::Monitor => {
            run_monitor_cli();
        }
    }
}

fn run_validation(input: String) {
    let data = fs::read_to_string(&input).unwrap_or_else(|_| {
        eprintln!("❌ Error reading file: {}", &input);
        process::exit(1);
    });
    
    let plan: Value = serde_json::from_str(&data).unwrap_or_else(|_| {
        eprintln!("❌ Error parsing JSON from file: {}", &input);
        process::exit(1);
    });
    
    let issues = rules::fast_validate(&plan);
    print_report(&issues);
}