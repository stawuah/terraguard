mod rules;
mod types;
mod report;
mod monitor;

use crate::report::print_report;
use crate::monitor::{monitor_resources, display_metrics};
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
    Monitor {
        /// Directory containing resource configuration files to monitor
        #[clap(long, short = 'd')]
        directory: String,
        
        /// Resource mapping file that maps resources to applications
        #[clap(long, short = 'm')]
        mapping: String,
        
        /// Interval in seconds between checks
        #[clap(long, short = 'i', default_value = "60")]
        interval: u64,
    },
    
    /// Display the latest metrics for all applications
    #[clap(name = "metrics")]
    Metrics {
        /// Optional application name to filter metrics
        #[clap(long, short = 'a')]
        application: Option<String>,
        
        /// Output format (text, json)
        #[clap(long, short = 'f', default_value = "text")]
        format: String,
    }
}

fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Validate { input } => {
            run_validation(input);
        },
        Commands::Monitor { directory, mapping, interval } => {
            monitor_resources(&directory, &mapping, interval);
        },
        Commands::Metrics { application, format } => {
            display_metrics(application, &format);
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