
mod rules;
mod types;
mod report;

use crate::report::print_report;
use clap::Parser;
use serde_json::Value;
use std::fs;
use std::process;

#[derive(Parser)]
struct Cli {
    /// Input Terraform plan JSON file
    #[arg(name = "INPUT")]
    input: String,
}

fn main() {
    let cli = Cli::parse();

    let data = fs::read_to_string(&cli.input).unwrap_or_else(|_| {
        eprintln!("❌ Error reading file: {}", &cli.input);
        process::exit(1);
    });

    let plan: Value = serde_json::from_str(&data).unwrap_or_else(|_| {
        eprintln!("❌ Error parsing JSON from file: {}", &cli.input);
        process::exit(1);
    });

    let issues = rules::fast_validate(&plan);
    print_report(&issues);
}

