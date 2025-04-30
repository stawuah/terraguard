use serde::Deserialize;
use colored::*;


#[derive(Debug, Deserialize)]
pub struct Plan {
    pub resource_changes: Vec<ResourceChange>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceChange {
    pub address: String,
    pub change: Change,
}

#[derive(Debug, Deserialize)]
pub struct Change {
    pub after: Option<serde_json::Value>,
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

pub struct Issue {
    pub resource: String,
    pub message: String,
    pub severity: Severity,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = match self {
            Severity::Low => "LOW".green(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::High => "HIGH".red().bold(),
        };
        write!(f, "{}", output)
    }
}
