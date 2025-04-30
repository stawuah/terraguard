use crate::types::{Issue, Severity};
use colored::*;

pub fn print_report(issues: &[Issue]) {
    if issues.is_empty() {
        println!("{}", "✅ No security issues found.".green().bold());
    } else {
        let high_severity_issues: Vec<&Issue> = issues
            .iter()
            .filter(|issue| issue.severity == Severity::High)
            .collect();

        if !high_severity_issues.is_empty() {
            // First, print High severity issues
            println!("{}", "⚠️  High Severity Issues Found:".red().bold());
            for issue in high_severity_issues {
                let severity_text = match issue.severity {
                    Severity::Low => "LOW".yellow(),
                    Severity::Medium => "MEDIUM".magenta(),
                    Severity::High => "HIGH".red().bold(),
                };

                println!(
                    "[{}] {}: {}",
                    severity_text,
                    issue.resource.bold(),
                    issue.message
                );
            }
        }

        // Then, print Medium and Low severity issues if any
        let other_issues: Vec<&Issue> = issues
            .iter()
            .filter(|issue| issue.severity != Severity::High)
            .collect();

        if !other_issues.is_empty() {
            println!("{}", "⚠️  Other Security Issues Found:".yellow().bold());
            for issue in other_issues {
                let severity_text = match issue.severity {
                    Severity::Low => "LOW".yellow(),
                    Severity::Medium => "MEDIUM".magenta(),
                    Severity::High => "HIGH".red().bold(),
                };

                println!(
                    "[{}] {}: {}",
                    severity_text,
                    issue.resource.bold(),
                    issue.message
                );
            }
        }
    }
}
