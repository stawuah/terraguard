use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::Path;
use std::time::Duration;
use std::thread;
use serde_json::Value;
use std::collections::HashMap;
use crate::monitor::DriftMonitor;
use crate::types::Severity;

#[derive(Parser)]
#[clap(about = "Security Group Drift Monitor")]
pub struct MonitorCli {
    #[clap(subcommand)]
    command: MonitorCommands,
}

#[derive(Subcommand)]
enum MonitorCommands {
    /// Monitor resources for security drifts
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

/// Resource to application mapping
#[derive(serde::Deserialize)]
struct ResourceMapping {
    resources: HashMap<String, String>,
}

pub fn run_monitor_cli() {
    let cli = MonitorCli::parse();
    
    match cli.command {
        MonitorCommands::Monitor { directory, mapping, interval } => {
            monitor_resources(&directory, &mapping, interval);
        },
       
        MonitorCommands::Metrics { application, format: _format} => {
            // In a real implementation, this would load metrics from a persistent store
            println!("Metrics command not fully implemented in this example");
            println!("Would display metrics for: {}", application.unwrap_or("all applications".to_string()));
        }
    }
}

/// Load resource mapping from a JSON file
fn load_resource_mapping(path: &str) -> ResourceMapping {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Could not read mapping file: {}", path));
    
    serde_json::from_str(&content)
        .unwrap_or_else(|_| panic!("Invalid JSON in mapping file: {}", path))
}

/// Monitor resources for security drifts
fn monitor_resources(directory: &str, mapping_path: &str, interval: u64) {
    println!("{}", "Starting continuous security drift monitoring...".blue().bold());
    println!("Monitoring directory: {}", directory);
    println!("Check interval: {} seconds", interval);
    
    // Create drift monitor
    let mut monitor = DriftMonitor::new();
    
    // Load resource to application mapping
    let mapping = load_resource_mapping(mapping_path);
    
    // Apply resource mapping
    for (resource_id, application) in &mapping.resources {
        monitor.map_resource_to_app(resource_id, application);
    }
    
    // Start monitoring loop
    let interval_duration = Duration::from_secs(interval);
    
    loop {
        println!("{}", "\n=== Running security drift check ===".cyan().bold());
        let check_time = chrono::Utc::now();
        println!("Check time: {}", check_time.format("%Y-%m-%d %H:%M:%S UTC"));
        
        // Scan directory for resource configuration files
        let mut drift_detected = false;
        if let Ok(entries) = fs::read_dir(directory) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_file() {
                        let path = entry.path();
                        if let Some(extension) = path.extension() {
                            if extension == "json" {
                                process_resource_file(&mut monitor, &path, &mut drift_detected);
                            }
                        }
                    }
                }
            }
        }
        
        // Display current metrics
        print_current_metrics(&monitor);
        
        // If any drift was detected in this run, show alert
        if drift_detected {
            println!("\n{}", "⚠️  SECURITY DRIFT DETECTED!".red().bold());
            print_recent_drifts(&monitor);
        } else {
            println!("\n{}", "✅ No security drift detected in this check.".green());
        }
        
        println!("\nNext check in {} seconds...", interval);
        thread::sleep(interval_duration);
    }
}

/// Process a single resource configuration file
fn process_resource_file(monitor: &mut DriftMonitor, path: &Path, drift_detected: &mut bool) {
    if let Some(file_name) = path.file_name() {
        if let Some(file_name_str) = file_name.to_str() {
            // Extract resource ID and type from filename
            // Assuming filename format: {resource_type}-{resource_id}.json
            if let Some((resource_type, resource_id)) = file_name_str
                .trim_end_matches(".json")
                .split_once('-') 
            {
                println!("Checking resource: {} ({})", resource_id, resource_type);
                
                // Load resource configuration
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(config) = serde_json::from_str::<Value>(&content) {
                        // Check for drift
                        if let Some(drift_event) = monitor.check_resource(resource_id, resource_type, &config) {
                            *drift_detected = true;
                            
                            // Print drift alert
                            println!("  {} Drift detected in {} at {}", 
                                "⚠️".red().bold(),
                                resource_id.yellow().bold(),
                                drift_event.detected_at.format("%H:%M:%S"));
                            
                            // Print new issues
                            if !drift_event.new_issues.is_empty() {
                                println!("  {} New issues:", "•".red());
                                for issue in &drift_event.new_issues {
                                    println!("    - [{}] {}", 
                                        format!("{:?}", issue.severity).red().bold(),
                                        issue.message);
                                }
                            }
                            
                            // Print resolved issues
                            if !drift_event.resolved_issues.is_empty() {
                                println!("  {} Resolved issues:", "•".green());
                                for issue in &drift_event.resolved_issues {
                                    println!("    - [{}] {}", 
                                        format!("{:?}", issue.severity).green(),
                                        issue.message);
                                }
                            }
                        } else {
                            println!("  {} No changes", "✓".green());
                        }
                    } else {
                        println!("  {} Invalid JSON format", "✗".red());
                    }
                } else {
                    println!("  {} Could not read file", "✗".red());
                }
            }
        }
    }
}

/// Print current metrics for all applications
fn print_current_metrics(monitor: &DriftMonitor) {
    println!("\n{}", "=== Current Application Metrics ===".cyan().bold());
    
    let metrics = monitor.get_application_metrics();
    if metrics.is_empty() {
        println!("No application metrics available yet.");
        return;
    }
    
    for app_metrics in metrics {
        println!("\n{} ({})", 
            app_metrics.name.yellow().bold(),
            format!("{} resources", app_metrics.resource_count).cyan());
        
        // Print issue counts by severity
        println!("  Issues: ");
        for severity in [Severity::High, Severity::Medium, Severity::Low] {
            let count = app_metrics.issues.get(&severity).cloned().unwrap_or(0);
            let color_text = match severity {
                Severity::High => count.to_string().red().bold(),
                Severity::Medium => count.to_string().yellow(),
                Severity::Low => count.to_string().green(),
            };
            println!("    - {:?}: {}", severity, color_text);
        }
        
        // Print drift stats
        println!("  Drifts: {}", app_metrics.total_drifts);
        if let Some(last_drift) = app_metrics.last_drift {
            println!("  Last drift: {}", last_drift.format("%Y-%m-%d %H:%M:%S"));
        } else {
            println!("  Last drift: Never");
        }
    }
}

/// Print recent drift events
fn print_recent_drifts(monitor: &DriftMonitor) {
    let drifts = monitor.get_recent_drifts();
    if drifts.is_empty() {
        return;
    }
    
    println!("\n{}", "=== Recent Drift Events ===".red().bold());
    
    // Group drifts by application
    let mut app_drifts: HashMap<String, Vec<&crate::monitor::DriftEvent>> = HashMap::new();
    for drift in drifts {
        app_drifts.entry(drift.application.clone())
            .or_default()
            .push(drift);
    }
    
    // Print drifts by application
    for (app, events) in app_drifts {
        println!("\n{} ({})", app.yellow().bold(), format!("{} drifts", events.len()).cyan());
        
        // Show the 5 most recent events
        for event in events.iter().rev().take(5) {
            println!("  • {} - {} in {}", 
                event.detected_at.format("%Y-%m-%d %H:%M:%S"),
                event.resource_type.cyan(),
                event.resource_id.bold());
            
            let new_issues_count = event.new_issues.len();
            let resolved_issues_count = event.resolved_issues.len();
            
            if new_issues_count > 0 {
                println!("    {} new issues", new_issues_count.to_string().red());
            }
            
            if resolved_issues_count > 0 {
                println!("    {} resolved issues", resolved_issues_count.to_string().green());
            }
        }
    }
}