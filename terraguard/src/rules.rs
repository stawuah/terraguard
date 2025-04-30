use std::collections::HashSet;
use serde_json::Value;
use crate::types::{Issue, Severity};

pub fn validate(plan: &Value) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Step 1: Get "resource_changes"
    if let Some(resource_changes) = plan.get("resource_changes").and_then(|v| v.as_array()) {
        for rc in resource_changes {
            let address = rc.get("address").and_then(|a| a.as_str()).unwrap_or("unknown");
            let after = rc.get("change")
                    .and_then(|c| c.get("after"));

            if let Some(after_val) = after {
                issues.extend(check_open_ingress(address.to_string(), after_val));
            }

            if let Some(after_value ) = after  {
                issues.extend(check_allowed_ports(address.to_string(), after_value));
            }
        }
    }

    issues
}

fn check_open_ingress(address: String, after: &Value) -> Vec<Issue> {
    let mut issues = Vec::new();

    if let Some(ingress) = after.get("ingress").and_then(|i| i.as_array()) {
        for rule in ingress {
            if let Some(blocks) = rule.get("cidr_blocks").and_then(|b| b.as_array()) {
                for cidr in blocks {
                    if cidr == "0.0.0.0/0" {
                        issues.push(Issue {
                            resource: address.clone(),
                            message: "Open ingress from 0.0.0.0/0".to_string(),
                            severity: Severity::High,
                        });
                    }
                }
            }
        }
    }

    issues
}


pub fn check_allowed_ports(resource_address: String, after: &Value) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Sensitive ports that should be handled with care (like SSH, RDP)
    let disallowed_ports: HashSet<i32> = vec![
        22,    // SSH
        3389,  // RDP
        23,    // Telnet
        21,    // FTP
        25,    // SMTP
        53,    // DNS
    ]
    .into_iter()
    .collect();

    // You can expand the accepted port range based on your use case
    let allowed_ports: HashSet<i32> = vec![80, 443] // Typically allowed ports
        .into_iter()
        .collect();

    if let Some(ingress_rules) = after.get("ingress") {
        if let Some(rules) = ingress_rules.as_array() {
            for rule in rules {
                if let (Some(from_port), Some(to_port)) = (rule.get("from_port"), rule.get("to_port")) {
                    if let (Some(f), Some(t)) = (from_port.as_i64(), to_port.as_i64()) {
                        let f = f as i32;
                        let t = t as i32;

                        // Check from_port
                        if disallowed_ports.contains(&f) {
                            issues.push(Issue {
                                resource: resource_address.clone(),
                                message: format!("From Port {} is disallowed", f),
                                severity: Severity::High,
                            });
                        } else if !allowed_ports.contains(&f) {
                            issues.push(Issue {
                                resource: resource_address.clone(),
                                message: format!("From Port {} not recommended but accepted !", f),
                                severity: Severity::Medium,
                            });
                        }

                        // Check to_port
                        if disallowed_ports.contains(&t) {
                            issues.push(Issue {
                                resource: resource_address.clone(),
                                message: format!("To Port {} is disallowed \n", t),
                                severity: Severity::High,
                            });
                        } else if !allowed_ports.contains(&t) {
                            issues.push(Issue {
                                resource: resource_address.clone(),
                                message: format!("To Port {} not recommended but accepted !", t),
                                severity: Severity::Medium,
                            });
                        }
                    }
                }
            }
        }
    }

    issues
}