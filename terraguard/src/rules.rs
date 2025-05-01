
use serde_json::Value;
use crate::types::{Issue, Severity};
use std::collections::{HashMap, HashSet};
/// Fast plan validator that focuses on efficiently validating
/// security configurations in infrastructure plans
pub struct FastValidator {
    // Cache port information for quick lookups
    port_services: HashMap<i32, &'static str>,
    disallowed_ports: HashSet<i32>,
    allowed_ports: HashSet<i32>,
    
    // Cache for already validated resources to avoid duplicate work
    validated_resources: HashSet<String>
}

impl FastValidator {
    /// Create a new FastValidator with pre-configured security rules
    pub fn new() -> Self {
        // Map ports to their common services for better messages
        let port_services: HashMap<i32, &'static str> = [
            (22, "SSH"),
            (3389, "RDP"),
            (23, "Telnet"),
            (21, "FTP"),
            (25, "SMTP"),
            (53, "DNS"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (27017, "MongoDB"),
            (6379, "Redis"),
            (1433, "MSSQL"),
            (8080, "HTTP-Alt"),
            (8443, "HTTPS-Alt"),
        ].iter().cloned().collect();

        // Sensitive ports that should be handled with care
        let disallowed_ports: HashSet<i32> = vec![
            22,    // SSH
            3389,  // RDP
            23,    // Telnet
            21,    // FTP
            25,    // SMTP
            53,    // DNS
        ].into_iter().collect();

        // Explicitly allowed ports
        let allowed_ports: HashSet<i32> = vec![
            80,    // HTTP
            443,   // HTTPS
            8080,  // HTTP-Alt
            8443   // HTTPS-Alt
        ].into_iter().collect();

        Self {
            port_services,
            disallowed_ports,
            allowed_ports,
            validated_resources: HashSet::new()
        }
    }

    /// Validate a plan and return a list of security issues
    pub fn validate(&mut self, plan: &Value) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Step 1: Process "resource_changes" - handles Terraform plan format
        if let Some(resource_changes) = plan.get("resource_changes").and_then(|v| v.as_array()) {
            for rc in resource_changes {
                if let Some(address) = rc.get("address").and_then(|a| a.as_str()) {
                    // Skip already validated resources
                    if self.validated_resources.contains(address) {
                        continue;
                    }
                    
                    self.validated_resources.insert(address.to_string());
                    
                    if let Some(after) = rc.get("change").and_then(|c| c.get("after")) {
                        // Process security groups
                        if address.contains("aws_security_group") {
                            issues.extend(self.check_security_group(address.to_string(), after));
                        }
                        
                        // Process EC2 instances
                        if address.contains("aws_instance") {
                            issues.extend(self.check_ec2_instance(address.to_string(), after));
                        }
                        
                        // Process S3 buckets
                        if address.contains("aws_s3_bucket") {
                            issues.extend(self.check_s3_bucket(address.to_string(), after));
                        }
                    }
                }
            }
        }
        // Step 2: Process "resources" - handles CloudFormation/raw plan format
        else if let Some(resources) = plan.get("resources").and_then(|v| v.as_object()) {
            for (address, resource) in resources {
                // Skip already validated resources
                if self.validated_resources.contains(address) {
                    continue;
                }
                
                self.validated_resources.insert(address.to_string());
                
                // Process based on resource type
                if address.contains("SecurityGroup") {
                    issues.extend(self.check_security_group(address.to_string(), resource));
                } else if address.contains("Instance") || address.contains("EC2") {
                    issues.extend(self.check_ec2_instance(address.to_string(), resource));
                } else if address.contains("S3") || address.contains("Bucket") {
                    issues.extend(self.check_s3_bucket(address.to_string(), resource));
                }
            }
        }

        issues
    }

    /// Check security group for issues
   pub  fn check_security_group(&self, address: String, resource: &Value) -> Vec<Issue> {
        let mut issues = Vec::new();
        
        // Check for open ingress
        issues.extend(self.check_open_ingress(address.clone(), resource));
        
        // Check for disallowed ports
        issues.extend(self.check_ports(address, resource));
        
        issues
    }
    
    /// Check for open ingress from 0.0.0.0/0
    fn check_open_ingress(&self, address: String, resource: &Value) -> Vec<Issue> {
        let mut issues = Vec::new();

        if let Some(ingress) = resource.get("ingress").and_then(|i| i.as_array()) {
            for rule in ingress {
                // Check CIDR blocks
                if let Some(blocks) = rule.get("cidr_blocks").and_then(|b| b.as_array()) {
                    for cidr in blocks {
                        if let Some(cidr_str) = cidr.as_str() {
                            if cidr_str == "0.0.0.0/0" {
                                // Check what port this open ingress applies to
                                let port_info = if let (Some(from), Some(to)) = (
                                    rule.get("from_port").and_then(|p| p.as_i64()), 
                                    rule.get("to_port").and_then(|p| p.as_i64())
                                ) {
                                    let from = from as i32;
                                    let to = to as i32;
                                    
                                    // Check if any of these ports are particularly sensitive
                                    let mut port_text = format!("ports {}-{}", from, to);
                                    
                                    // If it's a single port, try to identify the service
                                    if from == to && self.port_services.contains_key(&from) {
                                        port_text = format!("port {} ({})", from, self.port_services[&from]);
                                    }
                                    
                                    port_text
                                } else {
                                    "all ports".to_string()
                                };
                                
                                issues.push(Issue {
                                    resource: address.clone(),
                                    message: format!("Open ingress from 0.0.0.0/0 for {}", port_info),
                                    severity: Severity::High,
                                });
                                
                                // Only add the issue once per rule to avoid duplicates
                                break;
                            }
                        }
                    }
                }
                
                // Also check IPv6 CIDR blocks
                if let Some(blocks) = rule.get("ipv6_cidr_blocks").and_then(|b| b.as_array()) {
                    for cidr in blocks {
                        if let Some(cidr_str) = cidr.as_str() {
                            if cidr_str == "::/0" {
                                issues.push(Issue {
                                    resource: address.clone(),
                                    message: "Open ingress from ::/0 (all IPv6 addresses)".to_string(),
                                    severity: Severity::High,
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        issues
    }

    /// Check ports against allowed and disallowed lists
   pub  fn check_ports(&self, resource_address: String, resource: &Value) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Check ingress rules
        if let Some(ingress_rules) = resource.get("ingress") {
            if let Some(rules) = ingress_rules.as_array() {
                for rule in rules {
                    if let (Some(from_port), Some(to_port)) = (rule.get("from_port"), rule.get("to_port")) {
                        if let (Some(f), Some(t)) = (from_port.as_i64(), to_port.as_i64()) {
                            let f = f as i32;
                            let t = t as i32;

                            // Check port range
                            if f != t {
                                // Check if range contains disallowed ports
                                let has_disallowed = self.disallowed_ports.iter()
                                    .any(|&p| p >= f && p <= t);
                                
                                if has_disallowed {
                                    issues.push(Issue {
                                        resource: resource_address.clone(),
                                        message: format!("Port range {}-{} contains disallowed ports", f, t),
                                        severity: Severity::High,
                                    });
                                } else if t - f > 1000 {
                                    // Large port ranges are suspicious
                                    issues.push(Issue {
                                        resource: resource_address.clone(),
                                        message: format!("Overly permissive port range {}-{}", f, t),
                                        severity: Severity::Medium,
                                    });
                                }
                            } else {
                                // Single port checks
                                // Check from_port (same as to_port in this case)
                                if self.disallowed_ports.contains(&f) {
                                    let service = self.port_services.get(&f).unwrap_or(&"unknown service");
                                    issues.push(Issue {
                                        resource: resource_address.clone(),
                                        message: format!("Port {} ({}) is disallowed for inbound traffic", f, service),
                                        severity: Severity::High,
                                    });
                                } else if !self.allowed_ports.contains(&f) {
                                    issues.push(Issue {
                                        resource: resource_address.clone(),
                                        message: format!("Port {} is not explicitly allowed for inbound traffic", f),
                                        severity: Severity::Medium,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check egress rules
        if let Some(egress_rules) = resource.get("egress") {
            if let Some(rules) = egress_rules.as_array() {
                for rule in rules {
                    // Check for overly permissive egress
                    if let Some(cidr_blocks) = rule.get("cidr_blocks").and_then(|b| b.as_array()) {
                        for cidr in cidr_blocks {
                            if cidr == "0.0.0.0/0" {
                                // Check if this is for all ports
                                let all_ports = rule.get("from_port").and_then(|p| p.as_i64()).unwrap_or(0) == 0 &&
                                              rule.get("to_port").and_then(|p| p.as_i64()).unwrap_or(0) == 0;
                                
                                if all_ports {
                                    issues.push(Issue {
                                        resource: resource_address.clone(),
                                        message: "Unrestricted egress to 0.0.0.0/0 for all ports".to_string(),
                                        severity: Severity::Medium,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    
                    // Check specific ports
                    if let (Some(from_port), Some(to_port)) = (rule.get("from_port"), rule.get("to_port")) {
                        if let (Some(f), Some(t)) = (from_port.as_i64(), to_port.as_i64()) {
                            let f = f as i32;
                            let t = t as i32;
                            
                            // Check for overly permissive ranges
                            if t - f > 1000 {
                                issues.push(Issue {
                                    resource: resource_address.clone(),
                                    message: format!("Overly permissive egress port range {}-{}", f, t),
                                    severity: Severity::Low,
                                });
                            }
                        }
                    }
                }
            }
        }

        issues
    }
    
    /// Check EC2 instance configuration for security issues
   pub fn check_ec2_instance(&self, address: String, resource: &Value) -> Vec<Issue> {
        let mut issues = Vec::new();
    
        // Check for public IP assignment
        if let Some(public_ip) = resource.get("associate_public_ip_address") {
            if public_ip.as_bool().unwrap_or(false) {
                issues.push(Issue {
                    resource: address.clone(),
                    message: "Instance has a public IP address assigned".to_string(),
                    severity: Severity::Medium,
                });
            }
        }
        
        // Check for IMDSv2 enforcement
        if let Some(metadata_options) = resource.get("metadata_options") {
            if let Some(http_tokens) = metadata_options.get("http_tokens") {
                if http_tokens.as_str().unwrap_or("") != "required" {
                    issues.push(Issue {
                        resource: address,
                        message: "IMDSv2 (token-based) is not enforced, vulnerable to SSRF attacks".to_string(),
                        severity: Severity::High,
                    });
                }
            }
        }
        
        issues
    }
    
    /// Check S3 bucket configuration for security issues
    pub fn check_s3_bucket(&self, address: String, resource: &Value) -> Vec<Issue> {
        let mut issues = Vec::new();
        
        // Check for public access configuration
        if let Some(acl) = resource.get("acl").and_then(|a| a.as_str()) {
            if acl == "public-read" || acl == "public-read-write" {
                issues.push(Issue {
                    resource: address.clone(),
                    message: format!("S3 bucket has public access enabled (ACL: {})", acl),
                    severity: Severity::High,
                });
            }
        }
        
        // Check for encryption
        let encryption_enabled = resource.get("server_side_encryption_configuration").is_some();
        if !encryption_enabled {
            issues.push(Issue {
                resource: address.clone(),
                message: "S3 bucket is missing server-side encryption".to_string(),
                severity: Severity::Medium,
            });
        }
        
        // Check for versioning
        if let Some(versioning) = resource.get("versioning") {
            if let Some(enabled) = versioning.get("enabled") {
                if !enabled.as_bool().unwrap_or(false) {
                    issues.push(Issue {
                        resource: address,
                        message: "S3 bucket versioning is not enabled".to_string(),
                        severity: Severity::Low,
                    });
                }
            }
        }
        
        issues
    }
}

/// Fast validation implementation that uses the FastValidator struct
pub fn fast_validate(plan: &Value) -> Vec<Issue> {
    let mut validator = FastValidator::new();
    validator.validate(plan)
}
