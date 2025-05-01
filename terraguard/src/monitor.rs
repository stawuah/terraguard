

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::types::{Issue, Severity};
use crate::rules::FastValidator;
use serde_json::Value;
use chrono::{DateTime, Utc};



/// Contains historical data about a single resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceHistory {
    /// Resource identifier
    pub resource_id: String,
    /// Resource type (security group, instance, etc.)
    pub resource_type: String,
    /// Application this resource belongs to
    pub application: String,
    /// When this resource was first seen
    pub first_seen: DateTime<Utc>,
    /// When this resource was last modified
    pub last_modified: DateTime<Utc>,
    /// Previous state snapshots (to detect drift)
    pub state_history: Vec<ResourceState>,
    /// Current issues found in this resource
    pub current_issues: Vec<Issue>,
    /// Number of times this resource has drifted
    pub drift_count: u32,
}

/// Single point-in-time resource state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceState {
    /// When this state was captured
    pub captured_at: DateTime<Utc>,
    /// The resource configuration
    pub configuration: Value,
    /// Hash of the configuration for fast comparison
    pub config_hash: String,
}

/// Drift event representing a change in resource configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    /// When the drift was detected
    pub detected_at: DateTime<Utc>,
    /// Resource that drifted
    pub resource_id: String,
    /// Resource type
    pub resource_type: String,
    /// Application this resource belongs to
    pub application: String,
    /// Issues introduced by this drift
    pub new_issues: Vec<Issue>,
    /// Issues fixed by this drift
    pub resolved_issues: Vec<Issue>,
}

/// Application metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApplicationMetrics {
    /// Application name
    pub name: String,
    /// Number of resources tracked for this application
    pub resource_count: usize,
    /// Total number of issues per severity
    pub issues: HashMap<Severity, u32>,
    /// Total number of drifts detected
    pub total_drifts: u32,
    /// Last time a drift was detected
    pub last_drift: Option<DateTime<Utc>>,
}

/// DriftMonitor is responsible for tracking resource states over time
/// and detecting changes (drift) in security configurations
pub struct DriftMonitor {
    /// Map of resource ID to its history
    resource_history: HashMap<String, ResourceHistory>,
    /// Map of application name to metrics
    application_metrics: HashMap<String, ApplicationMetrics>,
    /// Resource to application mapping
    resource_to_app: HashMap<String, String>,
    /// Validator to check for security issues
    validator: FastValidator,
    /// Latest drift events
    recent_drifts: Vec<DriftEvent>,
    /// Maximum events to keep in history
    max_history_events: usize,
}

impl DriftMonitor {
    /// Create a new drift monitor
    pub fn new() -> Self {
        Self {
            resource_history: HashMap::new(),
            application_metrics: HashMap::new(),
            resource_to_app: HashMap::new(),
            validator: FastValidator::new(),
            recent_drifts: Vec::new(),
            max_history_events: 100,
        }
    }

    /// Map a resource to an application
    pub fn map_resource_to_app(&mut self, resource_id: &str, application: &str) {
        self.resource_to_app.insert(resource_id.to_string(), application.to_string());
        
        // Ensure we have metrics for this application
        if !self.application_metrics.contains_key(application) {
            self.application_metrics.insert(application.to_string(), ApplicationMetrics {
                name: application.to_string(),
                ..Default::default()
            });
        }
    }

    /// Generate a simple hash of a resource configuration for comparison
    fn hash_config(&self, config: &Value) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        format!("{:?}", config).hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Check a resource for drift and update metrics
    pub fn check_resource(&mut self, resource_id: &str, resource_type: &str, config: &Value) -> Option<DriftEvent> {
        let now = Utc::now();
        let config_hash = self.hash_config(config);
    
        // Get application for this resource
        let application = self.resource_to_app
            .get(resource_id)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
    
        // Find security issues in the current configuration
        let current_issues = self.validate_resource(resource_id, resource_type, config);
        let current_issues_for_metrics = current_issues.clone();
    
        // Update application metrics for issues
        let app_metrics = self.application_metrics
            .entry(application.clone())
            .or_insert_with(|| ApplicationMetrics {
                name: application.clone(),
                ..Default::default()
            });
    
        // Check for existing resource history
        let mut drift_event = None;
    
        if let Some(history) = self.resource_history.get_mut(resource_id) {
            // Resource exists, check for drift
            if let Some(last_state) = history.state_history.last() {
                if last_state.config_hash != config_hash {
                    // Configuration has changed - this is drift!
                    history.drift_count += 1;
                    history.last_modified = now;
    
                    // Find new and resolved issues
                    let previous_issues = &history.current_issues;
                    let new_issues: Vec<Issue> = current_issues
                        .iter()
                        .filter(|i| !previous_issues.iter().any(|pi| pi.message == i.message))
                        .cloned()
                        .collect();
    
                    let resolved_issues: Vec<Issue> = previous_issues
                        .iter()
                        .filter(|i| !current_issues.iter().any(|ci| ci.message == i.message))
                        .cloned()
                        .collect();
    
                    // Create drift event
                    drift_event = Some(DriftEvent {
                        detected_at: now,
                        resource_id: resource_id.to_string(),
                        resource_type: resource_type.to_string(),
                        application: application.clone(),
                        new_issues,
                        resolved_issues,
                    });
    
                    // Update application metrics
                    app_metrics.total_drifts += 1;
                    app_metrics.last_drift = Some(now);
                }
            }
    
            // Update current issues and add new state
            history.current_issues = current_issues;
            history.state_history.push(ResourceState {
                captured_at: now,
                configuration: config.clone(),
                config_hash,
            });
    
            // Prune state history if it gets too large
            if history.state_history.len() > 10 {
                history.state_history.remove(0);
            }
        } else {
            // First time seeing this resource
            let history = ResourceHistory {
                resource_id: resource_id.to_string(),
                resource_type: resource_type.to_string(),
                application: application.clone(),
                first_seen: now,
                last_modified: now,
                state_history: vec![ResourceState {
                    captured_at: now,
                    configuration: config.clone(),
                    config_hash,
                }],
                current_issues: current_issues.clone(),
                drift_count: 0,
            };
    
            self.resource_history.insert(resource_id.to_string(), history);
    
            // Update application resource count
            app_metrics.resource_count += 1;
        }
    
        // Update issue metrics for application
        app_metrics.issues.clear();
        for issue in &current_issues_for_metrics {
            *app_metrics.issues.entry(issue.severity.clone()).or_insert(0) += 1;
        }
    
        // If we have a drift event, track it
        if let Some(event) = &drift_event {
            self.recent_drifts.push(event.clone());
    
            // Maintain maximum event history
            if self.recent_drifts.len() > self.max_history_events {
                self.recent_drifts.remove(0);
            }
        }
    
        drift_event
    }
    
    
    /// Validate a single resource and return issues
    fn validate_resource(&mut self, resource_id: &str, resource_type: &str, config: &Value) -> Vec<Issue> {
        match resource_type {
            "security_group" => self.validator.check_security_group(resource_id.to_string(), config),
            "ec2_instance" => self.validator.check_ec2_instance(resource_id.to_string(), config),
            "s3_bucket" => self.validator.check_s3_bucket(resource_id.to_string(), config),
            _ => Vec::new(), // Unknown resource type
        }
    }
    
    /// Get metrics for all applications
    pub fn get_application_metrics(&self) -> Vec<ApplicationMetrics> {
        self.application_metrics.values().cloned().collect()
    }
    
    /// Get metrics for a specific application
    pub fn get_app_metrics(&self, application: &str) -> Option<ApplicationMetrics> {
        self.application_metrics.get(application).cloned()
    }
    
    /// Get recent drift events
    pub fn get_recent_drifts(&self) -> &[DriftEvent] {
        &self.recent_drifts
    }
    
    /// Get drift events for a specific application
    pub fn get_app_drifts(&self, application: &str) -> Vec<&DriftEvent> {
        self.recent_drifts
            .iter()
            .filter(|e| e.application == application)
            .collect()
    }
    
    /// Get history for a specific resource
    pub fn get_resource_history(&self, resource_id: &str) -> Option<&ResourceHistory> {
        self.resource_history.get(resource_id)
    }
}