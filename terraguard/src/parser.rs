use crate::types::Plan;
use std::fs;


pub fn _parse_plan(path: &str) -> serde_json::Result<Plan> {
    let content = fs::read_to_string(path).map_err(|e| {
        serde_json::Error::io(e)  // If available, or create a custom conversion
    })?;
    let plan: Plan = serde_json::from_str(&content)?;
    Ok(plan)
}