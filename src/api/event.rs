use serde_json::Value;

use crate::cli::other::{EventAction, EventCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

pub async fn run(client: &WazuhClient, cmd: EventCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        EventAction::Send { file } => {
            let content = std::fs::read_to_string(&file).map_err(|e| {
                WazuhError::Config(format!("Failed to read file '{}': {}", file, e))
            })?;
            let body: Value = serde_json::from_str(&content).map_err(|e| {
                WazuhError::Config(format!("Failed to parse file '{}': {}", file, e))
            })?;
            client.post("/events", &body).await
        }
    }
}
