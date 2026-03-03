use serde_json::{Value, json};

use crate::cli::manager::{ManagerAction, ManagerCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

pub async fn run(client: &WazuhClient, cmd: ManagerCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        ManagerAction::Status => client.get("/manager/status", &[]).await,
        ManagerAction::Info => client.get("/manager/info", &[]).await,
        ManagerAction::Config => client.get("/manager/configuration", &[]).await,
        ManagerAction::UpdateConfig { file } => {
            let content = std::fs::read_to_string(&file).map_err(|e| {
                WazuhError::Config(format!("Failed to read file '{}': {}", file, e))
            })?;
            let body: Value = serde_json::from_str(&content).map_err(|e| {
                WazuhError::Config(format!("Failed to parse JSON from '{}': {}", file, e))
            })?;
            client.put("/manager/configuration", &body).await
        }
        ManagerAction::Stats { hourly, weekly } => {
            let path = if hourly {
                "/manager/stats/hourly"
            } else if weekly {
                "/manager/stats/weekly"
            } else {
                "/manager/stats"
            };
            client.get(path, &[]).await
        }
        ManagerAction::Logs { summary } => {
            let path = if summary {
                "/manager/logs/summary"
            } else {
                "/manager/logs"
            };
            client.get(path, &[]).await
        }
        ManagerAction::Restart => client.put("/manager/restart", &json!({})).await,
        ManagerAction::ValidateConfig => client.get("/manager/configuration/validation", &[]).await,
        ManagerAction::ApiConfig => client.get("/manager/api/config", &[]).await,
        ManagerAction::VersionCheck => client.get("/manager/version/check", &[]).await,
    }
}
