use serde_json::Value;

use crate::cli::other::{ListAction, ListCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: ListCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        ListAction::Get { limit } => {
            if limit.is_none() {
                return client.get_all_pages("/lists", &[], PAGE_SIZE).await;
            }
            let mut query = Vec::new();
            let limit_str = limit.map(|l| l.to_string());
            if let Some(ref l) = limit_str {
                query.push(("limit", l.as_str()));
            }
            client.get("/lists", &query).await
        }
        ListAction::Files => client.get("/lists/files", &[]).await,
        ListAction::File { filename } => {
            let path = format!("/lists/files/{}", filename);
            client.get(&path, &[]).await
        }
        ListAction::Update { filename, file } => {
            let content = std::fs::read_to_string(&file).map_err(|e| {
                WazuhError::Config(format!("Failed to read file '{}': {}", file, e))
            })?;
            let body: Value = serde_json::from_str(&content).map_err(|e| {
                WazuhError::Config(format!("Failed to parse file '{}': {}", file, e))
            })?;
            let path = format!("/lists/files/{}", filename);
            client.put(&path, &body).await
        }
        ListAction::Delete { filename } => {
            let path = format!("/lists/files/{}", filename);
            client.delete(&path, &[]).await
        }
    }
}
