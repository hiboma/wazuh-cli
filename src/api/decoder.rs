use serde_json::Value;

use crate::cli::decoder::{DecoderAction, DecoderCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: DecoderCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        DecoderAction::List { limit } => {
            if limit.is_none() {
                return client.get_all_pages("/decoders", &[], PAGE_SIZE).await;
            }
            let mut query = Vec::new();
            let limit_str = limit.map(|l| l.to_string());
            if let Some(ref l) = limit_str {
                query.push(("limit", l.as_str()));
            }
            client.get("/decoders", &query).await
        }
        DecoderAction::Files => client.get("/decoders/files", &[]).await,
        DecoderAction::File { filename } => {
            let path = format!("/decoders/files/{}", filename);
            client.get(&path, &[]).await
        }
        DecoderAction::Update { filename, file } => {
            let content = std::fs::read_to_string(&file).map_err(|e| {
                WazuhError::Config(format!("Failed to read file '{}': {}", file, e))
            })?;
            let body: Value = serde_json::from_str(&content).map_err(|e| {
                WazuhError::Config(format!("Failed to parse file '{}': {}", file, e))
            })?;
            let path = format!("/decoders/files/{}", filename);
            client.put(&path, &body).await
        }
        DecoderAction::Delete { filename } => {
            let path = format!("/decoders/files/{}", filename);
            client.delete(&path, &[]).await
        }
        DecoderAction::Parents => client.get("/decoders/parents", &[]).await,
    }
}
