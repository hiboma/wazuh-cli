use serde_json::Value;

use crate::cli::rule::{RuleAction, RuleCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: RuleCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        RuleAction::List {
            group,
            level,
            limit,
        } => {
            let mut query = Vec::new();
            if let Some(ref g) = group {
                query.push(("group", g.as_str()));
            }
            let level_str = level.map(|l| l.to_string());
            if let Some(ref l) = level_str {
                query.push(("level", l.as_str()));
            }
            if limit.is_none() {
                return client.get_all_pages("/rules", &query, PAGE_SIZE).await;
            }
            let limit_str = limit.map(|l| l.to_string());
            if let Some(ref l) = limit_str {
                query.push(("limit", l.as_str()));
            }
            client.get("/rules", &query).await
        }
        RuleAction::Groups => client.get("/rules/groups", &[]).await,
        RuleAction::Requirements { requirement } => {
            let path = format!("/rules/requirement/{}", requirement);
            client.get(&path, &[]).await
        }
        RuleAction::Files => client.get("/rules/files", &[]).await,
        RuleAction::File { filename } => {
            let path = format!("/rules/files/{}", filename);
            client.get(&path, &[]).await
        }
        RuleAction::Update { filename, file } => {
            let content = std::fs::read_to_string(&file).map_err(|e| {
                WazuhError::Config(format!("Failed to read file '{}': {}", file, e))
            })?;
            let body: Value = serde_json::from_str(&content).map_err(|e| {
                WazuhError::Config(format!("Failed to parse file '{}': {}", file, e))
            })?;
            let path = format!("/rules/files/{}", filename);
            client.put(&path, &body).await
        }
        RuleAction::Delete { filename } => {
            let path = format!("/rules/files/{}", filename);
            client.delete(&path, &[]).await
        }
    }
}
