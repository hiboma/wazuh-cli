use serde_json::{Value, json};

use crate::cli::group::{GroupAction, GroupCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: GroupCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        GroupAction::List { limit, offset } => {
            if limit.is_none() && offset.is_none() {
                return client.get_all_pages("/groups", &[], PAGE_SIZE).await;
            }
            let mut query = Vec::new();
            let limit_str = limit.map(|l| l.to_string());
            let offset_str = offset.map(|o| o.to_string());
            if let Some(ref l) = limit_str {
                query.push(("limit", l.as_str()));
            }
            if let Some(ref o) = offset_str {
                query.push(("offset", o.as_str()));
            }
            client.get("/groups", &query).await
        }
        GroupAction::Create { group_id } => {
            let body = json!({"group_id": group_id});
            client.post("/groups", &body).await
        }
        GroupAction::Delete { group_ids } => {
            let ids = group_ids.join(",");
            let query = [("groups_list", ids.as_str())];
            client.delete("/groups", &query).await
        }
        GroupAction::Agents { group_id } => {
            let path = format!("/groups/{}/agents", group_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
        GroupAction::Config { group_id } => {
            let path = format!("/groups/{}/configuration", group_id);
            client.get(&path, &[]).await
        }
        GroupAction::UpdateConfig { group_id, file } => {
            let content = std::fs::read_to_string(&file).map_err(|e| {
                WazuhError::Config(format!("Failed to read file '{}': {}", file, e))
            })?;
            let body: Value = serde_json::from_str(&content).map_err(|e| {
                WazuhError::Config(format!("Failed to parse file '{}': {}", file, e))
            })?;
            let path = format!("/groups/{}/configuration", group_id);
            client.put(&path, &body).await
        }
        GroupAction::Files { group_id } => {
            let path = format!("/groups/{}/files", group_id);
            client.get(&path, &[]).await
        }
        GroupAction::File { group_id, filename } => {
            let path = format!("/groups/{}/files/{}", group_id, filename);
            client.get(&path, &[]).await
        }
    }
}
