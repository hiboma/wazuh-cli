use serde_json::Value;

use crate::cli::other::{TaskAction, TaskCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: TaskCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        TaskAction::Status { limit } => {
            if limit.is_none() {
                return client.get_all_pages("/tasks/status", &[], PAGE_SIZE).await;
            }
            let mut query = Vec::new();
            let limit_str = limit.map(|l| l.to_string());
            if let Some(ref l) = limit_str {
                query.push(("limit", l.as_str()));
            }
            client.get("/tasks/status", &query).await
        }
    }
}
