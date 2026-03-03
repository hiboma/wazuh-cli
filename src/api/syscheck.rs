use serde_json::{Value, json};

use crate::cli::syscheck::{SyscheckAction, SyscheckCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: SyscheckCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        SyscheckAction::Get { agent_id, search } => {
            let mut query = Vec::new();
            if let Some(ref s) = search {
                query.push(("search", s.as_str()));
            }
            let path = format!("/syscheck/{}", agent_id);
            client.get_all_pages(&path, &query, PAGE_SIZE).await
        }
        SyscheckAction::LastScan { agent_id } => {
            let path = format!("/syscheck/{}/last_scan", agent_id);
            client.get(&path, &[]).await
        }
        SyscheckAction::Run { agent_ids } => {
            let body = if agent_ids.is_empty() {
                json!({})
            } else {
                json!({"agents_list": agent_ids})
            };
            client.put("/syscheck", &body).await
        }
        SyscheckAction::Clear { agent_ids } => {
            if agent_ids.is_empty() {
                client.delete("/syscheck", &[]).await
            } else {
                let mut results = Vec::new();
                for id in &agent_ids {
                    let path = format!("/syscheck/{}", id);
                    let result = client.delete(&path, &[]).await?;
                    results.push(result);
                }
                if results.len() == 1 {
                    Ok(results.into_iter().next().unwrap())
                } else {
                    Ok(Value::Array(results))
                }
            }
        }
    }
}
