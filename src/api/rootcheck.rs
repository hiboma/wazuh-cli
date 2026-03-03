use serde_json::{Value, json};

use crate::cli::rootcheck::{RootcheckAction, RootcheckCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: RootcheckCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        RootcheckAction::Get { agent_id } => {
            let path = format!("/rootcheck/{}", agent_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
        RootcheckAction::LastScan { agent_id } => {
            let path = format!("/rootcheck/{}/last_scan", agent_id);
            client.get(&path, &[]).await
        }
        RootcheckAction::Run { agent_ids } => {
            let body = if agent_ids.is_empty() {
                json!({})
            } else {
                json!({"agents_list": agent_ids})
            };
            client.put("/rootcheck", &body).await
        }
        RootcheckAction::Clear { agent_id } => {
            let path = format!("/rootcheck/{}", agent_id);
            client.delete(&path, &[]).await
        }
    }
}
