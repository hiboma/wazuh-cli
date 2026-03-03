use serde_json::{Value, json};

use crate::cli::agent::{AgentAction, AgentCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: AgentCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        AgentAction::List {
            status,
            group,
            limit,
            offset,
        } => {
            let mut query = Vec::new();
            if let Some(ref s) = status {
                query.push(("status", s.as_str()));
            }
            if let Some(ref g) = group {
                query.push(("group", g.as_str()));
            }
            if limit.is_none() && offset.is_none() {
                return client.get_all_pages("/agents", &query, PAGE_SIZE).await;
            }
            let limit_str = limit.map(|l| l.to_string());
            if let Some(ref l) = limit_str {
                query.push(("limit", l.as_str()));
            }
            let offset_str = offset.map(|o| o.to_string());
            if let Some(ref o) = offset_str {
                query.push(("offset", o.as_str()));
            }
            client.get("/agents", &query).await
        }
        AgentAction::Get { agent_id } => {
            let query = [("agents_list", agent_id.as_str())];
            client.get("/agents", &query).await
        }
        AgentAction::Create { name, ip } => {
            let body = json!({"name": name, "ip": ip});
            client.post("/agents", &body).await
        }
        AgentAction::Delete { agent_ids } => {
            let ids = agent_ids.join(",");
            let query = [("agents_list", ids.as_str())];
            client.delete("/agents", &query).await
        }
        AgentAction::Restart { agent_ids } => {
            let mut results = Vec::new();
            for id in &agent_ids {
                let path = format!("/agents/{}/restart", id);
                let result = client.put(&path, &json!({})).await?;
                results.push(result);
            }
            if results.len() == 1 {
                Ok(results.into_iter().next().unwrap())
            } else {
                Ok(Value::Array(results))
            }
        }
        AgentAction::RestartAll => client.put("/agents/restart", &json!({})).await,
        AgentAction::Upgrade { agent_ids } => {
            let body = json!({"agents_list": agent_ids});
            client.put("/agents/upgrade", &body).await
        }
        AgentAction::Key { agent_id } => {
            let path = format!("/agents/{}/key", agent_id);
            client.get(&path, &[]).await
        }
        AgentAction::Groups { agent_id } => {
            let path = format!("/agents/{}/group/is_sync", agent_id);
            client.get(&path, &[]).await
        }
        AgentAction::AddGroup { agent_id, group_id } => {
            let path = format!("/agents/{}/group/{}", agent_id, group_id);
            client.put(&path, &json!({})).await
        }
        AgentAction::RemoveGroup { agent_id, group_id } => match group_id {
            Some(gid) => {
                let path = format!("/agents/{}/group/{}", agent_id, gid);
                client.delete(&path, &[]).await
            }
            None => {
                let path = format!("/agents/{}/group", agent_id);
                client.delete(&path, &[]).await
            }
        },
        AgentAction::Outdated => {
            client
                .get_all_pages("/agents/outdated", &[], PAGE_SIZE)
                .await
        }
        AgentAction::SummaryStatus => client.get("/agents/summary/status", &[]).await,
        AgentAction::SummaryOs => client.get("/agents/summary/os", &[]).await,
    }
}
