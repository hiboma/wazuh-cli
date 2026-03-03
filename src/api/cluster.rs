use serde_json::{Value, json};

use crate::cli::cluster::{ClusterAction, ClusterCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

pub async fn run(client: &WazuhClient, cmd: ClusterCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        ClusterAction::Status => client.get("/cluster/status", &[]).await,
        ClusterAction::Health => client.get("/cluster/healthcheck", &[]).await,
        ClusterAction::Nodes => client.get("/cluster/nodes", &[]).await,
        ClusterAction::LocalInfo => client.get("/cluster/local/info", &[]).await,
        ClusterAction::LocalConfig => client.get("/cluster/local/config", &[]).await,
        ClusterAction::NodeInfo { node_id } => {
            let path = format!("/cluster/{}/info", node_id);
            client.get(&path, &[]).await
        }
        ClusterAction::NodeConfig { node_id } => {
            let path = format!("/cluster/{}/configuration", node_id);
            client.get(&path, &[]).await
        }
        ClusterAction::NodeStats { node_id } => {
            let path = format!("/cluster/{}/stats", node_id);
            client.get(&path, &[]).await
        }
        ClusterAction::NodeLogs { node_id, summary } => {
            let path = if summary {
                format!("/cluster/{}/logs/summary", node_id)
            } else {
                format!("/cluster/{}/logs", node_id)
            };
            client.get(&path, &[]).await
        }
        ClusterAction::Restart => client.put("/cluster/restart", &json!({})).await,
        ClusterAction::RulesetSync => client.get("/cluster/ruleset/synchronization", &[]).await,
        ClusterAction::ValidateConfig => client.get("/cluster/configuration/validation", &[]).await,
    }
}
