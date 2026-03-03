use serde_json::Value;

use crate::cli::sca::{ScaAction, ScaCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

pub async fn run(client: &WazuhClient, cmd: ScaCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        ScaAction::List { agent_id } => {
            let path = format!("/sca/{}", agent_id);
            client.get(&path, &[]).await
        }
        ScaAction::Checks {
            agent_id,
            policy_id,
        } => {
            let path = format!("/sca/{}/checks/{}", agent_id, policy_id);
            client.get(&path, &[]).await
        }
    }
}
