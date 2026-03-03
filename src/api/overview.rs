use serde_json::Value;

use crate::cli::other::{OverviewAction, OverviewCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

pub async fn run(client: &WazuhClient, cmd: OverviewCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        OverviewAction::Agents => client.get("/overview/agents", &[]).await,
    }
}
