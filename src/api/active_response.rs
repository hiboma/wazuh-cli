use serde_json::{Value, json};

use crate::cli::other::{ActiveResponseAction, ActiveResponseCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

pub async fn run(client: &WazuhClient, cmd: ActiveResponseCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        ActiveResponseAction::Run { agent, command } => {
            let body = json!({
                "command": command,
                "arguments": [],
                "alert": {
                    "data": {
                        "srcip": "0.0.0.0",
                    },
                },
                "agent_list": [agent],
            });
            client.put("/active-response", &body).await
        }
    }
}
