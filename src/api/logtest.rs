use serde_json::{Value, json};

use crate::cli::other::{LogtestAction, LogtestCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

pub async fn run(client: &WazuhClient, cmd: LogtestCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        LogtestAction::Run { log, session } => {
            let mut body = json!({
                "event": log,
                "log_format": "syslog",
                "location": "stdin",
            });
            if let Some(token) = session {
                body["token"] = json!(token);
            }
            client.put("/logtest", &body).await
        }
        LogtestAction::DeleteSession { token } => {
            let path = format!("/logtest/sessions/{}", token);
            client.delete(&path, &[]).await
        }
    }
}
