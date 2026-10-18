use serde_json::{Value, json};

use crate::cli::other::{LogtestAction, LogtestCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;
use crate::secret::{SecretJson, SecretSource, read_secret};
use zeroize::Zeroizing;

pub async fn run(client: &WazuhClient, cmd: LogtestCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        LogtestAction::Run {
            log,
            session_stdin,
            session_file,
            session_prompt,
            ..
        } => {
            let mut body = SecretJson(json!({
                "event": log,
                "log_format": "syslog",
                "location": "stdin",
            }));
            if session_stdin || session_file.is_some() || session_prompt {
                let token = read_secret(
                    SecretSource::from_flags(session_stdin, session_file.as_deref()),
                    "Session token (input hidden): ",
                    false,
                )?;
                body.0["token"] = json!(token.as_str());
            }
            client.put("/logtest", &body.0).await
        }
        LogtestAction::DeleteSession {
            token_stdin,
            token_file,
            ..
        } => {
            let token = read_secret(
                SecretSource::from_flags(token_stdin, token_file.as_deref()),
                "Session token (input hidden): ",
                false,
            )?;
            let path = session_path(&token)?;
            client.delete(&path, &[]).await
        }
    }
}

fn session_path(token: &str) -> Result<Zeroizing<String>, WazuhError> {
    if token.is_empty()
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(WazuhError::Config(
            "invalid session token: expected ASCII letters, digits, underscores, or hyphens".into(),
        ));
    }
    Ok(Zeroizing::new(format!("/logtest/sessions/{}", token)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_path_rejects_url_syntax_without_reflecting_tokens() {
        for token in [
            "../secret",
            "%2e%2e",
            "secret?x",
            "secret#x",
            "secret/token",
            "secret\\token",
            ".",
        ] {
            let err = session_path(token).unwrap_err().to_string();
            assert!(!err.contains(token));
        }
        assert_eq!(
            session_path("abc-123_DEF").unwrap().as_str(),
            "/logtest/sessions/abc-123_DEF"
        );
    }
}
