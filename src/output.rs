use std::io::Write;

use crate::config::OutputFormat;
use crate::error::WazuhError;

fn secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("password")
        || key.contains("token")
        || key.contains("authorization")
        || key == "key"
        || key.ends_with("_key")
        || key == "secret"
}

/// Collect sent secrets so a server cannot reflect them under an innocent key.
pub(crate) fn collect_secrets<'a>(value: &'a serde_json::Value, secrets: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if secret_key(key)
                    && let Some(value) = value.as_str()
                {
                    secrets.push(value);
                }
                collect_secrets(value, secrets);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_secrets(item, secrets);
            }
        }
        _ => {}
    }
}

/// Apply to both values and object keys, including embedded exact matches.
pub(crate) fn redact_values(value: &mut serde_json::Value, secrets: &[&str]) {
    fn redact(text: &mut String, secrets: &[&str]) {
        use zeroize::Zeroize;
        for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
            if text.contains(secret) {
                let safe = text.replace(secret, "[REDACTED]");
                text.zeroize();
                *text = safe;
            }
        }
    }
    match value {
        serde_json::Value::String(text) => redact(text, secrets),
        serde_json::Value::Array(items) => {
            for item in items {
                redact_values(item, secrets);
            }
        }
        serde_json::Value::Object(map) => {
            for (mut key, mut item) in std::mem::take(map) {
                redact(&mut key, secrets);
                redact_values(&mut item, secrets);
                map.insert(key, item);
            }
        }
        _ => {}
    }
}

fn public_response(value: &serde_json::Value) -> serde_json::Value {
    let mut secrets = Vec::new();
    collect_secrets(value, &mut secrets);
    let mut safe = value.clone();
    redact_values(&mut safe, &secrets);
    fn mask(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    if secret_key(key) {
                        *item = serde_json::json!("[REDACTED]");
                    } else {
                        mask(item);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    mask(item);
                }
            }
            _ => {}
        }
    }
    mask(&mut safe);
    safe
}

/// Explicit secret export preserves newly issued session tokens/enrollment keys.
/// Never overwrite or follow an existing path. Non-Unix platforms fail closed
/// until a private ACL can be installed atomically.
pub fn write_secret_response(
    path: &std::path::Path,
    value: &serde_json::Value,
) -> Result<(), WazuhError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| {
                WazuhError::Config(
                    "cannot create secret output file; use a new path in a private directory"
                        .into(),
                )
            })?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, value);
        Err(WazuhError::Config(
            "secret output files require Unix permission enforcement".into(),
        ))
    }
}

/// Extracts data.affected_items from an API response.
/// Fallback order: affected_items -> data -> original JSON
fn extract_data(value: &serde_json::Value) -> &serde_json::Value {
    if let Some(data) = value.get("data") {
        if let Some(items) = data.get("affected_items") {
            return items;
        }
        return data;
    }
    value
}

/// Prints an API response to stdout in the specified format.
/// If raw is true, outputs the original JSON as-is.
/// If raw is false, extracts and outputs affected_items.
/// Treats a broken pipe (closed downstream) as a successful exit.
pub fn print_response(
    value: &serde_json::Value,
    _format: OutputFormat,
    raw: bool,
) -> Result<(), WazuhError> {
    let safe = public_response(value);
    let output = if raw { &safe } else { extract_data(&safe) };
    let mut stdout = std::io::stdout().lock();

    if let Some(items) = output.as_array() {
        for item in items {
            let line = serde_json::to_string(item).map_err(WazuhError::Json)?;
            match writeln!(stdout, "{}", line) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                Err(e) => return Err(WazuhError::Io(e)),
            }
        }
        Ok(())
    } else {
        let formatted = serde_json::to_string_pretty(output).map_err(WazuhError::Json)?;
        match writeln!(stdout, "{}", formatted) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(WazuhError::Io(e)),
        }
    }
}

/// Prints an error message to stderr.
pub fn print_error(error: &WazuhError) {
    eprintln!("Error: {}", error);
}

/// Returns the exit code corresponding to a WazuhError.
/// - 0: Success
/// - 1: Error (config, connection, auth, API)
/// - 2: CLI input error (reserved for future use)
/// - 3: Partial success
pub fn exit_code(error: &WazuhError) -> i32 {
    match error {
        WazuhError::PartialSuccess { .. } => 3,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_config_error() {
        let err = WazuhError::Config("test".to_string());
        assert_eq!(exit_code(&err), 1);
    }

    #[test]
    fn test_exit_code_auth_error() {
        let err = WazuhError::Auth("test".to_string());
        assert_eq!(exit_code(&err), 1);
    }

    #[test]
    fn test_exit_code_api_error() {
        let err = WazuhError::Api {
            status: 404,
            message: "not found".to_string(),
        };
        assert_eq!(exit_code(&err), 1);
    }

    #[test]
    fn test_exit_code_partial_success() {
        let err = WazuhError::PartialSuccess {
            succeeded: 5,
            failed: 2,
        };
        assert_eq!(exit_code(&err), 3);
    }

    #[test]
    fn test_exit_code_connection_error() {
        let err = WazuhError::Connection("timeout".to_string());
        assert_eq!(exit_code(&err), 1);
    }

    #[test]
    fn test_print_response_json() {
        let value = serde_json::json!({"key": "value"});
        let result = print_response(&value, OutputFormat::Json, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_response_raw() {
        let value = serde_json::json!({
            "data": {
                "affected_items": [{"id": "001"}],
                "total_affected_items": 1
            },
            "message": "ok",
            "error": 0
        });
        let result = print_response(&value, OutputFormat::Json, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_error_config() {
        let err = WazuhError::Config("missing value".to_string());
        print_error(&err);
    }

    #[test]
    fn test_print_error_tls() {
        let err = WazuhError::Tls("cert error".to_string());
        print_error(&err);
    }

    #[test]
    fn test_extract_data_with_affected_items() {
        let value = serde_json::json!({
            "data": {
                "affected_items": [{"id": "001"}, {"id": "002"}],
                "total_affected_items": 2,
                "total_failed_items": 0,
                "failed_items": []
            },
            "message": "All selected agents information was returned",
            "error": 0
        });
        let result = extract_data(&value);
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 2);
        assert_eq!(result[0]["id"], "001");
    }

    #[test]
    fn test_extract_data_without_affected_items() {
        let value = serde_json::json!({
            "data": {
                "enabled": "yes",
                "running": "yes"
            },
            "message": "ok",
            "error": 0
        });
        let result = extract_data(&value);
        assert!(result.is_object());
        assert_eq!(result["enabled"], "yes");
    }

    #[test]
    fn test_extract_data_without_data() {
        let value = serde_json::json!({
            "message": "ok",
            "error": 0
        });
        let result = extract_data(&value);
        assert!(result.is_object());
        assert_eq!(result["message"], "ok");
    }

    #[test]
    fn test_extract_data_non_object() {
        let value = serde_json::json!("plain string");
        let result = extract_data(&value);
        assert_eq!(result, &serde_json::json!("plain string"));
    }

    #[test]
    fn test_extract_data_empty_affected_items() {
        let value = serde_json::json!({
            "data": {
                "affected_items": [],
                "total_affected_items": 0,
                "total_failed_items": 0,
                "failed_items": []
            },
            "message": "ok",
            "error": 0
        });
        let result = extract_data(&value);
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 0);
    }
}
