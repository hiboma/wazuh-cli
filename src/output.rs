use std::io::Write;

use crate::config::OutputFormat;
use crate::error::WazuhError;

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
    let output = if raw { value } else { extract_data(value) };
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
