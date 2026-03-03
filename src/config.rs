use crate::error::WazuhError;

/// Struct corresponding to CLI global options.
/// Each field is Option-typed; None falls back to environment variable, then default value.
pub struct CliOpts {
    pub api_url: Option<String>,
    pub api_user: Option<String>,
    pub api_password: Option<String>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub insecure: bool,
    pub output: Option<String>,
    pub raw: bool,
    pub progress: bool,
    pub timeout: Option<u64>,
}

pub struct Config {
    pub api_url: String,
    pub api_user: String,
    pub api_password: String,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub insecure: bool,
    pub output_format: OutputFormat,
    pub raw_output: bool,
    pub progress: bool,
    pub timeout: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Json,
}

impl Config {
    /// Builds Config from CLI options and environment variables.
    /// Priority: CLI options > environment variables > default values
    pub fn from_cli_and_env(cli: &CliOpts) -> Result<Config, WazuhError> {
        let api_url = resolve_string(
            &cli.api_url,
            "WAZUH_API_URL",
            Some("https://localhost:55000"),
        )?;

        let api_user = resolve_string(&cli.api_user, "WAZUH_API_USER", Some("wazuh"))?;

        let api_password = resolve_string(&cli.api_password, "WAZUH_API_PASSWORD", None)?;

        let ca_cert = resolve_optional_string(&cli.ca_cert, "WAZUH_CA_CERT");
        let client_cert = resolve_optional_string(&cli.client_cert, "WAZUH_CLIENT_CERT");
        let client_key = resolve_optional_string(&cli.client_key, "WAZUH_CLIENT_KEY");

        let insecure = if cli.insecure {
            true
        } else {
            resolve_bool("WAZUH_INSECURE", false)
        };

        let output_format = resolve_output_format(&cli.output)?;

        let raw_output = if cli.raw {
            true
        } else {
            resolve_bool("WAZUH_RAW", false)
        };

        let progress = if cli.progress {
            true
        } else {
            resolve_bool("WAZUH_PROGRESS", false)
        };

        let timeout = resolve_timeout(cli.timeout)?;

        Ok(Config {
            api_url,
            api_user,
            api_password,
            ca_cert,
            client_cert,
            client_key,
            insecure,
            output_format,
            raw_output,
            progress,
            timeout,
        })
    }
}

/// Resolves a string in order: CLI option -> environment variable -> default value.
/// Returns an empty string if default is None and no value is found.
fn resolve_string(
    cli_value: &Option<String>,
    env_var: &str,
    default: Option<&str>,
) -> Result<String, WazuhError> {
    if let Some(v) = cli_value {
        return Ok(v.clone());
    }

    if let Ok(v) = std::env::var(env_var)
        && !v.is_empty()
    {
        return Ok(v);
    }

    match default {
        Some(d) => Ok(d.to_string()),
        None => Ok(String::new()),
    }
}

/// Resolves an optional string in order: CLI option -> environment variable.
/// Returns None if neither is set.
fn resolve_optional_string(cli_value: &Option<String>, env_var: &str) -> Option<String> {
    if let Some(v) = cli_value {
        return Some(v.clone());
    }

    if let Ok(v) = std::env::var(env_var)
        && !v.is_empty()
    {
        return Some(v);
    }

    None
}

/// Resolves a boolean from an environment variable.
/// Treats "true", "1", "yes" as true (case-insensitive).
fn resolve_bool(env_var: &str, default: bool) -> bool {
    match std::env::var(env_var) {
        Ok(v) => matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

/// Resolves the output format.
/// Priority: CLI option -> environment variable -> default value (json).
fn resolve_output_format(cli_value: &Option<String>) -> Result<OutputFormat, WazuhError> {
    let raw = if let Some(v) = cli_value {
        v.clone()
    } else if let Ok(v) = std::env::var("WAZUH_OUTPUT") {
        v
    } else {
        return Ok(OutputFormat::Json);
    };

    match raw.to_lowercase().as_str() {
        "json" => Ok(OutputFormat::Json),
        other => Err(WazuhError::Config(format!(
            "unsupported output format: {}",
            other
        ))),
    }
}

/// Resolves the timeout value.
/// Priority: CLI option -> environment variable -> default value (30 seconds).
fn resolve_timeout(cli_value: Option<u64>) -> Result<u64, WazuhError> {
    if let Some(v) = cli_value {
        return Ok(v);
    }

    if let Ok(v) = std::env::var("WAZUH_TIMEOUT") {
        return v
            .parse::<u64>()
            .map_err(|_| WazuhError::Config(format!("invalid WAZUH_TIMEOUT value: {}", v)));
    }

    Ok(30)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cli_opts() -> CliOpts {
        CliOpts {
            api_url: None,
            api_user: None,
            api_password: None,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            insecure: false,
            output: None,
            raw: false,
            progress: false,
            timeout: None,
        }
    }

    #[test]
    fn test_default_values() {
        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert_eq!(config.api_url, "https://localhost:55000");
        assert_eq!(config.api_user, "wazuh");
        assert_eq!(config.api_password, "");
        assert_eq!(config.insecure, false);
        assert_eq!(config.timeout, 30);
        assert!(config.ca_cert.is_none());
        assert!(config.client_cert.is_none());
        assert!(config.client_key.is_none());
    }

    #[test]
    fn test_cli_opts_override() {
        let cli = CliOpts {
            api_url: Some("https://custom:9200".to_string()),
            api_user: Some("admin".to_string()),
            api_password: Some("secret".to_string()),
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: true,
            output: Some("json".to_string()),
            raw: true,
            progress: false,
            timeout: Some(60),
        };
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert_eq!(config.api_url, "https://custom:9200");
        assert_eq!(config.api_user, "admin");
        assert_eq!(config.api_password, "secret");
        assert_eq!(config.ca_cert.unwrap(), "/path/to/ca.pem");
        assert_eq!(config.client_cert.unwrap(), "/path/to/cert.pem");
        assert_eq!(config.client_key.unwrap(), "/path/to/key.pem");
        assert_eq!(config.insecure, true);
        assert_eq!(config.timeout, 60);
    }

    #[test]
    fn test_invalid_output_format() {
        let cli = CliOpts {
            output: Some("xml".to_string()),
            ..default_cli_opts()
        };
        let result = Config::from_cli_and_env(&cli);

        assert!(result.is_err());
    }

    #[test]
    fn test_env_var_fallback() {
        unsafe {
            std::env::set_var("WAZUH_API_URL", "https://env-host:55000");
            std::env::set_var("WAZUH_API_USER", "env_user");
            std::env::set_var("WAZUH_API_PASSWORD", "env_pass");
            std::env::set_var("WAZUH_CA_CERT", "/env/ca.pem");
            std::env::set_var("WAZUH_CLIENT_CERT", "/env/cert.pem");
            std::env::set_var("WAZUH_CLIENT_KEY", "/env/key.pem");
        }

        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert_eq!(config.api_url, "https://env-host:55000");
        assert_eq!(config.api_user, "env_user");
        assert_eq!(config.api_password, "env_pass");
        assert_eq!(config.ca_cert.unwrap(), "/env/ca.pem");
        assert_eq!(config.client_cert.unwrap(), "/env/cert.pem");
        assert_eq!(config.client_key.unwrap(), "/env/key.pem");

        unsafe {
            std::env::remove_var("WAZUH_API_URL");
            std::env::remove_var("WAZUH_API_USER");
            std::env::remove_var("WAZUH_API_PASSWORD");
            std::env::remove_var("WAZUH_CA_CERT");
            std::env::remove_var("WAZUH_CLIENT_CERT");
            std::env::remove_var("WAZUH_CLIENT_KEY");
        }
    }

    #[test]
    fn test_env_var_insecure_true() {
        unsafe {
            std::env::set_var("WAZUH_INSECURE", "true");
        }

        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert!(config.insecure);

        unsafe {
            std::env::remove_var("WAZUH_INSECURE");
        }
    }

    #[test]
    fn test_env_var_insecure_yes() {
        unsafe {
            std::env::set_var("WAZUH_INSECURE", "YES");
        }

        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert!(config.insecure);

        unsafe {
            std::env::remove_var("WAZUH_INSECURE");
        }
    }

    #[test]
    fn test_env_var_insecure_one() {
        unsafe {
            std::env::set_var("WAZUH_INSECURE", "1");
        }

        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert!(config.insecure);

        unsafe {
            std::env::remove_var("WAZUH_INSECURE");
        }
    }

    #[test]
    fn test_env_var_insecure_false() {
        unsafe {
            std::env::set_var("WAZUH_INSECURE", "no");
        }

        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert!(!config.insecure);

        unsafe {
            std::env::remove_var("WAZUH_INSECURE");
        }
    }

    #[test]
    fn test_env_var_output_format() {
        unsafe {
            std::env::set_var("WAZUH_OUTPUT", "json");
        }

        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert!(matches!(config.output_format, OutputFormat::Json));

        unsafe {
            std::env::remove_var("WAZUH_OUTPUT");
        }
    }

    #[test]
    fn test_env_var_timeout() {
        unsafe {
            std::env::set_var("WAZUH_TIMEOUT", "60");
        }

        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert_eq!(config.timeout, 60);

        unsafe {
            std::env::remove_var("WAZUH_TIMEOUT");
        }
    }

    #[test]
    fn test_env_var_timeout_invalid() {
        unsafe {
            std::env::set_var("WAZUH_TIMEOUT", "not_a_number");
        }

        let cli = default_cli_opts();
        let result = Config::from_cli_and_env(&cli);

        assert!(result.is_err());

        unsafe {
            std::env::remove_var("WAZUH_TIMEOUT");
        }
    }

    #[test]
    fn test_cli_overrides_env() {
        unsafe {
            std::env::set_var("WAZUH_API_URL", "https://env-host:55000");
        }

        let cli = CliOpts {
            api_url: Some("https://cli-host:55000".to_string()),
            ..default_cli_opts()
        };
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert_eq!(config.api_url, "https://cli-host:55000");

        unsafe {
            std::env::remove_var("WAZUH_API_URL");
        }
    }

    #[test]
    fn test_empty_env_var_uses_default() {
        unsafe {
            std::env::set_var("WAZUH_API_URL", "");
        }

        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert_eq!(config.api_url, "https://localhost:55000");

        unsafe {
            std::env::remove_var("WAZUH_API_URL");
        }
    }
}
