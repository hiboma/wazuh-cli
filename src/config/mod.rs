use std::fmt;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::error::WazuhError;

pub mod credential_store;
pub mod file;

use file::ConfigFile;

use credential_store::{CredentialStore, KEY_API_PASSWORD, StoreError, default_store};

/// Struct corresponding to CLI global options.
/// Each field is Option-typed; None falls back to environment variable, then default value.
pub struct CliOpts {
    pub api_url: Option<String>,
    pub api_user: Option<String>,
    /// Wrapped in `Zeroizing` so that the plaintext moved from `argv`
    /// via clap is wiped when `CliOpts` drops, rather than sitting on
    /// the heap for the rest of the process. The original `argv`
    /// slot that clap copies from is already exposed via `ps`, but
    /// the in-process heap copy is recoverable from a core dump and
    /// is the one under our control.
    pub api_password: Option<Zeroizing<String>>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub insecure: bool,
    pub output: Option<String>,
    pub raw: bool,
    pub progress: bool,
    pub timeout: Option<u64>,
    /// Path to a TOML config file (`--config <PATH>`). Overrides
    /// both `WAZUH_CONFIG` and the default
    /// `~/.config/wazuh-cli/config.toml` location.
    pub config: Option<PathBuf>,
}

pub struct Config {
    pub api_url: String,
    pub api_user: String,
    /// Wrapped in `Zeroizing` so the heap allocation is wiped when
    /// `Config` drops. The `String` inside is only ever cloned into
    /// another `Zeroizing<String>` (see `Credentials.password`), so
    /// plaintext copies do not leak into unmanaged heap.
    pub api_password: Zeroizing<String>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub insecure: bool,
    pub output_format: OutputFormat,
    pub raw_output: bool,
    pub progress: bool,
    pub timeout: u64,
}

/// Hand-written `Debug` impl that masks the API password. Auto-derived
/// `Debug` would dump the plaintext into logs / panic backtraces / any
/// `{:?}` format call, which is a common accidental leakage path.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("api_url", &self.api_url)
            .field("api_user", &self.api_user)
            .field(
                "api_password",
                &if self.api_password.is_empty() {
                    "(empty)"
                } else {
                    "***"
                },
            )
            .field("ca_cert", &self.ca_cert)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field("insecure", &self.insecure)
            .field("output_format", &self.output_format)
            .field("raw_output", &self.raw_output)
            .field("progress", &self.progress)
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Json,
}

impl Config {
    /// Builds Config from CLI options and environment variables,
    /// consulting the platform default credential store (macOS
    /// Keychain) and, optionally, a TOML config file.
    ///
    /// Priority (first non-empty wins, per field):
    ///     CLI options
    ///   > environment variables
    ///   > credential store  (api_password only)
    ///   > config file       (~/.config/wazuh-cli/config.toml)
    ///   > built-in defaults
    ///
    /// The `wazuh-cli` binary does not call this directly — it uses
    /// `from_cli_env_store_and_file` with a pre-captured env password
    /// so the startup path can scrub `WAZUH_API_PASSWORD` from the
    /// environment before any subcommand dispatches. This variant
    /// exists for library callers (integration tests, embedders)
    /// that do not need the early-scrub discipline.
    #[allow(dead_code)]
    pub fn from_cli_and_env(cli: &CliOpts) -> Result<Config, WazuhError> {
        // Consume `WAZUH_API_PASSWORD` here if it is still in the
        // environment. `main.rs` normally captures-and-scrubs earlier,
        // but non-binary callers (tests, embedding) need the
        // convenience path to Just Work.
        let env_pw = std::env::var("WAZUH_API_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty())
            .map(Zeroizing::new);
        let loaded = file::load(
            cli.config.as_deref(),
            std::env::var("WAZUH_CONFIG").ok().as_deref(),
        )?;
        let file_cfg = loaded.as_ref().map(|(_, f)| f);
        Self::from_cli_env_store_and_file(cli, env_pw.as_ref(), default_store().as_ref(), file_cfg)
    }

    /// Preserved name for the env+store-only signature. Kept as a
    /// thin wrapper over `from_cli_env_store_and_file` so existing
    /// call sites (and tests) do not have to pass `None` for the
    /// file argument explicitly.
    #[allow(dead_code)]
    pub fn from_cli_env_and_store(
        cli: &CliOpts,
        env_password: Option<&Zeroizing<String>>,
        store: &dyn CredentialStore,
    ) -> Result<Config, WazuhError> {
        Self::from_cli_env_store_and_file(cli, env_password, store, None)
    }

    /// Full resolution form. Every input except `cli` is injectable so
    /// tests can drive any tier independently.
    pub fn from_cli_env_store_and_file(
        cli: &CliOpts,
        env_password: Option<&Zeroizing<String>>,
        store: &dyn CredentialStore,
        file_cfg: Option<&ConfigFile>,
    ) -> Result<Config, WazuhError> {
        let api_url = resolve_string(
            cli.api_url.as_deref(),
            "WAZUH_API_URL",
            file_cfg.and_then(|f| f.api.url.as_deref()),
            Some("https://localhost:55000"),
        )?;

        let api_user = resolve_string(
            cli.api_user.as_deref(),
            "WAZUH_API_USER",
            file_cfg.and_then(|f| f.api.user.as_deref()),
            Some("wazuh"),
        )?;

        let api_password = resolve_api_password(&cli.api_password, env_password, store)?;

        let ca_cert = resolve_optional_string(
            cli.ca_cert.as_deref(),
            "WAZUH_CA_CERT",
            file_cfg.and_then(|f| f.tls.ca_cert.as_deref()),
        );
        let client_cert = resolve_optional_string(
            cli.client_cert.as_deref(),
            "WAZUH_CLIENT_CERT",
            file_cfg.and_then(|f| f.tls.client_cert.as_deref()),
        );
        let client_key = resolve_optional_string(
            cli.client_key.as_deref(),
            "WAZUH_CLIENT_KEY",
            file_cfg.and_then(|f| f.tls.client_key.as_deref()),
        );

        let insecure = resolve_bool_tier(
            cli.insecure,
            "WAZUH_INSECURE",
            file_cfg.and_then(|f| f.tls.insecure),
            false,
        );

        let output_format = resolve_output_format(
            cli.output.as_deref(),
            file_cfg.and_then(|f| f.output.format.as_deref()),
        )?;

        let raw_output = resolve_bool_tier(
            cli.raw,
            "WAZUH_RAW",
            file_cfg.and_then(|f| f.output.raw),
            false,
        );

        let progress = resolve_bool_tier(
            cli.progress,
            "WAZUH_PROGRESS",
            file_cfg.and_then(|f| f.output.progress),
            false,
        );

        let timeout = resolve_timeout(cli.timeout, file_cfg.and_then(|f| f.request.timeout))?;

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

/// Resolve the API password in priority order: CLI > env > credential
/// store. The store's `Unavailable` is treated as "no answer here, try
/// the next tier" (so users who never opted into the Keychain still
/// get the previous env-only behavior); `Backend` is surfaced as a
/// hard error to avoid silently falling through to a stale source
/// after a Keychain ACL denial.
fn resolve_api_password(
    cli_value: &Option<Zeroizing<String>>,
    env_password: Option<&Zeroizing<String>>,
    store: &dyn CredentialStore,
) -> Result<Zeroizing<String>, WazuhError> {
    if let Some(v) = cli_value {
        // Clone into a fresh Zeroizing so the returned value has an
        // independent lifetime from `CliOpts`. Both the source and
        // the clone are wiped on their respective drops.
        return Ok(Zeroizing::new((**v).clone()));
    }

    if let Some(v) = env_password {
        return Ok(Zeroizing::new((**v).clone()));
    }

    match store.get(KEY_API_PASSWORD) {
        Ok(Some(v)) => Ok(Zeroizing::new(v)),
        Ok(None) => Ok(Zeroizing::new(String::new())),
        Err(StoreError::Unavailable(_)) => Ok(Zeroizing::new(String::new())),
        Err(StoreError::Backend(msg)) => Err(WazuhError::CredentialStore(format!(
            "{}. Run `wazuh-cli credentials status` for guidance, or set \
             WAZUH_API_PASSWORD to bypass the store.",
            msg
        ))),
    }
}

/// Resolve a string-valued setting in priority order:
/// CLI > env var > config file > default.
fn resolve_string(
    cli_value: Option<&str>,
    env_var: &str,
    file_value: Option<&str>,
    default: Option<&str>,
) -> Result<String, WazuhError> {
    if let Some(v) = cli_value {
        return Ok(v.to_string());
    }
    if let Ok(v) = std::env::var(env_var)
        && !v.is_empty()
    {
        return Ok(v);
    }
    if let Some(v) = file_value
        && !v.is_empty()
    {
        return Ok(v.to_string());
    }
    Ok(default.map(|s| s.to_string()).unwrap_or_default())
}

/// Resolve an optional string setting in priority order:
/// CLI > env var > config file. Returns None if none of the three
/// tiers supplies a non-empty value.
fn resolve_optional_string(
    cli_value: Option<&str>,
    env_var: &str,
    file_value: Option<&str>,
) -> Option<String> {
    if let Some(v) = cli_value {
        return Some(v.to_string());
    }
    if let Ok(v) = std::env::var(env_var)
        && !v.is_empty()
    {
        return Some(v);
    }
    if let Some(v) = file_value
        && !v.is_empty()
    {
        return Some(v.to_string());
    }
    None
}

/// Resolve a boolean in priority order: CLI flag (if set, true) >
/// env var (truthy values: "true"/"1"/"yes", case-insensitive) >
/// config file > default.
///
/// The CLI flag has no "unset" state — clap flags are bool — so a
/// `false` CLI value never overrides the lower tiers. That matches
/// the previous behavior for `--insecure` / `--raw` / `--progress`.
fn resolve_bool_tier(
    cli_flag: bool,
    env_var: &str,
    file_value: Option<bool>,
    default: bool,
) -> bool {
    if cli_flag {
        return true;
    }
    if let Ok(v) = std::env::var(env_var) {
        if matches!(v.to_lowercase().as_str(), "true" | "1" | "yes") {
            return true;
        }
        if matches!(v.to_lowercase().as_str(), "false" | "0" | "no") {
            return false;
        }
        // An env var with a value that is neither truthy nor falsy
        // is ignored rather than forcing a parse error — matches
        // pre-existing resolve_bool behavior.
    }
    if let Some(v) = file_value {
        return v;
    }
    default
}

/// Resolves the output format.
/// Priority: CLI > env var > config file > default (`json`).
fn resolve_output_format(
    cli_value: Option<&str>,
    file_value: Option<&str>,
) -> Result<OutputFormat, WazuhError> {
    let raw = if let Some(v) = cli_value {
        v.to_string()
    } else if let Ok(v) = std::env::var("WAZUH_OUTPUT")
        && !v.is_empty()
    {
        v
    } else if let Some(v) = file_value
        && !v.is_empty()
    {
        v.to_string()
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
/// Priority: CLI > env var > config file > default (30 seconds).
fn resolve_timeout(cli_value: Option<u64>, file_value: Option<u64>) -> Result<u64, WazuhError> {
    if let Some(v) = cli_value {
        return Ok(v);
    }
    if let Ok(v) = std::env::var("WAZUH_TIMEOUT") {
        return v
            .parse::<u64>()
            .map_err(|_| WazuhError::Config(format!("invalid WAZUH_TIMEOUT value: {}", v)));
    }
    if let Some(v) = file_value {
        return Ok(v);
    }
    Ok(30)
}

#[cfg(test)]
mod tests {
    use super::credential_store::{FailingStore, MemoryStore};
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
            config: None,
        }
    }

    #[test]
    fn test_default_values() {
        let cli = default_cli_opts();
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert_eq!(config.api_url, "https://localhost:55000");
        assert_eq!(config.api_user, "wazuh");
        assert_eq!(config.api_password.as_str(), "");
        assert!(!config.insecure);
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
            api_password: Some("secret".to_string().into()),
            ca_cert: Some("/path/to/ca.pem".to_string()),
            client_cert: Some("/path/to/cert.pem".to_string()),
            client_key: Some("/path/to/key.pem".to_string()),
            insecure: true,
            output: Some("json".to_string()),
            raw: true,
            progress: false,
            timeout: Some(60),
            config: None,
        };
        let config = Config::from_cli_and_env(&cli).unwrap();

        assert_eq!(config.api_url, "https://custom:9200");
        assert_eq!(config.api_user, "admin");
        assert_eq!(config.api_password.as_str(), "secret");
        assert_eq!(config.ca_cert.unwrap(), "/path/to/ca.pem");
        assert_eq!(config.client_cert.unwrap(), "/path/to/cert.pem");
        assert_eq!(config.client_key.unwrap(), "/path/to/key.pem");
        assert!(config.insecure);
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
        assert_eq!(config.api_password.as_str(), "env_pass");
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

    #[test]
    fn test_api_password_from_credential_store_when_env_unset() {
        // No CLI, no env -> should fall through to the credential store.
        let store = MemoryStore::new();
        store
            .set(credential_store::KEY_API_PASSWORD, "from-keychain")
            .unwrap();

        let cli = default_cli_opts();
        let config = Config::from_cli_env_and_store(&cli, None, &store).unwrap();

        assert_eq!(config.api_password.as_str(), "from-keychain");
    }

    #[test]
    fn test_env_wins_over_credential_store() {
        let store = MemoryStore::new();
        store
            .set(credential_store::KEY_API_PASSWORD, "from-keychain")
            .unwrap();

        let env_pw = Zeroizing::new("from-env".to_string());
        let cli = default_cli_opts();
        let config = Config::from_cli_env_and_store(&cli, Some(&env_pw), &store).unwrap();

        assert_eq!(config.api_password.as_str(), "from-env");
    }

    #[test]
    fn test_cli_wins_over_env_and_credential_store() {
        let store = MemoryStore::new();
        store
            .set(credential_store::KEY_API_PASSWORD, "from-keychain")
            .unwrap();

        let env_pw = Zeroizing::new("from-env".to_string());
        let cli = CliOpts {
            api_password: Some("from-cli".to_string().into()),
            ..default_cli_opts()
        };
        let config = Config::from_cli_env_and_store(&cli, Some(&env_pw), &store).unwrap();

        assert_eq!(config.api_password.as_str(), "from-cli");
    }

    #[test]
    fn test_credential_store_backend_error_propagates_and_not_fallthrough() {
        // No CLI, no env -> would normally fall through to the store.
        // The store returns Backend, which must surface as a
        // CredentialStore error (NOT silently produce an empty
        // password), so users notice the Keychain ACL denial rather
        // than running against an empty secret.
        let store = FailingStore::backend();
        let cli = default_cli_opts();
        let err = Config::from_cli_env_and_store(&cli, None, &store).unwrap_err();
        match err {
            WazuhError::CredentialStore(msg) => {
                assert!(msg.contains("simulated backend failure"));
                assert!(msg.contains("WAZUH_API_PASSWORD"));
            }
            other => panic!("expected CredentialStore error, got {:?}", other),
        }
    }

    #[test]
    fn test_file_supplies_api_url_when_cli_and_env_unset() {
        // The config-file tier only kicks in when CLI and env do
        // not supply a value. Pin that contract so a rewrite cannot
        // silently promote the file above env.
        let file = file::ConfigFile {
            api: file::ApiSection {
                url: Some("https://from-file:55000".to_string()),
                user: Some("file-user".to_string()),
                password: None,
            },
            ..Default::default()
        };
        let store = MemoryStore::new();
        let cli = default_cli_opts();
        let config = Config::from_cli_env_store_and_file(&cli, None, &store, Some(&file)).unwrap();
        assert_eq!(config.api_url, "https://from-file:55000");
        assert_eq!(config.api_user, "file-user");
    }

    #[test]
    fn test_env_wins_over_file_for_api_url() {
        // WAZUH_API_URL > file. This env access runs inside a
        // single-threaded test runner (--test-threads=1) which the
        // crate enforces precisely so env mutations do not collide.
        unsafe {
            std::env::set_var("WAZUH_API_URL", "https://from-env:55000");
        }
        let file = file::ConfigFile {
            api: file::ApiSection {
                url: Some("https://from-file:55000".to_string()),
                user: None,
                password: None,
            },
            ..Default::default()
        };
        let store = MemoryStore::new();
        let cli = default_cli_opts();
        let config = Config::from_cli_env_store_and_file(&cli, None, &store, Some(&file)).unwrap();
        assert_eq!(config.api_url, "https://from-env:55000");
        unsafe {
            std::env::remove_var("WAZUH_API_URL");
        }
    }

    #[test]
    fn test_cli_wins_over_file_for_api_url() {
        let file = file::ConfigFile {
            api: file::ApiSection {
                url: Some("https://from-file:55000".to_string()),
                user: None,
                password: None,
            },
            ..Default::default()
        };
        let store = MemoryStore::new();
        let cli = CliOpts {
            api_url: Some("https://from-cli:55000".to_string()),
            ..default_cli_opts()
        };
        let config = Config::from_cli_env_store_and_file(&cli, None, &store, Some(&file)).unwrap();
        assert_eq!(config.api_url, "https://from-cli:55000");
    }

    #[test]
    fn test_keychain_wins_over_file_password_because_file_password_is_ignored() {
        // `[api] password` in the file is deliberately IGNORED by
        // the merge (file.rs's `load()` warns about it, and the
        // merge layer simply never reads `file.api.password`). So
        // the Keychain's value wins.
        let file = file::ConfigFile {
            api: file::ApiSection {
                url: None,
                user: None,
                password: Some("plaintext-in-file".to_string()),
            },
            ..Default::default()
        };
        let store = MemoryStore::new();
        store
            .set(credential_store::KEY_API_PASSWORD, "from-keychain")
            .unwrap();
        let cli = default_cli_opts();
        let config = Config::from_cli_env_store_and_file(&cli, None, &store, Some(&file)).unwrap();
        assert_eq!(config.api_password.as_str(), "from-keychain");
    }

    #[test]
    fn test_file_timeout_used_when_cli_and_env_unset() {
        let file = file::ConfigFile {
            request: file::RequestSection { timeout: Some(77) },
            ..Default::default()
        };
        let store = MemoryStore::new();
        let cli = default_cli_opts();
        let config = Config::from_cli_env_store_and_file(&cli, None, &store, Some(&file)).unwrap();
        assert_eq!(config.timeout, 77);
    }

    #[test]
    fn test_file_tls_insecure_flag_merges() {
        let file = file::ConfigFile {
            tls: file::TlsSection {
                insecure: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let store = MemoryStore::new();
        let cli = default_cli_opts();
        let config = Config::from_cli_env_store_and_file(&cli, None, &store, Some(&file)).unwrap();
        assert!(config.insecure);
    }

    #[test]
    fn test_credential_store_backend_does_not_swallow_when_env_set() {
        // If the captured env password is set, resolve() should use
        // it and never even consult the store — so a Backend error
        // must not surface in that case. This pins the "env > store"
        // priority even when the real `WAZUH_API_PASSWORD` env var
        // has already been scrubbed.
        let env_pw = Zeroizing::new("from-env-bypass".to_string());
        let store = FailingStore::backend();
        let cli = default_cli_opts();
        let config = Config::from_cli_env_and_store(&cli, Some(&env_pw), &store).unwrap();
        assert_eq!(config.api_password.as_str(), "from-env-bypass");
    }

    #[test]
    fn test_config_debug_masks_api_password() {
        let config = Config {
            api_url: "https://x".to_string(),
            api_user: "u".to_string(),
            api_password: "super-secret".to_string().into(),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            insecure: false,
            output_format: OutputFormat::Json,
            raw_output: false,
            progress: false,
            timeout: 30,
        };
        let dbg = format!("{:?}", config);
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("***"));
    }

    #[test]
    fn test_config_debug_shows_empty_marker_when_password_unset() {
        let config = Config {
            api_url: "https://x".to_string(),
            api_user: "u".to_string(),
            api_password: Zeroizing::new(String::new()),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            insecure: false,
            output_format: OutputFormat::Json,
            raw_output: false,
            progress: false,
            timeout: 30,
        };
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("(empty)"));
        assert!(!dbg.contains("***"));
    }
}
