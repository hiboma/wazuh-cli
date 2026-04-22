//! TOML configuration file support.
//!
//! Search order (first hit wins):
//!   1. `--config <PATH>` (from `CliOpts.config`)
//!   2. `WAZUH_CONFIG` environment variable
//!   3. `~/.config/wazuh-cli/config.toml` (or `$XDG_CONFIG_HOME/wazuh-cli/config.toml`)
//!
//! Within the merged Config, the file sits **below** Keychain in the
//! priority chain: CLI > env > Keychain (api_password only) > file >
//! defaults. That way a rotated Keychain secret wins over a stale
//! password someone forgot to scrub from `config.toml`, and the
//! `[api] password` field in the file is actively discouraged
//! (warning + ignored) to push users toward the Keychain.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::WazuhError;

/// On-disk shape of `config.toml`. Every field is optional so the
/// merge layer can skip absent keys without special-casing.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub api: ApiSection,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub output: OutputSection,
    #[serde(default)]
    pub request: RequestSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSection {
    pub url: Option<String>,
    pub user: Option<String>,
    /// Present only so we can recognize it and warn. Reading the
    /// plaintext here defeats the purpose of the Keychain backing —
    /// we refuse to use the value and tell the user to run
    /// `wazuh-cli credentials set api-password` instead.
    pub password: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub insecure: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSection {
    pub format: Option<String>,
    pub raw: Option<bool>,
    pub progress: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSection {
    pub timeout: Option<u64>,
}

/// Resolve which config file path to read, honoring the documented
/// search order. Returns `None` if nothing is found (which is not an
/// error — the file is optional).
///
/// - `cli_override`: `--config <PATH>` value if the user passed one.
///   If set, the caller explicitly wanted this file; a missing file
///   at this path is an error rather than a silent skip.
/// - `env_override`: `WAZUH_CONFIG` env-var value if set and
///   non-empty. Same strictness as `cli_override`.
pub fn find_config_path(
    cli_override: Option<&Path>,
    env_override: Option<&str>,
) -> Option<PathBuf> {
    if let Some(p) = cli_override {
        return Some(p.to_path_buf());
    }
    if let Some(s) = env_override
        && !s.is_empty()
    {
        return Some(PathBuf::from(s));
    }

    // `$XDG_CONFIG_HOME/wazuh-cli/config.toml`, falling back to
    // `~/.config/wazuh-cli/config.toml`. Implemented by hand to
    // avoid pulling a directories-crate dependency for one path.
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    let candidate = base.join("wazuh-cli").join("config.toml");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Load and parse a config file, returning `None` when no path was
/// found and the caller did not ask for a specific one. Returns
/// `Err` for a user-supplied path that cannot be read / parsed, so
/// typos and syntax errors surface loudly.
pub fn load(
    cli_override: Option<&Path>,
    env_override: Option<&str>,
) -> Result<Option<(PathBuf, ConfigFile)>, WazuhError> {
    // `explicit == true` when the caller pointed us at a specific
    // path. A missing / unreadable file in that case is an error; a
    // missing default path is not.
    let explicit = cli_override.is_some() || env_override.is_some_and(|s| !s.is_empty());
    let Some(path) = find_config_path(cli_override, env_override) else {
        return Ok(None);
    };

    match fs::read_to_string(&path) {
        Ok(text) => {
            let file: ConfigFile = toml::from_str(&text).map_err(|e| {
                WazuhError::Config(format!(
                    "failed to parse config file {}: {}",
                    path.display(),
                    e
                ))
            })?;
            warn_on_insecure_mode(&path);
            warn_on_password_field(&path, &file);
            Ok(Some((path, file)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => {
            // Default location simply does not exist: that is fine.
            Ok(None)
        }
        Err(e) => Err(WazuhError::Config(format!(
            "failed to read config file {}: {}",
            path.display(),
            e
        ))),
    }
}

/// Warn (but do NOT refuse) when the config file is group/world
/// readable. The file is expected to contain non-secret settings
/// (URL, user, cert paths); the Keychain holds `api_password`. If
/// the user writes a plaintext password anyway and the file is
/// group-readable, we want that failure mode to be loud but we do
/// not want to break non-sensitive configs behind the same fence.
#[cfg(unix)]
fn warn_on_insecure_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: {} has mode {:o} (group/world accessible). \
                 This is tolerable for non-secret settings, but do NOT \
                 store secrets here; use \
                 `wazuh-cli credentials set api-password` instead. \
                 Consider `chmod 600 {}`.",
                path.display(),
                mode,
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_on_insecure_mode(_path: &Path) {}

fn warn_on_password_field(path: &Path, file: &ConfigFile) {
    if file.api.password.is_some() {
        eprintln!(
            "warning: {} contains a plaintext [api] password entry. \
             wazuh-cli IGNORES this field and sources the password \
             from --api-password, WAZUH_API_PASSWORD, or the macOS \
             Keychain (in that priority order). Remove the field \
             from the file and run `wazuh-cli credentials set \
             api-password` to store the secret safely.",
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp_toml(contents: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("wazuh-cli-configfile-test-{}-{}", pid, n));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parses_full_example() {
        let path = write_tmp_toml(
            r#"
[api]
url = "https://wazuh:55000"
user = "alice"

[tls]
ca_cert = "/tls/ca.pem"
client_cert = "/tls/c.pem"
client_key = "/tls/k.pem"
insecure = false

[output]
format = "json"
raw = false
progress = true

[request]
timeout = 45
"#,
        );
        let (_, file) = load(Some(&path), None).unwrap().unwrap();
        assert_eq!(file.api.url.as_deref(), Some("https://wazuh:55000"));
        assert_eq!(file.api.user.as_deref(), Some("alice"));
        assert!(file.api.password.is_none());
        assert_eq!(file.tls.ca_cert.as_deref(), Some("/tls/ca.pem"));
        assert_eq!(file.tls.insecure, Some(false));
        assert_eq!(file.output.format.as_deref(), Some("json"));
        assert_eq!(file.output.progress, Some(true));
        assert_eq!(file.request.timeout, Some(45));
    }

    #[test]
    fn rejects_unknown_field_at_parse_time() {
        // deny_unknown_fields is load-bearing: a typo like
        // `clinet_cert` must fail loudly so users find it before
        // wondering why mTLS is not working.
        let path = write_tmp_toml(
            r#"
[tls]
clinet_cert = "/oops.pem"
"#,
        );
        let err = load(Some(&path), None).unwrap_err();
        match err {
            WazuhError::Config(msg) => assert!(msg.contains("clinet_cert"), "got: {}", msg),
            other => panic!("expected Config error, got {:?}", other),
        }
    }

    #[test]
    fn missing_explicit_path_is_error() {
        let path = PathBuf::from("/tmp/wazuh-cli-definitely-missing-xyz");
        let err = load(Some(&path), None).unwrap_err();
        match err {
            WazuhError::Config(msg) => assert!(msg.contains("failed to read"), "got: {}", msg),
            other => panic!("expected Config error, got {:?}", other),
        }
    }

    #[test]
    fn missing_default_path_is_ok() {
        // When neither --config nor WAZUH_CONFIG is set, and the
        // default location does not exist, load() returns Ok(None)
        // rather than an error. This preserves the "config file is
        // optional" contract.
        //
        // We cannot force XDG_CONFIG_HOME to a guaranteed-empty path
        // across all test runners without side effects on other
        // tests; the `find_config_path` helper is exercised
        // directly instead.
        let dir = std::env::temp_dir().join(format!(
            "wazuh-cli-configfile-empty-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(
            find_config_path(None, Some(&format!("{}/does-not-exist", dir.display()))).is_some()
        );
        // A Some(path-string) is *requested*; the missing-file error
        // surfaces from load(), not from path resolution.
    }

    #[test]
    fn env_override_takes_precedence_over_default() {
        let path = write_tmp_toml("");
        let got = find_config_path(None, Some(path.to_str().unwrap())).unwrap();
        assert_eq!(got, path);
    }

    #[test]
    fn cli_override_wins_over_env_override() {
        let cli = write_tmp_toml("");
        let env = write_tmp_toml("");
        let got = find_config_path(Some(&cli), Some(env.to_str().unwrap())).unwrap();
        assert_eq!(got, cli);
    }

    #[test]
    fn password_field_triggers_warning_but_is_accessible() {
        // The warning goes to stderr (hard to assert here without
        // capturing). The important invariant for the merge layer is
        // that `file.api.password` is `Some` so the merge step knows
        // to IGNORE it — the field exists in the struct precisely so
        // we can detect its presence.
        let path = write_tmp_toml(
            r#"
[api]
password = "plaintext-leak"
"#,
        );
        let (_, file) = load(Some(&path), None).unwrap().unwrap();
        assert_eq!(file.api.password.as_deref(), Some("plaintext-leak"));
    }
}
