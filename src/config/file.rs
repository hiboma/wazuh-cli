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
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zeroize::Zeroizing;

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

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSection {
    pub url: Option<String>,
    pub user: Option<String>,
    /// Recognize the deprecated field without keeping its plaintext value.
    pub password: Option<serde::de::IgnoredAny>,
}

impl std::fmt::Debug for ApiSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiSection")
            .field("url", &self.url.as_ref().map(|_| "[redacted]"))
            .field("user", &self.user.as_ref().map(|_| "[redacted]"))
            .field("password_present", &self.password.is_some())
            .finish()
    }
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
    if !matches!(fs::symlink_metadata(&candidate), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
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

    match read_config(&path) {
        Ok(text) => {
            let file: ConfigFile = toml::from_str(&text).map_err(|e| {
                let offset = e.span().map(|span| span.start).unwrap_or(0).min(text.len());
                let prefix = &text.as_bytes()[..offset];
                let line = prefix.iter().filter(|&&b| b == b'\n').count() + 1;
                let column = prefix
                    .iter()
                    .rposition(|&b| b == b'\n')
                    .map_or(offset + 1, |last| offset - last);
                WazuhError::Config(format!(
                    "failed to parse config file {} at line {}, column {}: invalid configuration",
                    path.display(),
                    line,
                    column
                ))
            })?;
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

fn invalid_file(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

const CONFIG_MAX_BYTES: usize = 1024 * 1024;

fn read_config(path: &Path) -> std::io::Result<Zeroizing<String>> {
    read_config_after_check(path, || {})
}

// The hook permits deterministic testing of replacement between lstat and open.
fn read_config_after_check(
    path: &Path,
    after_check: impl FnOnce(),
) -> std::io::Result<Zeroizing<String>> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(invalid_file("config must be a regular file, not a symlink"));
    }
    after_check();
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    validate_config_metadata(&before, &meta)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(CONFIG_MAX_BYTES + 1));
    file.take((CONFIG_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > CONFIG_MAX_BYTES {
        return Err(invalid_file("config exceeds 1 MiB"));
    }
    let text = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Zeroizing::new(text),
        Err(error) => {
            let _bytes = Zeroizing::new(error.into_bytes());
            return Err(invalid_file("config is not valid UTF-8"));
        }
    };
    Ok(text)
}

fn validate_config_metadata(before: &fs::Metadata, meta: &fs::Metadata) -> std::io::Result<()> {
    if !meta.is_file() {
        return Err(invalid_file("config must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != meta.dev() || before.ino() != meta.ino() {
            return Err(invalid_file("config changed while being opened"));
        }
        // SAFETY: geteuid has no preconditions and does not modify process state.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(invalid_file("config must be owned by the effective user"));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(invalid_file("config must not be group/world writable"));
        }
        if meta.nlink() != 1 {
            return Err(invalid_file("config must have exactly one hard link"));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = before;
        Err(invalid_file(
            "configuration files require Unix ownership checks; use CLI options and environment settings on this platform",
        ))
    }
    #[cfg(unix)]
    Ok(())
}

#[cfg(all(test, not(unix)))]
mod platform_tests {
    #[test]
    fn rejects_config_without_platform_trust_checks() {
        let metadata = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
        assert!(super::validate_config_metadata(&metadata, &metadata).is_err());
    }
}

fn warn_on_password_field(path: &Path, file: &ConfigFile) {
    if file.api.password.is_some() {
        eprintln!(
            "warning: {} contains a plaintext [api] password entry. \
             wazuh-cli IGNORES this field and sources the password \
             from WAZUH_API_PASSWORD or the macOS \
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
            WazuhError::Config(msg) => {
                assert!(msg.contains("invalid configuration"));
                assert!(!msg.contains("clinet_cert"));
            }
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
    fn password_field_is_detected_without_retaining_value() {
        let path = write_tmp_toml(
            r#"
[api]
password = "plaintext-leak"
"#,
        );
        let (_, file) = load(Some(&path), None).unwrap().unwrap();
        assert!(file.api.password.is_some());
        assert!(!format!("{file:?}").contains("plaintext-leak"));
    }

    #[test]
    fn parser_diagnostics_never_echo_secret_values_or_unknown_keys() {
        for contents in [
            "[api]\npassword = \"SENTINEL_SECRET",
            "[api]\nSENTINEL_SECRET = true",
            "[request]\ntimeout = \"SENTINEL_SECRET\"",
        ] {
            let path = write_tmp_toml(contents);
            let error = load(Some(&path), None).unwrap_err();
            assert!(!format!("{error:?}").contains("SENTINEL_SECRET"));
            assert!(error.to_string().contains("line"));
        }
    }

    #[test]
    fn config_debug_hides_unvalidated_url() {
        let path = write_tmp_toml("[api]\nurl = 'https://SENTINEL_SECRET@host/'");
        let (_, cfg) = load(Some(&path), None).unwrap().unwrap();
        assert!(!format!("{cfg:?}").contains("SENTINEL_SECRET"));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_readable_but_rejects_writable_shared_config() {
        use std::os::unix::fs::PermissionsExt;
        let path = write_tmp_toml("");
        for mode in [0o600, 0o644] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(load(Some(&path), None).is_ok());
        }
        for mode in [0o620, 0o602, 0o666] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(load(Some(&path), None).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_links_directory_and_fifo() {
        use std::os::unix::fs::symlink;
        let path = write_tmp_toml("");
        let dir = path.parent().unwrap();
        let link = dir.join("symlink");
        symlink(&path, &link).unwrap();
        assert!(load(Some(&link), None).is_err());
        assert!(load(Some(dir), None).is_err());
        let fifo = dir.join("fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: cpath is a valid nul-terminated path.
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(load(Some(&fifo), None).is_err());
        fs::hard_link(&path, dir.join("hardlink")).unwrap();
        assert!(load(Some(&path), None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_another_users_file_metadata() {
        use std::os::unix::fs::MetadataExt;
        // /etc/passwd is a readable regular file owned by root on supported
        // Unix platforms. No ownership changes or elevated privileges needed.
        let meta = fs::metadata("/etc/passwd").unwrap();
        // SAFETY: geteuid has no preconditions.
        if meta.uid() != unsafe { libc::geteuid() } {
            let error = validate_config_metadata(&meta, &meta).unwrap_err();
            assert!(error.to_string().contains("effective user"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_path_replacement_between_check_and_open() {
        for replace_with_symlink in [false, true] {
            let path = write_tmp_toml("");
            let replacement = write_tmp_toml("[api]\nurl = 'https://attacker.invalid'");
            let result = read_config_after_check(&path, || {
                fs::remove_file(&path).unwrap();
                if replace_with_symlink {
                    std::os::unix::fs::symlink(&replacement, &path).unwrap();
                } else {
                    fs::rename(&replacement, &path).unwrap();
                }
            });
            assert!(result.is_err());
        }
    }

    #[test]
    fn rejects_invalid_utf8_and_oversized_config() {
        let path = write_tmp_toml("");
        fs::write(&path, [0xff]).unwrap();
        assert!(load(Some(&path), None).is_err());
        fs::write(&path, vec![b' '; CONFIG_MAX_BYTES + 1]).unwrap();
        assert!(load(Some(&path), None).is_err());
    }
}
