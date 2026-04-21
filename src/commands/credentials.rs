use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use zeroize::Zeroizing;

use crate::cli::credentials::{CredentialField, CredentialsAction, CredentialsCommand};
use crate::config::credential_store::{
    CredentialStore, KEY_API_PASSWORD, StoreError, default_store,
};
use crate::error::WazuhError;

/// Shared text used when the Keychain backend returns a real access
/// failure (denied ACL, daemon unavailable). Pointing users at
/// Keychain Access.app is the fastest path to recovery; re-storing via
/// `credentials set` is the fallback.
const ACL_GUIDANCE: &str = "The Keychain backend refused the operation. This usually means a \
     Keychain ACL change (often triggered by a `cargo install` rebuild or \
     `brew upgrade` that changed the binary's code signature). Open \
     Keychain Access.app, find the `dev.wazuh-cli` entry, and re-grant \
     access via the \"Access Control\" tab (or delete and re-store the \
     entry with `wazuh-cli credentials set api-password`).";

pub fn run(cmd: CredentialsCommand) -> Result<(), WazuhError> {
    let store = default_store();
    match cmd.action {
        CredentialsAction::Set { field, stdin, file } => {
            set_value(store.as_ref(), field, stdin, file.as_deref())
        }
        CredentialsAction::Delete { field } => delete_value(store.as_ref(), field),
        CredentialsAction::Status { json } => print_status(store.as_ref(), json),
    }
}

/// Strip a single trailing `\r`, `\n`, or `\r\n`, leaving any other
/// trailing whitespace intact. Full `String::trim()` would silently
/// eat a real trailing space in a password — unacceptable for secret
/// material. This matches what a terminal / editor would insert and
/// nothing more.
fn strip_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    } else if s.ends_with('\r') {
        s.pop();
    }
}

fn read_from_file(path: &Path) -> Result<Zeroizing<String>, WazuhError> {
    // Refuse world/group-readable files. A secret that any other
    // account on the system can read defeats the point of storing it
    // in the Keychain.
    let meta = fs::metadata(path)
        .map_err(|e| WazuhError::Config(format!("failed to stat {}: {}", path.display(), e)))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(WazuhError::Config(format!(
            "{} has mode {:o}; refuse to read a secret from a file \
             accessible to other users. Run `chmod 600 {}` and retry.",
            path.display(),
            mode,
            path.display()
        )));
    }

    // Read straight into a `String` and wrap in `Zeroizing` so the
    // heap allocation is wiped on drop. `fs::read_to_string` rejects
    // non-UTF-8 content, which is what we want — a password the
    // user can actually type into a prompt.
    let raw = fs::read_to_string(path)
        .map_err(|e| WazuhError::Config(format!("failed to read {}: {}", path.display(), e)))?;
    let mut s: Zeroizing<String> = Zeroizing::new(raw);
    strip_trailing_newline(&mut s);
    Ok(s)
}

fn read_from_stdin() -> Result<Zeroizing<String>, WazuhError> {
    // `read_to_string` is used over `read_line` so callers can pipe
    // multi-line secrets (rare, but the code becomes wrong if we
    // silently truncate). Only the final `\r` / `\n` is stripped.
    let mut buf: Zeroizing<String> = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| WazuhError::Config(format!("failed to read stdin: {}", e)))?;
    strip_trailing_newline(&mut buf);
    Ok(buf)
}

fn prompt_tty(field: CredentialField) -> Result<Zeroizing<String>, WazuhError> {
    let prompt = format!("Enter {} (input hidden): ", field.display());
    let raw = rpassword::prompt_password(prompt)
        .map_err(|e| WazuhError::Config(format!("failed to read password: {}", e)))?;
    Ok(Zeroizing::new(raw))
}

fn set_value(
    store: &dyn CredentialStore,
    field: CredentialField,
    from_stdin: bool,
    from_file: Option<&Path>,
) -> Result<(), WazuhError> {
    // Resolve the input source. `conflicts_with` in the CLI definition
    // guarantees at most one of `--stdin` / `--file` is set, so the
    // priority order here is informational.
    let value: Zeroizing<String> = if let Some(p) = from_file {
        read_from_file(p)?
    } else if from_stdin {
        read_from_stdin()?
    } else {
        prompt_tty(field)?
    };

    if value.is_empty() {
        return Err(WazuhError::Config(
            "empty value; refusing to store an empty credential".to_string(),
        ));
    }

    if let Err(e) = store.set(field.key(), &value) {
        return Err(store_err_with_guidance(e));
    }
    println!("Stored {} in credential store", field.display());
    // Route the nudge to stderr so piped / captured stdout stays
    // machine-clean.
    eprintln!("Verify with: wazuh-cli credentials status");
    Ok(())
}

fn delete_value(store: &dyn CredentialStore, field: CredentialField) -> Result<(), WazuhError> {
    if let Err(e) = store.delete(field.key()) {
        return Err(store_err_with_guidance(e));
    }
    println!("Deleted {} from credential store", field.display());
    Ok(())
}

fn print_status(store: &dyn CredentialStore, json: bool) -> Result<(), WazuhError> {
    // Print only the key name ("api-password") and a presence flag —
    // never the credential value.
    let fields = [CredentialField::ApiPassword];

    if json {
        return print_status_json(store, &fields);
    }

    // Header on stderr so stdout only carries the TSV rows (caller can
    // `awk` / `jq` without parsing headers).
    eprintln!("Credential store: macOS Keychain (service=dev.wazuh-cli)");
    let mut saw_error = false;
    for field in fields {
        match store.get(field.key()) {
            Ok(Some(_)) => println!("{}\tstored", field.display()),
            Ok(None) => println!("{}\tnot-stored", field.display()),
            Err(e) => {
                println!("{}\terror\t{}", field.display(), e);
                saw_error = true;
            }
        }
    }
    if saw_error {
        eprintln!();
        eprintln!("{}", ACL_GUIDANCE);
    }
    Ok(())
}

fn print_status_json(
    store: &dyn CredentialStore,
    fields: &[CredentialField],
) -> Result<(), WazuhError> {
    let mut entries = serde_json::Map::new();
    let mut saw_error = false;
    for field in fields {
        let (state, err) = match store.get(field.key()) {
            Ok(Some(_)) => ("stored", None),
            Ok(None) => ("not_stored", None),
            Err(e) => {
                saw_error = true;
                ("error", Some(e.to_string()))
            }
        };
        let mut entry = serde_json::Map::new();
        entry.insert(
            "state".to_string(),
            serde_json::Value::String(state.to_string()),
        );
        if let Some(msg) = err {
            entry.insert("error".to_string(), serde_json::Value::String(msg));
        }
        entries.insert(
            field.display().to_string(),
            serde_json::Value::Object(entry),
        );
    }

    let out = serde_json::json!({
        "service": crate::config::credential_store::KEYCHAIN_SERVICE,
        "entries": entries,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(WazuhError::Json)?
    );

    if saw_error {
        eprintln!("{}", ACL_GUIDANCE);
    }
    Ok(())
}

/// Map a `StoreError` to a `WazuhError`, attaching the ACL guidance so
/// `set` / `delete` failure paths surface the same hint that `status`
/// shows on a read failure.
fn store_err_with_guidance(e: StoreError) -> WazuhError {
    match e {
        StoreError::Backend(msg) => {
            WazuhError::CredentialStore(format!("{}\n\n{}", msg, ACL_GUIDANCE))
        }
        StoreError::Unavailable(msg) => WazuhError::CredentialStore(format!(
            "{}\n\nOn non-macOS hosts (or a macOS install without a default \
             keychain) the credential store is unavailable. Use \
             WAZUH_API_PASSWORD or `--api-password` instead.",
            msg
        )),
    }
}

// Unused helper left here to make the public surface explicit.
#[allow(dead_code)]
fn _ensure_field_key(_: CredentialField) -> &'static str {
    KEY_API_PASSWORD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_trailing_newline_handles_lf() {
        let mut s = String::from("secret\n");
        strip_trailing_newline(&mut s);
        assert_eq!(s, "secret");
    }

    #[test]
    fn strip_trailing_newline_handles_crlf() {
        let mut s = String::from("secret\r\n");
        strip_trailing_newline(&mut s);
        assert_eq!(s, "secret");
    }

    #[test]
    fn strip_trailing_newline_handles_bare_cr() {
        let mut s = String::from("secret\r");
        strip_trailing_newline(&mut s);
        assert_eq!(s, "secret");
    }

    #[test]
    fn strip_trailing_newline_preserves_trailing_space() {
        // This is the whole reason we hand-roll instead of calling
        // `trim()`: a password ending in a space is valid and must
        // not be silently mutated.
        let mut s = String::from("secret \n");
        strip_trailing_newline(&mut s);
        assert_eq!(s, "secret ");
    }

    #[test]
    fn strip_trailing_newline_only_removes_one_newline() {
        // A blank line after the secret is the user's input — only
        // the final `\n` should go. Pre-existing blank lines in a
        // multi-line secret (rare but legal) must be preserved.
        let mut s = String::from("secret\n\n");
        strip_trailing_newline(&mut s);
        assert_eq!(s, "secret\n");
    }

    #[test]
    fn strip_trailing_newline_no_op_without_trailing_newline() {
        let mut s = String::from("secret");
        strip_trailing_newline(&mut s);
        assert_eq!(s, "secret");
    }
}
