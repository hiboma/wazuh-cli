use std::path::Path;

use crate::cli::credentials::{CredentialField, CredentialsAction, CredentialsCommand};
use crate::config::credential_store::{
    CredentialStore, KEY_API_PASSWORD, StoreError, default_store,
};
use crate::error::WazuhError;
use crate::secret::{SecretSource, read_secret};

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

fn set_value(
    store: &dyn CredentialStore,
    field: CredentialField,
    from_stdin: bool,
    from_file: Option<&Path>,
) -> Result<(), WazuhError> {
    let prompt = format!("Enter {} (input hidden): ", field.display());
    let value = read_secret(
        SecretSource::from_flags(from_stdin, from_file),
        &prompt,
        false,
    )?;

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
    // `awk` / `cut -f2` without parsing headers).
    eprintln!("Credential store: macOS Keychain (service=dev.wazuh-cli)");
    let mut saw_error = false;
    let mut all_missing = true;
    for field in fields {
        match store.contains(field.key()) {
            Ok(true) => {
                println!("{}\tstored", field.display());
                all_missing = false;
            }
            Ok(false) => println!("{}\tnot-stored", field.display()),
            Err(e) => {
                // Sanitize the error text: any TAB / CR / LF in it
                // would silently break the 3-column TSV invariant
                // (`cut -f3` would pick up the wrong substring, or
                // tooling would see an extra row). Replace with
                // single spaces. Prefer `--json` if you need the
                // original message intact.
                let msg = e.to_string().replace(['\t', '\n', '\r'], " ");
                println!("{}\terror\t{}", field.display(), msg);
                saw_error = true;
                all_missing = false;
            }
        }
    }
    if saw_error {
        eprintln!();
        eprintln!("{}", ACL_GUIDANCE);
    } else if all_missing {
        // First-time-user nudge. Only fires when nothing is stored
        // and nothing errored — the two distinct "show me my
        // setup" paths give distinct guidance.
        eprintln!();
        eprintln!(
            "No credentials stored yet. To populate the Keychain, run:\n  \
             wazuh-cli credentials set api-password"
        );
    }
    Ok(())
}

fn print_status_json(
    store: &dyn CredentialStore,
    fields: &[CredentialField],
) -> Result<(), WazuhError> {
    let mut entries = serde_json::Map::new();
    let mut saw_error = false;
    let mut any_stored = false;
    for field in fields {
        // Use hyphen-separated state names so the JSON and TSV
        // vocabularies agree: `stored`, `not-stored`, `error`. The
        // key in `entries` is also the hyphenated CLI arg value so
        // `.entries["api-password"].state` works without a
        // conversion table on the caller side.
        let (state, err) = match store.contains(field.key()) {
            Ok(true) => {
                any_stored = true;
                ("stored", None)
            }
            Ok(false) => ("not-stored", None),
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

    // `ok` is a top-level boolean so monitoring checks (Datadog,
    // PagerDuty custom checks, a trivial `jq '.ok'`) do not have to
    // enumerate the entries map to decide "is anything wrong".
    let ok = !saw_error;
    let out = serde_json::json!({
        "service": crate::config::credential_store::KEYCHAIN_SERVICE,
        "ok": ok,
        "entries": entries,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(WazuhError::Json)?
    );

    if saw_error {
        eprintln!("{}", ACL_GUIDANCE);
    } else if !any_stored {
        eprintln!(
            "No credentials stored yet. To populate the Keychain, run:\n  \
             wazuh-cli credentials set api-password"
        );
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
             WAZUH_API_PASSWORD instead.",
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
    use crate::config::credential_store::{FailingStore, MemoryStore};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    const SENTINEL: &str = "credential-command-secret-SENTINEL";
    const CHILD_CASE: &str = "WAZUH_TEST_CREDENTIAL_OUTPUT_CASE";

    #[test]
    fn credential_commands_do_not_print_stored_or_submitted_secrets() {
        // Capture the actual println!/eprintln! output in an isolated test
        // process. All stores are injected; no test opens the real Keychain.
        if let Ok(case) = std::env::var(CHILD_CASE) {
            exercise_command(&case);
            return;
        }
        for case in [
            "set",
            "set-error",
            "missing-tsv",
            "stored-tsv",
            "error-tsv",
            "missing-json",
            "stored-json",
            "error-json",
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::credentials::tests::credential_commands_do_not_print_stored_or_submitted_secrets",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_CASE, case)
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            // Do not include captured output in assertions: a regression
            // must not cause even the test harness to print a secret.
            assert!(!stdout.contains(SENTINEL), "stdout leaked in {case}");
            assert!(!stderr.contains(SENTINEL), "stderr leaked in {case}");
            assert!(output.status.success(), "child failed in {case}");
            if case == "set" {
                assert!(stdout.contains("Stored api-password in credential store"));
                assert!(stderr.contains("Verify with: wazuh-cli credentials status"));
            } else if case == "set-error" {
                assert!(!stdout.contains("Stored api-password"));
                assert!(stderr.contains("simulated backend failure"));
                assert!(stderr.contains(ACL_GUIDANCE));
            } else {
                let state = if case.starts_with("missing") {
                    "not-stored"
                } else if case.starts_with("stored") {
                    "stored"
                } else {
                    "error"
                };
                if case.ends_with("json") {
                    // The test harness adds its own lines around the command.
                    let start = stdout.find('{').unwrap();
                    let end = stdout.rfind('}').unwrap() + 1;
                    let value: serde_json::Value =
                        serde_json::from_str(&stdout[start..end]).unwrap();
                    assert_eq!(value["entries"]["api-password"]["state"], state);
                    assert_eq!(value["ok"], state != "error");
                    assert_eq!(
                        value["service"],
                        crate::config::credential_store::KEYCHAIN_SERVICE
                    );
                    assert_eq!(
                        value["entries"]["api-password"]["error"].is_string(),
                        state == "error"
                    );
                } else {
                    let start = stdout.find("api-password\t").unwrap();
                    let row = stdout[start..].lines().next().unwrap();
                    let columns: Vec<_> = row.split('\t').collect();
                    assert_eq!(columns[1], state);
                    assert_eq!(columns.len(), if state == "error" { 3 } else { 2 });
                }
                assert_eq!(stderr.contains(ACL_GUIDANCE), state == "error");
                assert_eq!(
                    stderr.contains("No credentials stored yet"),
                    state == "not-stored"
                );
            }
        }
    }

    fn exercise_command(case: &str) {
        let memory = MemoryStore::new();
        let failing = FailingStore::backend();
        if case.starts_with("set") {
            let path = std::env::temp_dir().join(format!(
                "wazuh-credential-command-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            writeln!(file, "{SENTINEL}").unwrap();
            drop(file);
            let store: &dyn CredentialStore = if case == "set-error" {
                &failing
            } else {
                &memory
            };
            let result = set_value(store, CredentialField::ApiPassword, false, Some(&path));
            std::fs::remove_file(path).unwrap();
            if case == "set-error" {
                crate::output::print_error(&result.unwrap_err());
            } else {
                result.unwrap();
                assert!(memory.get(KEY_API_PASSWORD).unwrap().as_deref() == Some(SENTINEL));
            }
        } else {
            if case.starts_with("stored") {
                memory.set(KEY_API_PASSWORD, SENTINEL).unwrap();
            }
            let store: &dyn CredentialStore = if case.starts_with("error") {
                &failing
            } else {
                &memory
            };
            print_status(store, case.ends_with("json")).unwrap();
        }
    }
}
