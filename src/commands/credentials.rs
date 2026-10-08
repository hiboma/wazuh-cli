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
        match store.get(field.key()) {
            Ok(Some(_)) => {
                println!("{}\tstored", field.display());
                all_missing = false;
            }
            Ok(None) => println!("{}\tnot-stored", field.display()),
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
        let (state, err) = match store.get(field.key()) {
            Ok(Some(_)) => {
                any_stored = true;
                ("stored", None)
            }
            Ok(None) => ("not-stored", None),
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
