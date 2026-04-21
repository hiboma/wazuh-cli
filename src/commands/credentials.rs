use std::io;

use zeroize::Zeroizing;

use crate::cli::credentials::{CredentialField, CredentialsAction, CredentialsCommand};
use crate::config::credential_store::{CredentialStore, KEY_API_PASSWORD, default_store};
use crate::error::WazuhError;

pub fn run(cmd: CredentialsCommand) -> Result<(), WazuhError> {
    let store = default_store();
    match cmd.action {
        CredentialsAction::Set { field, stdin } => set_value(store.as_ref(), field, stdin),
        CredentialsAction::Delete { field } => delete_value(store.as_ref(), field),
        CredentialsAction::Status => print_status(store.as_ref()),
    }
}

fn set_value(
    store: &dyn CredentialStore,
    field: CredentialField,
    from_stdin: bool,
) -> Result<(), WazuhError> {
    // Wrap the secret in Zeroizing so the heap allocation is wiped on
    // drop. This narrows the window where a swap-out, core dump, or
    // panic-time backtrace could expose the value. The buffer used to
    // read stdin is also zeroized for the same reason.
    let value: Zeroizing<String> = if from_stdin {
        let mut buf: Zeroizing<String> = Zeroizing::new(String::new());
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| WazuhError::Config(format!("failed to read stdin: {}", e)))?;
        // Trim full whitespace (not just CRLF) so a stray trailing
        // space pasted from a password manager does not silently
        // corrupt the secret.
        let trimmed = Zeroizing::new(buf.trim().to_string());
        if trimmed.is_empty() {
            return Err(WazuhError::Config("empty value from stdin".to_string()));
        }
        trimmed
    } else {
        let prompt = format!("Enter {} (input hidden): ", field.key());
        Zeroizing::new(
            rpassword::prompt_password(prompt)
                .map_err(|e| WazuhError::Config(format!("failed to read password: {}", e)))?,
        )
    };

    if value.is_empty() {
        return Err(WazuhError::Config("empty value".to_string()));
    }

    store
        .set(field.key(), &value)
        .map_err(|e| WazuhError::Config(e.to_string()))?;
    println!("Stored {} in credential store", field.key());
    println!("Verify with: wazuh-cli credentials status");
    Ok(())
}

fn delete_value(store: &dyn CredentialStore, field: CredentialField) -> Result<(), WazuhError> {
    store
        .delete(field.key())
        .map_err(|e| WazuhError::Config(e.to_string()))?;
    println!("Deleted {} from credential store", field.key());
    Ok(())
}

fn print_status(store: &dyn CredentialStore) -> Result<(), WazuhError> {
    // Print only the key name ("api_password") and a presence flag —
    // never the credential value.
    let keys = [KEY_API_PASSWORD];
    println!("Credential store: macOS Keychain (service=dev.wazuh-cli)");
    let mut saw_error = false;
    for key in keys {
        match store.get(key) {
            Ok(Some(_)) => println!("  {} : stored", key),
            Ok(None) => println!("  {} : not stored", key),
            Err(e) => {
                println!("  {} : error ({})", key, e);
                saw_error = true;
            }
        }
    }
    if saw_error {
        println!();
        println!(
            "One or more entries could not be accessed. This usually means a \
             Keychain ACL change (often triggered by a `cargo install` rebuild \
             that changed the binary's code signature). Open Keychain Access.app, \
             find the `dev.wazuh-cli` entry, and re-grant access via the \
             \"Access Control\" tab (or delete and re-store the entry with \
             `wazuh-cli credentials set api-password`)."
        );
    }
    Ok(())
}
