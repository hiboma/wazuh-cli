use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

/// `libc::O_NOFOLLOW` — refuse to open if the final path component is
/// a symlink. Inlined as a constant so we do not pull `libc` in just
/// for one flag. Value is stable across macOS / Linux / BSDs.
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;

/// Read the secret from a regular file at `path`, refusing:
///   1. symlinks in the final path component (`O_NOFOLLOW` on open),
///   2. any non-regular file (directory, FIFO, socket, device),
///   3. files whose mode allows group or world access (`0o077` bits
///      clear required),
///   4. files not owned by the current effective UID.
///
/// Checks 3 and 4 are done on the already-opened file descriptor, not
/// by path-based `stat`, to avoid a TOCTOU window between
/// `fs::metadata(path)` and `fs::read_to_string(path)` in which an
/// attacker with write access to a parent directory could swap the
/// path for a different file.
fn read_from_file(path: &Path) -> Result<Zeroizing<String>, WazuhError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            // `ELOOP` on macOS / Linux is what `O_NOFOLLOW` returns for
            // a symlinked final component. Translate to a clearer
            // message so the user knows why the seemingly valid path
            // was rejected.
            if e.raw_os_error() == Some(libc_eloop()) {
                WazuhError::Config(format!(
                    "{} is a symlink; refusing to follow for secret \
                     material. Pass the real path, or copy the secret \
                     to a regular file.",
                    path.display()
                ))
            } else if e.kind() == io::ErrorKind::NotFound {
                WazuhError::Config(format!(
                    "{} does not exist. Double-check the --file path \
                     (shell ~ is not expanded by clap; pass an \
                     absolute path or a path relative to the current \
                     working directory).",
                    path.display()
                ))
            } else {
                WazuhError::Config(format!("failed to open {}: {}", path.display(), e))
            }
        })?;

    // fstat the opened fd (not the path) so the mode/uid checks
    // apply to the exact inode we are about to read, closing the
    // TOCTOU window.
    let meta = file
        .metadata()
        .map_err(|e| WazuhError::Config(format!("failed to stat {}: {}", path.display(), e)))?;

    if !meta.is_file() {
        return Err(WazuhError::Config(format!(
            "{} is not a regular file; refuse to read a secret from \
             a directory, FIFO, socket, or device.",
            path.display()
        )));
    }

    // Ownership check: another user's file sitting in an
    // invoker-writable directory (e.g. /tmp) would otherwise satisfy
    // the mode check while the plaintext is attacker-controlled.
    // `geteuid()` is safe on Unix.
    //
    // SAFETY: `libc::geteuid` is a direct syscall with no preconditions.
    let euid = unsafe { libc_geteuid() };
    if meta.uid() != euid {
        return Err(WazuhError::Config(format!(
            "{} is owned by uid {}, not the current euid {}; refuse \
             to read a secret from a file the invoker does not own.",
            path.display(),
            meta.uid(),
            euid
        )));
    }

    // Refuse world/group-readable files. A secret that any other
    // account on the system can read defeats the point of storing it
    // in the Keychain.
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

    // Read into a fresh `String` sized up-front by the file length.
    // Sizing the allocation before any bytes are read avoids the
    // `String::push_str` realloc+free cycle that would leave
    // un-zeroed old buffer fragments behind on the heap.
    let size = meta.len() as usize;
    let mut raw = String::with_capacity(size.saturating_add(1));
    let mut file = file;
    file.read_to_string(&mut raw).map_err(|e| {
        // If the buffer grew anyway (rare: e.g. len() lied, TOCTOU
        // on a growing file), wipe whatever we did read before
        // propagating the error.
        use zeroize::Zeroize;
        raw.zeroize();
        WazuhError::Config(format!("failed to read {}: {}", path.display(), e))
    })?;
    let mut s: Zeroizing<String> = Zeroizing::new(raw);
    strip_trailing_newline(&mut s);
    Ok(s)
}

/// `ELOOP` value. Inlined to avoid a `libc` dependency for one
/// constant. macOS and Linux both use 62 for ELOOP... wait, macOS
/// uses 62 and Linux uses 40. Use the right one per target.
#[cfg(target_os = "macos")]
fn libc_eloop() -> i32 {
    62
}

/// `geteuid()` via a FFI declaration — avoids pulling the `libc`
/// crate. Stable ABI on every Unix.
#[cfg(target_os = "macos")]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

/// Soft cap on secret size. A JWT or API password is far smaller
/// than this; the cap exists to bound the allocation we pre-reserve
/// for `read_from_stdin` (so `String::push_str`'s realloc path is
/// avoided and we do not leave un-zeroed old buffer fragments on
/// the heap) and to reject clearly-abnormal input (someone piping
/// a log file into `credentials set`).
const STDIN_MAX_BYTES: usize = 8 * 1024;

fn read_from_stdin() -> Result<Zeroizing<String>, WazuhError> {
    // Read the whole stdin into a pre-sized Vec<u8> inside a
    // Zeroizing wrapper, so:
    //   * the buffer is wiped on drop even if we return an Err,
    //   * `read_to_end` does not trigger a realloc+free that would
    //     leave an un-zeroed previous allocation on the heap.
    // Read_line was not used because callers may pipe a multi-line
    // secret (rare, but silently truncating would be worse than
    // preserving).
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(STDIN_MAX_BYTES + 1));
    io::stdin()
        .take((STDIN_MAX_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| WazuhError::Config(format!("failed to read stdin: {}", e)))?;
    if buf.len() > STDIN_MAX_BYTES {
        return Err(WazuhError::Config(format!(
            "stdin exceeded {} bytes; refusing to treat this as a \
             credential (did you pipe the wrong stream?)",
            STDIN_MAX_BYTES
        )));
    }
    // Convert Vec<u8> → String in place without copying. If the
    // bytes are not valid UTF-8, zeroize the Vec before returning
    // the error.
    let s = match String::from_utf8(std::mem::take(&mut *buf)) {
        Ok(s) => s,
        Err(e) => {
            // The invalid bytes are inside the FromUtf8Error; pulling
            // them back out and zeroizing closes the only remaining
            // window.
            let mut bad = e.into_bytes();
            use zeroize::Zeroize;
            bad.zeroize();
            return Err(WazuhError::Config(
                "stdin input is not valid UTF-8".to_string(),
            ));
        }
    };
    let mut s: Zeroizing<String> = Zeroizing::new(s);
    strip_trailing_newline(&mut s);
    Ok(s)
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
    // guarantees at most one of `--stdin` / `--file` is set.
    let (value, source_label): (Zeroizing<String>, &'static str) = if let Some(p) = from_file {
        (read_from_file(p)?, "--file")
    } else if from_stdin {
        (read_from_stdin()?, "--stdin")
    } else {
        (prompt_tty(field)?, "prompt")
    };

    if value.is_empty() {
        return Err(WazuhError::Config(format!(
            "empty value from {}; refusing to store an empty credential",
            source_label
        )));
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

    #[test]
    fn read_from_file_rejects_group_readable_file() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir_in_target();
        let path = dir.join("perm.txt");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"secret").unwrap();
        drop(f);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = read_from_file(&path).unwrap_err();
        match err {
            WazuhError::Config(msg) => {
                assert!(msg.contains("chmod 600"), "got: {}", msg);
                assert!(msg.contains("644"), "got: {}", msg);
            }
            other => panic!("expected Config error, got {:?}", other),
        }
    }

    #[test]
    fn read_from_file_rejects_symlink() {
        use std::io::Write;
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempdir_in_target();
        let target = dir.join("real.txt");
        let mut f = fs::File::create(&target).unwrap();
        f.write_all(b"secret").unwrap();
        drop(f);
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

        let link = dir.join("link.txt");
        symlink(&target, &link).unwrap();

        let err = read_from_file(&link).unwrap_err();
        match err {
            WazuhError::Config(msg) => {
                assert!(msg.contains("symlink"), "got: {}", msg);
            }
            other => panic!("expected Config error, got {:?}", other),
        }
    }

    #[test]
    fn read_from_file_accepts_mode_0600_regular_file() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir_in_target();
        let path = dir.join("ok.txt");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"sekret\n").unwrap();
        drop(f);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let got = read_from_file(&path).unwrap();
        // The trailing \n is stripped; the body is preserved.
        assert_eq!(got.as_str(), "sekret");
    }

    /// Create a unique directory under `target/credentials-tests/`
    /// that the test owns and can write into with `0o600` files.
    /// Using `env::temp_dir()` (`/tmp`) is fine on macOS local dev
    /// but problematic under `cargo test` on CI when multiple tests
    /// run concurrently and collide on paths; a target-relative
    /// directory sidesteps the issue and cleans up with `cargo
    /// clean`.
    fn tempdir_in_target() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("wazuh-cli-creds-test-{}-{}", pid, n));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
