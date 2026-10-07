//! Read secret material (passwords) without putting it on the command line.
//!
//! Values passed as command-line arguments are visible in `ps`, shell
//! history, auditd `EXECVE` records and EDR process events, and often end
//! up in a SIEM. Every command that accepts a secret therefore takes it
//! from one of the sources below instead of from an argument value:
//!
//!   * an interactive prompt on the controlling terminal (input hidden),
//!   * stdin (`--*-stdin`), for pipelines such as `op read ... | wazuh-cli ...`,
//!   * a file owned by the invoker with mode 0600 (`--*-file <PATH>`).

use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::Path;

use clap::builder::TypedValueParser;
use zeroize::Zeroizing;

use crate::error::WazuhError;

/// Where to read a secret from.
pub enum SecretSource<'a> {
    Prompt,
    Stdin,
    File(&'a Path),
}

impl<'a> SecretSource<'a> {
    /// Build a source from the `--*-stdin` / `--*-file` flag pair. clap's
    /// `conflicts_with` guarantees at most one of them is set.
    pub fn from_flags(stdin: bool, file: Option<&'a Path>) -> Self {
        if let Some(p) = file {
            SecretSource::File(p)
        } else if stdin {
            SecretSource::Stdin
        } else {
            SecretSource::Prompt
        }
    }

    fn label(&self) -> &'static str {
        match self {
            SecretSource::Prompt => "prompt",
            SecretSource::Stdin => "stdin",
            SecretSource::File(_) => "file",
        }
    }
}

/// Read a secret from `source` and reject an empty value.
///
/// `prompt` is shown on the terminal for `SecretSource::Prompt`. When
/// `confirm` is true the prompt asks twice and fails on a mismatch, which
/// is what a command that *sets* a password needs.
pub fn read_secret(
    source: SecretSource<'_>,
    prompt: &str,
    confirm: bool,
) -> Result<Zeroizing<String>, WazuhError> {
    let value = match source {
        SecretSource::Prompt => {
            let first = prompt_hidden(prompt)?;
            if confirm && !first.is_empty() {
                let second = prompt_hidden("Retype to confirm (input hidden): ")?;
                if *first != *second {
                    return Err(WazuhError::Config(
                        "the two entries do not match".to_string(),
                    ));
                }
            }
            first
        }
        SecretSource::Stdin => read_from_stdin()?,
        SecretSource::File(p) => read_from_file(p)?,
    };
    if value.is_empty() {
        return Err(WazuhError::Config(format!(
            "empty value from {}; refusing to use an empty secret",
            source.label()
        )));
    }
    Ok(value)
}

/// Prompt on the controlling terminal with echo disabled.
pub fn prompt_hidden(prompt: &str) -> Result<Zeroizing<String>, WazuhError> {
    let raw = rpassword::prompt_password(prompt).map_err(|e| {
        WazuhError::Config(format!(
            "failed to read from the terminal: {}. If no terminal is \
             available, pass the secret through the command's stdin or \
             file option instead (see --help).",
            e
        ))
    })?;
    Ok(Zeroizing::new(raw))
}

/// Strip a single trailing `\r`, `\n`, or `\r\n`, leaving any other
/// trailing whitespace intact. Full `String::trim()` would silently
/// eat a real trailing space in a password — unacceptable for secret
/// material. This matches what a terminal / editor would insert and
/// nothing more.
pub fn strip_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    } else if s.ends_with('\r') {
        s.pop();
    }
}

/// Soft cap on secret size. A JWT or API password is far smaller
/// than this; the cap exists to bound the allocation we pre-reserve
/// (so a realloc never leaves un-zeroed old buffer fragments on the
/// heap) and to reject clearly-abnormal input (someone piping a log
/// file into the command, or pointing the file option at one).
const SECRET_MAX_BYTES: usize = 8 * 1024;

pub fn read_from_stdin() -> Result<Zeroizing<String>, WazuhError> {
    // Text typed on a terminal is echoed and kept in scrollback. The
    // hidden prompt is the right tool for interactive input.
    if io::stdin().is_terminal() {
        return Err(WazuhError::Config(
            "stdin is a terminal, so the secret would be echoed. Pipe the \
             secret in, or omit the stdin option to get a hidden prompt."
                .to_string(),
        ));
    }
    read_capped(io::stdin(), "stdin")
}

/// Read at most `SECRET_MAX_BYTES` from `reader` into a buffer that is
/// wiped on drop, then convert it to a `String` in place.
fn read_capped(reader: impl Read, label: &str) -> Result<Zeroizing<String>, WazuhError> {
    // Read the whole input into a pre-sized Vec<u8> inside a
    // Zeroizing wrapper, so:
    //   * the buffer is wiped on drop even if we return an Err,
    //   * `read_to_end` does not trigger a realloc+free that would
    //     leave an un-zeroed previous allocation on the heap.
    // Read_line was not used because callers may pipe a multi-line
    // secret (rare, but silently truncating would be worse than
    // preserving).
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(SECRET_MAX_BYTES + 1));
    reader
        .take((SECRET_MAX_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| WazuhError::Config(format!("failed to read {}: {}", label, e)))?;
    if buf.len() > SECRET_MAX_BYTES {
        return Err(WazuhError::Config(format!(
            "{} exceeded {} bytes; refusing to treat this as a \
             secret (wrong stream or file?)",
            label, SECRET_MAX_BYTES
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
            return Err(WazuhError::Config(format!("{} is not valid UTF-8", label)));
        }
    };
    let mut s: Zeroizing<String> = Zeroizing::new(s);
    strip_trailing_newline(&mut s);
    Ok(s)
}

/// Read the secret from a regular file at `path`, refusing:
///   1. a symlink as the final path component,
///   2. any non-regular file (directory, FIFO, socket, device),
///   3. (Unix) files whose mode allows group or world access
///      (`0o077` bits clear required),
///   4. (Unix) files not owned by the current effective UID,
///   5. (Unix) files with more than one hard link: a link planted in an
///      attacker-controlled directory could point at an unrelated
///      0600 file of the invoker (e.g. an SSH key) and send its
///      content to the server as a password,
///   6. files larger than `SECRET_MAX_BYTES`.
///
/// On Windows, ownership and ACLs are not checked; only checks 1, 2
/// and 6 apply.
///
/// The symlink check uses `lstat` on the path; the remaining checks are
/// done on the already-opened file descriptor, and the descriptor's
/// device/inode must match the `lstat` result. This closes the TOCTOU
/// window in which an attacker with write access to a parent directory
/// could swap the path for a symlink or a different file between the
/// check and the read, without needing a platform-specific `O_NOFOLLOW`.
pub fn read_from_file(path: &Path) -> Result<Zeroizing<String>, WazuhError> {
    let lmeta = fs::symlink_metadata(path).map_err(|e| open_error(path, e))?;
    if lmeta.file_type().is_symlink() {
        return Err(WazuhError::Config(format!(
            "{} is a symlink; refusing to follow for secret \
             material. Pass the real path, or copy the secret \
             to a regular file.",
            path.display()
        )));
    }
    // Reject FIFOs and devices before `open`: opening a FIFO blocks
    // until a writer appears. The fstat check below still applies to
    // the inode actually opened.
    if !lmeta.is_file() {
        return Err(not_regular_file(path));
    }

    let file = open_no_follow(path).map_err(|e| open_error(path, e))?;

    // fstat the opened fd (not the path) so the checks apply to the
    // exact inode we are about to read.
    let meta = file
        .metadata()
        .map_err(|e| WazuhError::Config(format!("failed to stat {}: {}", path.display(), e)))?;

    if !meta.is_file() {
        return Err(not_regular_file(path));
    }

    #[cfg(unix)]
    check_unix_file(path, &lmeta, &meta)?;

    let label = path.display().to_string();
    read_capped(file, &label)
}

/// Open `path` for reading. On Windows, `FILE_FLAG_OPEN_REPARSE_POINT`
/// opens a symlink or junction itself instead of its target, so a link
/// swapped in after the `lstat` fails the `is_file()` check on the
/// handle. On Unix the dev/ino comparison in `check_unix_file` covers
/// the same race.
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path)
}

fn not_regular_file(path: &Path) -> WazuhError {
    WazuhError::Config(format!(
        "{} is not a regular file; refuse to read a secret from \
         a directory, FIFO, socket, or device.",
        path.display()
    ))
}

fn open_error(path: &Path, e: io::Error) -> WazuhError {
    if e.kind() == io::ErrorKind::NotFound {
        WazuhError::Config(format!(
            "{} does not exist. Double-check the path (shell ~ is \
             not expanded inside a quoted argument; pass an absolute \
             path or a path relative to the current working directory).",
            path.display()
        ))
    } else {
        WazuhError::Config(format!("failed to open {}: {}", path.display(), e))
    }
}

#[cfg(unix)]
fn check_unix_file(
    path: &Path,
    lmeta: &fs::Metadata,
    meta: &fs::Metadata,
) -> Result<(), WazuhError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if lmeta.dev() != meta.dev() || lmeta.ino() != meta.ino() {
        return Err(WazuhError::Config(format!(
            "{} changed while it was being opened; refusing to read it.",
            path.display()
        )));
    }

    if meta.nlink() > 1 {
        return Err(WazuhError::Config(format!(
            "{} has {} hard links; refuse to read a secret from a file \
             that may be a link to an unrelated file.",
            path.display(),
            meta.nlink()
        )));
    }

    // Ownership check: another user's file sitting in an
    // invoker-writable directory (e.g. /tmp) would otherwise satisfy
    // the mode check while the plaintext is attacker-controlled.
    //
    // SAFETY: `geteuid` is a direct syscall with no preconditions.
    let euid = unsafe { geteuid() };
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
    // account on the system can read defeats the point of keeping it
    // off the command line.
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
    Ok(())
}

/// `geteuid()` via a FFI declaration — avoids pulling the `libc`
/// crate. Stable ABI on every Unix.
#[cfg(unix)]
unsafe fn geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

/// clap value parser for an option that used to take a secret as its
/// value and has been removed. It always fails, and its error message
/// never echoes the value: clap's default "invalid value '<v>'" error
/// would print the secret to stderr, which may itself be logged.
#[derive(Clone)]
pub struct RemovedSecretOption {
    pub flag: &'static str,
    pub guidance: &'static str,
}

impl TypedValueParser for RemovedSecretOption {
    type Value = String;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        _value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        Err(clap::Error::raw(
            clap::error::ErrorKind::ValueValidation,
            format!(
                "{} was removed because a secret passed as a command-line \
                 argument is visible in `ps`, shell history, and audit/EDR \
                 logs. {}\n",
                self.flag, self.guidance
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
        // A real trailing space is part of the secret and must survive.
        let mut s = String::from("secret \n");
        strip_trailing_newline(&mut s);
        assert_eq!(s, "secret ");
    }

    #[test]
    fn strip_trailing_newline_only_removes_one_newline() {
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
    fn source_from_flags_prefers_file_then_stdin_then_prompt() {
        let p = PathBuf::from("/tmp/x");
        assert!(matches!(
            SecretSource::from_flags(false, Some(p.as_path())),
            SecretSource::File(_)
        ));
        assert!(matches!(
            SecretSource::from_flags(true, None),
            SecretSource::Stdin
        ));
        assert!(matches!(
            SecretSource::from_flags(false, None),
            SecretSource::Prompt
        ));
    }

    #[test]
    fn read_secret_rejects_empty_file() {
        let dir = tempdir_in_target();
        let path = dir.join("empty");
        write_secret_file(&path, "\n");
        let err = read_secret(SecretSource::File(&path), "unused", false).unwrap_err();
        assert!(err.to_string().contains("empty value"), "got: {}", err);
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn read_from_file_rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir_in_target();
        let path = dir.join("secret");
        fs::write(&path, "s3cret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let err = read_from_file(&path).unwrap_err();
        assert!(err.to_string().contains("mode 640"), "got: {}", err);
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn read_from_file_rejects_symlink() {
        let dir = tempdir_in_target();
        let target = dir.join("real");
        write_secret_file(&target, "s3cret\n");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = read_from_file(&link).unwrap_err();
        assert!(err.to_string().contains("symlink"), "got: {}", err);
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn read_from_file_rejects_directory() {
        let dir = tempdir_in_target();
        let err = read_from_file(&dir).unwrap_err();
        assert!(
            err.to_string().contains("not a regular file"),
            "got: {}",
            err
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn read_from_file_rejects_fifo_without_blocking() {
        let dir = tempdir_in_target();
        let path = dir.join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let err = read_from_file(&path).unwrap_err();
        assert!(
            err.to_string().contains("not a regular file"),
            "got: {}",
            err
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn read_from_file_rejects_hard_linked_file() {
        let dir = tempdir_in_target();
        let path = dir.join("secret");
        write_secret_file(&path, "s3cret\n");
        fs::hard_link(&path, dir.join("link")).unwrap();
        let err = read_from_file(&path).unwrap_err();
        assert!(err.to_string().contains("hard links"), "got: {}", err);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_from_file_rejects_oversized_file() {
        let dir = tempdir_in_target();
        let path = dir.join("big");
        write_secret_file(&path, &"a".repeat(SECRET_MAX_BYTES + 1));
        let err = read_from_file(&path).unwrap_err();
        assert!(err.to_string().contains("exceeded"), "got: {}", err);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_from_file_accepts_mode_0600_regular_file() {
        let dir = tempdir_in_target();
        let path = dir.join("secret");
        write_secret_file(&path, "s3cret \n");
        let v = read_from_file(&path).unwrap();
        assert_eq!(v.as_str(), "s3cret ");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_from_file_reports_missing_path() {
        let dir = tempdir_in_target();
        let err = read_from_file(&dir.join("missing")).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "got: {}", err);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn removed_secret_option_does_not_echo_value() {
        let parser = RemovedSecretOption {
            flag: "--password",
            guidance: "Use --password-stdin.",
        };
        let cmd = clap::Command::new("t");
        let err = parser
            .parse_ref(&cmd, None, std::ffi::OsStr::new("hunter2"))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--password was removed"), "got: {}", msg);
        assert!(!msg.contains("hunter2"), "secret leaked: {}", msg);
    }

    fn write_secret_file(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// `std::env::temp_dir()` is shared, so each test gets its own
    /// directory keyed by pid and a counter.
    fn tempdir_in_target() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("wazuh-cli-secret-test-{}-{}", pid, n));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
