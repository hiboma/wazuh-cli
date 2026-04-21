use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

/// Manage credentials stored in the macOS Keychain.
///
/// All entries are scoped under service `dev.wazuh-cli`. There is
/// intentionally no `get` subcommand: the value never has to leave
/// the Keychain for any legitimate workflow, and exposing one would
/// invite leakage into shell history, terminal scrollback, and
/// AI-agent transcripts.
///
/// Note: the global options (`--api-url`, `--api-password`, etc.)
/// are inherited from the top-level `Cli` struct because clap
/// propagates `global = true` unconditionally. They have no effect
/// when running `credentials` — use `--file` / `--stdin` instead of
/// `--api-password`, and ignore `--api-url`.
#[derive(Args)]
pub struct CredentialsCommand {
    #[command(subcommand)]
    pub action: CredentialsAction,
}

#[derive(Subcommand)]
pub enum CredentialsAction {
    /// Store a credential in the Keychain.
    ///
    /// Reads the value from (in priority order): `--file <PATH>`,
    /// `--stdin`, or an interactive hidden-input prompt.
    Set {
        /// Which credential to store.
        field: CredentialField,

        /// Read the value from stdin instead of prompting. Trailing
        /// `\r` / `\n` are stripped; other trailing characters
        /// (including plain spaces) are preserved byte-for-byte so a
        /// password with a real trailing space is not silently
        /// mangled.
        #[arg(long, conflicts_with = "file")]
        stdin: bool,

        /// Read the value from a 0o600 file at the given path. Useful
        /// for 1Password / sops integration:
        ///   `op read 'op://vault/item/password' > /tmp/s; \
        ///    wazuh-cli credentials set api-password --file /tmp/s`.
        /// Trailing `\r` / `\n` are stripped; other trailing bytes
        /// are preserved.
        #[arg(long, value_name = "PATH", conflicts_with = "stdin")]
        file: Option<PathBuf>,
    },
    /// Delete a credential from the Keychain.
    Delete {
        /// Which credential to delete.
        field: CredentialField,
    },
    /// Show which credentials are currently stored (value is never
    /// printed, only presence).
    Status {
        /// Emit a machine-readable JSON document instead of the
        /// human-readable table. Errors are still reported on stderr.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CredentialField {
    /// API password (`WAZUH_API_PASSWORD`).
    #[value(name = "api-password")]
    ApiPassword,
}

impl CredentialField {
    /// The key used as the `account` in the Keychain entry. Underscores
    /// rather than hyphens for wire compatibility with the
    /// service+account identifier convention.
    pub fn key(self) -> &'static str {
        match self {
            CredentialField::ApiPassword => crate::config::credential_store::KEY_API_PASSWORD,
        }
    }

    /// The hyphen-separated name shown to users (matches the CLI arg
    /// value). Use this in output so CLI arg and display string agree.
    pub fn display(self) -> &'static str {
        match self {
            CredentialField::ApiPassword => "api-password",
        }
    }
}
