use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum, ValueHint};

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
    /// Reads the value from `--file <PATH>`, `--stdin`, or an
    /// interactive hidden-input prompt (in that order of priority).
    /// Only the final line terminator (`\r`, `\n`, or `\r\n`) is
    /// stripped from the input — other trailing whitespace, and any
    /// interior newlines, are preserved byte-for-byte. The Keychain
    /// entry lands under service `dev.wazuh-cli`, account
    /// `api_password` (underscore on the Keychain side,
    /// `api-password` as the CLI arg value).
    Set {
        /// Which credential to store.
        field: CredentialField,

        /// Read the value from stdin instead of prompting. Only the
        /// final line terminator is stripped.
        #[arg(long, conflicts_with = "file")]
        stdin: bool,

        /// Read the value from a regular file at the given path.
        /// The file must:
        ///   (a) not be a symlink (opened with `O_NOFOLLOW`),
        ///   (b) be owned by the current user,
        ///   (c) have mode clear of group/world bits (`0o077`).
        /// Useful for 1Password / sops integration:
        ///
        ///   op read 'op://vault/item/password' > /tmp/s
        ///   chmod 600 /tmp/s
        ///   wazuh-cli credentials set api-password --file /tmp/s
        ///
        /// Only the final line terminator is stripped.
        #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath, conflicts_with = "stdin")]
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
