use clap::{Args, Subcommand, ValueEnum};

/// Manage credentials stored in the macOS Keychain.
///
/// All entries are scoped under service `dev.wazuh-cli`. There is
/// intentionally no `get` subcommand: the value never has to leave the
/// Keychain for any legitimate workflow, and exposing one would invite
/// leakage into shell history, terminal scrollback, and AI-agent
/// transcripts.
#[derive(Args)]
pub struct CredentialsCommand {
    #[command(subcommand)]
    pub action: CredentialsAction,
}

#[derive(Subcommand)]
pub enum CredentialsAction {
    /// Store a credential in the Keychain (prompted via hidden input,
    /// or read from stdin with `--stdin`).
    Set {
        /// Which credential to store.
        field: CredentialField,

        /// Read the value from stdin instead of prompting.
        #[arg(long)]
        stdin: bool,
    },
    /// Delete a credential from the Keychain.
    Delete {
        /// Which credential to delete.
        field: CredentialField,
    },
    /// Show which credentials are currently stored (value is never
    /// printed, only presence).
    Status,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CredentialField {
    /// API password (`WAZUH_API_PASSWORD`).
    #[value(name = "api-password")]
    ApiPassword,
}

impl CredentialField {
    pub fn key(self) -> &'static str {
        match self {
            CredentialField::ApiPassword => crate::config::credential_store::KEY_API_PASSWORD,
        }
    }
}
