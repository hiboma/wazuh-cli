use std::path::PathBuf;

use clap::{Args, Subcommand, ValueHint};

use crate::secret::RemovedSecretOption;

#[derive(Args)]
#[command(about = "Security management")]
pub struct SecurityCommand {
    #[command(subcommand)]
    pub action: SecurityAction,
}

#[derive(Subcommand)]
pub enum SecurityAction {
    /// Authenticate and get a JWT token
    Login,

    /// Revoke the current JWT token
    Logout,

    /// User management
    User(SecurityUserCommand),

    /// Role management
    Role(SecurityRoleCommand),

    /// Policy management
    Policy(SecurityPolicyCommand),

    /// Security rule management
    Rule(SecurityRuleCommand),

    /// Get security configuration
    Config,

    /// Update security configuration
    #[command(name = "update-config")]
    UpdateConfig,

    /// Reset security configuration
    #[command(name = "reset-config")]
    ResetConfig,
}

#[derive(Args)]
pub struct SecurityUserCommand {
    #[command(subcommand)]
    pub action: SecurityUserAction,
}

#[derive(Subcommand)]
pub enum SecurityUserAction {
    /// List users
    List,

    /// Get current user information
    #[command(name = "get-me")]
    GetMe,

    /// Create a new user. The password is read from a hidden prompt,
    /// --password-stdin, or --password-file, never from an argument.
    Create {
        /// Username
        #[arg(long)]
        username: String,

        #[command(flatten)]
        password: PasswordInput,
    },

    /// Change a user's password. The password is read from a hidden
    /// prompt, --password-stdin, or --password-file, never from an
    /// argument.
    Update {
        /// User ID
        user_id: String,

        #[command(flatten)]
        password: PasswordInput,
    },

    /// Delete one or more users
    Delete {
        /// User IDs
        #[arg(required = true)]
        user_ids: Vec<String>,
    },
}

#[derive(Args)]
pub struct SecurityRoleCommand {
    #[command(subcommand)]
    pub action: SecurityRoleAction,
}

#[derive(Subcommand)]
pub enum SecurityRoleAction {
    /// List roles
    List,

    /// Create a new role
    Create {
        /// Role name
        #[arg(long)]
        name: String,
    },

    /// Update a role
    Update {
        /// Role ID
        role_id: String,
    },

    /// Delete one or more roles
    Delete {
        /// Role IDs
        #[arg(required = true)]
        role_ids: Vec<String>,
    },
}

#[derive(Args)]
pub struct SecurityPolicyCommand {
    #[command(subcommand)]
    pub action: SecurityPolicyAction,
}

#[derive(Subcommand)]
pub enum SecurityPolicyAction {
    /// List policies
    List,

    /// Create a new policy
    Create {
        /// Policy name
        #[arg(long)]
        name: String,
    },

    /// Update a policy
    Update {
        /// Policy ID
        policy_id: String,
    },

    /// Delete one or more policies
    Delete {
        /// Policy IDs
        #[arg(required = true)]
        policy_ids: Vec<String>,
    },
}

#[derive(Args)]
pub struct SecurityRuleCommand {
    #[command(subcommand)]
    pub action: SecurityRuleAction,
}

#[derive(Subcommand)]
pub enum SecurityRuleAction {
    /// List security rules
    List,

    /// Create a new security rule
    Create,

    /// Update a security rule
    Update {
        /// Rule ID
        rule_id: String,
    },

    /// Delete one or more security rules
    Delete {
        /// Rule IDs
        #[arg(required = true)]
        rule_ids: Vec<String>,
    },
}

/// How to supply a user password. Without either flag the password is
/// prompted for on the terminal (input hidden, asked twice).
#[derive(Args)]
pub struct PasswordInput {
    /// Read the password from stdin instead of prompting. A single
    /// trailing newline is stripped.
    ///
    /// Example: op read 'op://vault/wazuh/alice' | wazuh-cli security user create --username alice --password-stdin
    #[arg(long, conflicts_with = "password_file")]
    pub password_stdin: bool,

    /// Read the password from a file instead of prompting. The file must
    /// be a regular file owned by you with no group/other permissions
    /// (chmod 600). A single trailing newline is stripped.
    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    pub password_file: Option<PathBuf>,

    /// Removed. Kept hidden only to explain the replacement.
    #[arg(
        long = "password",
        hide = true,
        // Accept `--password -abc` as a value so clap's "unexpected
        // argument" error never echoes part of the secret.
        allow_hyphen_values = true,
        value_name = "VALUE",
        value_parser = RemovedSecretOption {
            flag: "--password",
            guidance: "Omit it to be prompted, or use --password-stdin / --password-file.",
        }
    )]
    pub removed_password: Option<String>,
}
