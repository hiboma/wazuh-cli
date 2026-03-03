use clap::{Args, Subcommand};

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

    /// Create a new user
    Create {
        /// Username
        #[arg(long)]
        username: String,

        /// Password
        #[arg(long)]
        password: String,
    },

    /// Update a user
    Update {
        /// User ID
        user_id: String,

        /// New password
        #[arg(long)]
        password: Option<String>,
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
