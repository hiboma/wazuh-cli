use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Rule management")]
pub struct RuleCommand {
    #[command(subcommand)]
    pub action: RuleAction,
}

#[derive(Subcommand)]
pub enum RuleAction {
    /// List rules
    List {
        /// Filter by group name
        #[arg(long)]
        group: Option<String>,

        /// Filter by rule level
        #[arg(long)]
        level: Option<u32>,

        /// Maximum number of items to return
        #[arg(long)]
        limit: Option<u32>,
    },

    /// List rule groups
    Groups,

    /// List rule files
    Files,

    /// Get a rule file
    File {
        /// Rule file name
        filename: String,
    },

    /// Update a rule file
    Update {
        /// Rule file name
        filename: String,

        /// Path to the local file
        #[arg(long)]
        file: String,
    },

    /// Delete a rule file
    Delete {
        /// Rule file name
        filename: String,
    },

    /// List rule requirements
    Requirements {
        /// Requirement type
        requirement: String,
    },
}
