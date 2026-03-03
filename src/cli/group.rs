use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Group management")]
pub struct GroupCommand {
    #[command(subcommand)]
    pub action: GroupAction,
}

#[derive(Subcommand)]
pub enum GroupAction {
    /// List groups
    List {
        /// Maximum number of items to return
        #[arg(long)]
        limit: Option<u32>,

        /// First item to return
        #[arg(long)]
        offset: Option<u32>,
    },

    /// Create a new group
    Create {
        /// Group ID
        group_id: String,
    },

    /// Delete one or more groups
    Delete {
        /// Group IDs
        #[arg(required = true)]
        group_ids: Vec<String>,
    },

    /// List agents in a group
    Agents {
        /// Group ID
        group_id: String,
    },

    /// Get group configuration
    Config {
        /// Group ID
        group_id: String,
    },

    /// Update group configuration
    #[command(name = "update-config")]
    UpdateConfig {
        /// Group ID
        group_id: String,

        /// Path to configuration file
        #[arg(long)]
        file: String,
    },

    /// List group files
    Files {
        /// Group ID
        group_id: String,
    },

    /// Get a group file
    File {
        /// Group ID
        group_id: String,

        /// File name
        filename: String,
    },
}
