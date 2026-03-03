use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Agent management")]
pub struct AgentCommand {
    #[command(subcommand)]
    pub action: AgentAction,
}

#[derive(Subcommand)]
pub enum AgentAction {
    /// List agents
    List {
        /// Filter by agent status (active, disconnected, pending, never_connected)
        #[arg(long)]
        status: Option<String>,

        /// Filter by group name
        #[arg(long)]
        group: Option<String>,

        /// Maximum number of items to return
        #[arg(long)]
        limit: Option<u32>,

        /// First item to return
        #[arg(long)]
        offset: Option<u32>,
    },

    /// Get agent details
    Get {
        /// Agent ID
        agent_id: String,
    },

    /// Create a new agent
    Create {
        /// Agent name
        #[arg(long)]
        name: String,

        /// Agent IP address
        #[arg(long)]
        ip: String,
    },

    /// Delete one or more agents
    Delete {
        /// Agent IDs
        #[arg(required = true)]
        agent_ids: Vec<String>,
    },

    /// Restart one or more agents
    Restart {
        /// Agent IDs
        #[arg(required = true)]
        agent_ids: Vec<String>,
    },

    /// Restart all agents
    #[command(name = "restart-all")]
    RestartAll,

    /// Upgrade one or more agents
    Upgrade {
        /// Agent IDs
        #[arg(required = true)]
        agent_ids: Vec<String>,
    },

    /// Get agent key
    Key {
        /// Agent ID
        agent_id: String,
    },

    /// List groups of an agent
    Groups {
        /// Agent ID
        agent_id: String,
    },

    /// Add agent to a group
    #[command(name = "add-group")]
    AddGroup {
        /// Agent ID
        agent_id: String,

        /// Group ID
        group_id: String,
    },

    /// Remove agent from a group
    #[command(name = "remove-group")]
    RemoveGroup {
        /// Agent ID
        agent_id: String,

        /// Group ID (if omitted, remove from all groups)
        group_id: Option<String>,
    },

    /// List outdated agents
    Outdated,

    /// Get agent status summary
    #[command(name = "summary-status")]
    SummaryStatus,

    /// Get agent OS summary
    #[command(name = "summary-os")]
    SummaryOs,
}
