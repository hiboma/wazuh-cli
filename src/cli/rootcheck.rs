use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Rootcheck management")]
pub struct RootcheckCommand {
    #[command(subcommand)]
    pub action: RootcheckAction,
}

#[derive(Subcommand)]
pub enum RootcheckAction {
    /// Get rootcheck results for an agent
    Get {
        /// Agent ID
        agent_id: String,
    },

    /// Get last scan information for an agent
    #[command(name = "last-scan")]
    LastScan {
        /// Agent ID
        agent_id: String,
    },

    /// Run rootcheck on agents
    Run {
        /// Agent IDs (if omitted, run on all agents)
        agent_ids: Vec<String>,
    },

    /// Clear rootcheck results for an agent
    Clear {
        /// Agent ID
        agent_id: String,
    },
}
