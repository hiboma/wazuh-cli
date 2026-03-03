use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "File integrity monitoring")]
pub struct SyscheckCommand {
    #[command(subcommand)]
    pub action: SyscheckAction,
}

#[derive(Subcommand)]
pub enum SyscheckAction {
    /// Get syscheck results for an agent
    Get {
        /// Agent ID
        agent_id: String,

        /// Search term
        #[arg(long)]
        search: Option<String>,
    },

    /// Get last scan information for an agent
    #[command(name = "last-scan")]
    LastScan {
        /// Agent ID
        agent_id: String,
    },

    /// Run syscheck on agents
    Run {
        /// Agent IDs (if omitted, run on all agents)
        agent_ids: Vec<String>,
    },

    /// Clear syscheck results for agents
    Clear {
        /// Agent IDs (if omitted, clear all agents)
        agent_ids: Vec<String>,
    },
}
