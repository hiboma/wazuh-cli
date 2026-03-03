use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Cluster management")]
pub struct ClusterCommand {
    #[command(subcommand)]
    pub action: ClusterAction,
}

#[derive(Subcommand)]
pub enum ClusterAction {
    /// Get cluster status
    Status,

    /// Get cluster health
    Health,

    /// List cluster nodes
    Nodes,

    /// Get local node information
    #[command(name = "local-info")]
    LocalInfo,

    /// Get local node configuration
    #[command(name = "local-config")]
    LocalConfig,

    /// Get information of a specific node
    #[command(name = "node-info")]
    NodeInfo {
        /// Node ID
        node_id: String,
    },

    /// Get configuration of a specific node
    #[command(name = "node-config")]
    NodeConfig {
        /// Node ID
        node_id: String,
    },

    /// Get statistics of a specific node
    #[command(name = "node-stats")]
    NodeStats {
        /// Node ID
        node_id: String,
    },

    /// Get logs of a specific node
    #[command(name = "node-logs")]
    NodeLogs {
        /// Node ID
        node_id: String,

        /// Show log summary
        #[arg(long)]
        summary: bool,
    },

    /// Restart the cluster
    Restart,

    /// Get ruleset synchronization status
    #[command(name = "ruleset-sync")]
    RulesetSync,

    /// Validate cluster configuration
    #[command(name = "validate-config")]
    ValidateConfig,
}
