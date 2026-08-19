use clap::{Args, Subcommand};

/// Validates a `--sort` value.
///
/// `--sort` sets `allow_hyphen_values` so that a descending sort such as
/// `--sort -name` parses instead of being rejected as an unknown flag. That
/// also stops clap from rejecting a following option when the value is
/// omitted, so `agent list --sort --insecure` would otherwise consume
/// `--insecure` as the sort value and silently drop the flag. A Wazuh sort
/// field never begins with `--`, so rejecting that prefix restores the error
/// without giving up the `-name` form.
fn parse_sort_value(value: &str) -> Result<String, String> {
    if value.starts_with("--") {
        return Err(format!(
            "invalid sort field '{value}' (a value starting with '--' looks like a command-line \
             option; use '-field' for descending order)"
        ));
    }
    Ok(value.to_string())
}

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

        /// Search term (partial match against name, ip and other fields)
        #[arg(long)]
        search: Option<String>,

        /// API query filter (e.g. "name=compute-1", "ip=10.0.0.1;status=active")
        #[arg(long)]
        query: Option<String>,

        /// Comma-separated fields to return (e.g. "id,name,ip,status")
        #[arg(long)]
        select: Option<String>,

        /// Comma-separated fields to sort by, prefix with '-' for descending (e.g. "-name")
        #[arg(long, allow_hyphen_values = true, value_parser = parse_sort_value)]
        sort: Option<String>,

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

    /// [Extended] Get all SCA policies and their checks for an agent
    ///
    /// Fetches all SCA policies via /sca/{agent_id}, then retrieves checks
    /// for each policy via /sca/{agent_id}/checks/{policy_id}.
    /// Returns a unified response with checks embedded in each policy.
    Sca {
        /// Agent ID
        agent_id: String,
    },
}
