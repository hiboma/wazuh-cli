use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "System inventory")]
pub struct SyscollectorCommand {
    #[command(subcommand)]
    pub action: SyscollectorAction,
}

#[derive(Subcommand)]
pub enum SyscollectorAction {
    /// Get hardware information
    Hardware {
        /// Agent ID
        agent_id: String,
    },

    /// Get OS information
    Os {
        /// Agent ID
        agent_id: String,
    },

    /// List installed packages
    Packages {
        /// Agent ID
        agent_id: String,
    },

    /// List running processes
    Processes {
        /// Agent ID
        agent_id: String,
    },

    /// List open ports
    Ports {
        /// Agent ID
        agent_id: String,
    },

    /// List network addresses
    Netaddr {
        /// Agent ID
        agent_id: String,
    },

    /// List network interfaces
    Netiface {
        /// Agent ID
        agent_id: String,
    },

    /// List network protocols
    Netproto {
        /// Agent ID
        agent_id: String,
    },

    /// List hotfixes
    Hotfixes {
        /// Agent ID
        agent_id: String,
    },
}
