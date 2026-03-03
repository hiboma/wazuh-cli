use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Security configuration assessment")]
pub struct ScaCommand {
    #[command(subcommand)]
    pub action: ScaAction,
}

#[derive(Subcommand)]
pub enum ScaAction {
    /// List SCA policies for an agent
    List {
        /// Agent ID
        agent_id: String,
    },

    /// Get SCA checks for an agent and policy
    Checks {
        /// Agent ID
        agent_id: String,

        /// Policy ID
        policy_id: String,
    },
}
