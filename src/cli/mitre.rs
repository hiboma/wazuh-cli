use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "MITRE ATT&CK information")]
pub struct MitreCommand {
    #[command(subcommand)]
    pub action: MitreAction,
}

#[derive(Subcommand)]
pub enum MitreAction {
    /// List MITRE groups
    Groups,

    /// Get MITRE metadata
    Metadata,

    /// List MITRE mitigations
    Mitigations,

    /// List MITRE references
    References,

    /// List MITRE software
    Software,

    /// List MITRE tactics
    Tactics,

    /// List MITRE techniques
    Techniques,
}
