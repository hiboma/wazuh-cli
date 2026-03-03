use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Manager management")]
pub struct ManagerCommand {
    #[command(subcommand)]
    pub action: ManagerAction,
}

#[derive(Subcommand)]
pub enum ManagerAction {
    /// Get manager status
    Status,

    /// Get manager information
    Info,

    /// Get manager configuration
    Config,

    /// Update manager configuration
    #[command(name = "update-config")]
    UpdateConfig {
        /// Path to configuration file
        #[arg(long)]
        file: String,
    },

    /// Get manager statistics
    Stats {
        /// Show hourly statistics
        #[arg(long)]
        hourly: bool,

        /// Show weekly statistics
        #[arg(long)]
        weekly: bool,
    },

    /// Get manager logs
    Logs {
        /// Show log summary
        #[arg(long)]
        summary: bool,
    },

    /// Restart manager
    Restart,

    /// Validate manager configuration
    #[command(name = "validate-config")]
    ValidateConfig,

    /// Get API configuration
    #[command(name = "api-config")]
    ApiConfig,

    /// Check for available updates
    #[command(name = "version-check")]
    VersionCheck,
}
