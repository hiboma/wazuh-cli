use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "CDB list management")]
pub struct ListCommand {
    #[command(subcommand)]
    pub action: ListAction,
}

#[derive(Subcommand)]
pub enum ListAction {
    /// Get CDB lists
    Get {
        /// Maximum number of items to return
        #[arg(long)]
        limit: Option<u32>,
    },

    /// List CDB list files
    Files,

    /// Get a CDB list file
    File {
        /// CDB list file name
        filename: String,
    },

    /// Update a CDB list file
    Update {
        /// CDB list file name
        filename: String,

        /// Path to the local file
        #[arg(long)]
        file: String,
    },

    /// Delete a CDB list file
    Delete {
        /// CDB list file name
        filename: String,
    },
}

#[derive(Args)]
#[command(about = "Log analysis testing")]
pub struct LogtestCommand {
    #[command(subcommand)]
    pub action: LogtestAction,
}

#[derive(Subcommand)]
pub enum LogtestAction {
    /// Run a log analysis test
    Run {
        /// Log entry to test
        #[arg(long)]
        log: String,

        /// Read a session token from stdin for multi-step testing
        #[arg(long, conflicts_with_all = ["session_file", "session_prompt"])]
        session_stdin: bool,
        /// Read a session token from an owner-only regular file
        #[arg(long, conflicts_with = "session_prompt")]
        session_file: Option<std::path::PathBuf>,
        /// Read a session token using a hidden prompt
        #[arg(long)]
        session_prompt: bool,
        #[arg(long = "session", hide = true, allow_hyphen_values = true,
            value_parser = crate::secret::RemovedSecretOption {
                flag: "--session",
                guidance: "Use --session-stdin / --session-file / --session-prompt.",
            })]
        removed_session: Option<String>,
    },

    /// Delete a logtest session
    #[command(name = "delete-session")]
    DeleteSession {
        /// Read the session token from stdin instead of a hidden prompt
        #[arg(long, conflicts_with = "token_file")]
        token_stdin: bool,
        /// Read the session token from an owner-only regular file
        #[arg(long)]
        token_file: Option<std::path::PathBuf>,
        #[arg(hide = true, allow_hyphen_values = true,
            value_parser = crate::secret::RemovedSecretOption {
                flag: "positional token",
                guidance: "Use --token-stdin / --token-file, or omit to be prompted.",
            })]
        removed_token: Option<String>,
    },
}

#[derive(Args)]
#[command(about = "Task management")]
pub struct TaskCommand {
    #[command(subcommand)]
    pub action: TaskAction,
}

#[derive(Subcommand)]
pub enum TaskAction {
    /// Get task status
    Status {
        /// Maximum number of items to return
        #[arg(long)]
        limit: Option<u32>,
    },
}

#[derive(Args)]
#[command(about = "Event ingestion")]
pub struct EventCommand {
    #[command(subcommand)]
    pub action: EventAction,
}

#[derive(Subcommand)]
pub enum EventAction {
    /// Send events from a file
    Send {
        /// Path to the event file
        #[arg(long)]
        file: String,
    },
}

#[derive(Args)]
#[command(about = "Active response management")]
pub struct ActiveResponseCommand {
    #[command(subcommand)]
    pub action: ActiveResponseAction,
}

#[derive(Subcommand)]
pub enum ActiveResponseAction {
    /// Run an active response command
    Run {
        /// Target agent ID
        #[arg(long)]
        agent: String,

        /// Command to execute
        #[arg(long)]
        command: String,
    },
}

#[derive(Args)]
#[command(about = "Agent overview")]
pub struct OverviewCommand {
    #[command(subcommand)]
    pub action: OverviewAction,
}

#[derive(Subcommand)]
pub enum OverviewAction {
    /// Get agent overview
    Agents,
}
