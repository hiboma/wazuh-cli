use clap::{Args, Parser, Subcommand};

pub mod agent;
pub mod cluster;
pub mod decoder;
pub mod group;
pub mod manager;
pub mod mitre;
pub mod other;
pub mod rootcheck;
pub mod rule;
pub mod sca;
pub mod security;
pub mod syscheck;
pub mod syscollector;

#[derive(Parser)]
#[command(name = "wazuh-cli", about = "Wazuh REST API CLI")]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args)]
pub struct GlobalOpts {
    /// API URL
    #[arg(long, global = true)]
    pub api_url: Option<String>,

    /// API username
    #[arg(long, short = 'u', global = true)]
    pub api_user: Option<String>,

    /// API password
    #[arg(long, short = 'p', global = true)]
    pub api_password: Option<String>,

    /// CA certificate path
    #[arg(long, global = true)]
    pub ca_cert: Option<String>,

    /// Client certificate path
    #[arg(long, global = true)]
    pub client_cert: Option<String>,

    /// Client private key path
    #[arg(long, global = true)]
    pub client_key: Option<String>,

    /// Skip TLS verification
    #[arg(long, short = 'k', global = true)]
    pub insecure: bool,

    /// Output format (json)
    #[arg(long, short = 'o', global = true)]
    pub output: Option<String>,

    /// Output raw API response without extracting affected_items
    #[arg(long, global = true)]
    pub raw: bool,

    /// Suppress non-essential output
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Enable verbose output
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Show progress messages on stderr during auto-paging
    #[arg(long, global = true)]
    pub progress: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Agent management
    Agent(agent::AgentCommand),

    /// Group management
    Group(group::GroupCommand),

    /// Manager management
    Manager(manager::ManagerCommand),

    /// Security management
    Security(security::SecurityCommand),

    /// Rule management
    Rule(rule::RuleCommand),

    /// Decoder management
    Decoder(decoder::DecoderCommand),

    /// Cluster management
    Cluster(cluster::ClusterCommand),

    /// File integrity monitoring
    Syscheck(syscheck::SyscheckCommand),

    /// System inventory
    Syscollector(syscollector::SyscollectorCommand),

    /// Rootcheck management
    Rootcheck(rootcheck::RootcheckCommand),

    /// Security configuration assessment
    Sca(sca::ScaCommand),

    /// MITRE ATT&CK information
    Mitre(mitre::MitreCommand),

    /// CDB list management
    List(other::ListCommand),

    /// Log analysis testing
    Logtest(other::LogtestCommand),

    /// Task management
    Task(other::TaskCommand),

    /// Event ingestion
    Event(other::EventCommand),

    /// Active response management
    #[command(name = "active-response")]
    ActiveResponse(other::ActiveResponseCommand),

    /// Agent overview
    Overview(other::OverviewCommand),

    /// API information
    #[command(name = "api-info")]
    ApiInfo,
}
