use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "Experimental cross-agent APIs")]
pub struct ExperimentalCommand {
    #[command(subcommand)]
    pub action: ExperimentalAction,
}

#[derive(Subcommand)]
pub enum ExperimentalAction {
    /// Clear stored rootcheck results
    Rootcheck(ClearCommand),
    /// Clear stored file integrity monitoring results
    Syscheck(ClearCommand),
    /// Query CIS-CAT results across agents
    Ciscat(CiscatCommand),
    /// Query system inventory across agents
    Syscollector(InventoryCommand),
}

#[derive(Args)]
pub struct ClearCommand {
    #[command(subcommand)]
    pub action: ClearAction,
}

#[derive(Subcommand)]
pub enum ClearAction {
    /// Delete stored scan results for the specified agents (use 'all' for all agents)
    Clear {
        #[arg(required = true)]
        agent_ids: Vec<String>,
        #[command(flatten)]
        request: RequestOptions,
    },
}

#[derive(Args)]
pub struct CiscatCommand {
    #[command(subcommand)]
    pub action: CiscatAction,
}

#[derive(Subcommand)]
pub enum CiscatAction {
    /// List CIS-CAT results
    Results(ListOptions),
}

#[derive(Args)]
pub struct InventoryCommand {
    #[command(subcommand)]
    pub action: InventoryAction,
}

#[derive(Subcommand)]
pub enum InventoryAction {
    /// Get hardware information across agents
    Hardware(ListOptions),
    /// Get OS information across agents
    Os(ListOptions),
    /// List installed packages across agents
    Packages(ListOptions),
    /// List running processes across agents
    Processes(ListOptions),
    /// List open ports across agents
    Ports(ListOptions),
    /// List network addresses across agents
    Netaddr(ListOptions),
    /// List network interfaces across agents
    Netiface(ListOptions),
    /// List network protocols across agents
    Netproto(ListOptions),
    /// List hotfixes across agents
    Hotfixes(ListOptions),
}

#[derive(Args, Default)]
pub struct RequestOptions {
    /// Ask the API to format its response
    #[arg(long)]
    pub pretty: bool,
    /// Wait for distributed API requests to complete
    #[arg(long)]
    pub wait_for_complete: bool,
}

#[derive(Args, Default)]
pub struct ListOptions {
    /// Comma-separated agent IDs; omit to query all agents
    #[arg(long)]
    pub agents_list: Option<String>,
    /// Search term
    #[arg(long)]
    pub search: Option<String>,
    /// Comma-separated fields to return
    #[arg(long)]
    pub select: Option<String>,
    /// Sort fields; prefix with '-' for descending order
    #[arg(long, allow_hyphen_values = true, value_parser = super::agent::parse_sort_value)]
    pub sort: Option<String>,
    /// Maximum number of items; disables auto-pagination
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    pub limit: Option<u32>,
    /// First item to return; disables auto-pagination
    #[arg(long)]
    pub offset: Option<u32>,
    /// Endpoint-specific API filter, e.g. name=openssl or ram.free=1024 (repeatable)
    #[arg(long, value_name = "PARAMETER=VALUE", value_parser = parse_filter)]
    pub filter: Vec<(String, String)>,
    #[command(flatten)]
    pub request: RequestOptions,
}

fn parse_filter(value: &str) -> Result<(String, String), String> {
    match value.split_once('=') {
        Some((key, value)) if !key.is_empty() && !value.is_empty() => {
            Ok((key.to_string(), value.to_string()))
        }
        _ => Err("expected a non-empty PARAMETER=VALUE".to_string()),
    }
}
