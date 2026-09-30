use serde_json::Value;

use crate::cli::experimental::{
    CiscatAction, ClearAction, ClearCommand, ExperimentalAction, ExperimentalCommand,
    InventoryAction, ListOptions, RequestOptions,
};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: ExperimentalCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        ExperimentalAction::Rootcheck(cmd) => clear(client, "/experimental/rootcheck", cmd).await,
        ExperimentalAction::Syscheck(cmd) => clear(client, "/experimental/syscheck", cmd).await,
        ExperimentalAction::Ciscat(cmd) => match cmd.action {
            CiscatAction::Results(opts) => list(client, "/experimental/ciscat/results", opts).await,
        },
        ExperimentalAction::Syscollector(cmd) => {
            let (path, opts) = match cmd.action {
                InventoryAction::Hardware(opts) => ("/experimental/syscollector/hardware", opts),
                InventoryAction::Os(opts) => ("/experimental/syscollector/os", opts),
                InventoryAction::Packages(opts) => ("/experimental/syscollector/packages", opts),
                InventoryAction::Processes(opts) => ("/experimental/syscollector/processes", opts),
                InventoryAction::Ports(opts) => ("/experimental/syscollector/ports", opts),
                InventoryAction::Netaddr(opts) => ("/experimental/syscollector/netaddr", opts),
                InventoryAction::Netiface(opts) => ("/experimental/syscollector/netiface", opts),
                InventoryAction::Netproto(opts) => ("/experimental/syscollector/netproto", opts),
                InventoryAction::Hotfixes(opts) => ("/experimental/syscollector/hotfixes", opts),
            };
            list(client, path, opts).await
        }
    }
}

fn request_query(opts: &RequestOptions) -> Vec<(&'static str, String)> {
    let mut query = Vec::new();
    if opts.pretty {
        query.push(("pretty", "true".to_string()));
    }
    if opts.wait_for_complete {
        query.push(("wait_for_complete", "true".to_string()));
    }
    query
}

async fn clear(client: &WazuhClient, path: &str, cmd: ClearCommand) -> Result<Value, WazuhError> {
    let ClearAction::Clear { agent_ids, request } = cmd.action;
    let mut query = request_query(&request);
    query.push(("agents_list", agent_ids.join(",")));
    let query: Vec<_> = query
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    client.delete(path, &query).await
}

fn allowed_filters(path: &str) -> &'static [&'static str] {
    match path {
        "/experimental/ciscat/results" => &[
            "benchmark",
            "profile",
            "pass",
            "fail",
            "error",
            "notchecked",
            "unknown",
            "score",
        ],
        "/experimental/syscollector/hardware" => &[
            "ram.free",
            "ram.total",
            "cpu.cores",
            "cpu.mhz",
            "cpu.name",
            "board_serial",
        ],
        "/experimental/syscollector/netaddr" => &["proto", "address", "broadcast", "netmask"],
        "/experimental/syscollector/netiface" => &[
            "name",
            "adapter",
            "type",
            "state",
            "mtu",
            "tx.packets",
            "rx.packets",
            "tx.bytes",
            "rx.bytes",
            "tx.errors",
            "rx.errors",
            "tx.dropped",
            "rx.dropped",
        ],
        "/experimental/syscollector/netproto" => &["iface", "type", "gateway", "dhcp"],
        "/experimental/syscollector/os" => &[
            "os.name",
            "architecture",
            "os.version",
            "version",
            "release",
        ],
        "/experimental/syscollector/packages" => {
            &["vendor", "name", "architecture", "format", "version"]
        }
        "/experimental/syscollector/ports" => &[
            "pid",
            "protocol",
            "local.ip",
            "local.port",
            "remote.ip",
            "tx_queue",
            "state",
            "process",
        ],
        "/experimental/syscollector/processes" => &[
            "pid", "state", "ppid", "egroup", "euser", "fgroup", "name", "nlwp", "pgrp",
            "priority", "rgroup", "ruser", "sgroup", "suser",
        ],
        "/experimental/syscollector/hotfixes" => &["hotfix"],
        _ => &[],
    }
}

async fn list(client: &WazuhClient, path: &str, opts: ListOptions) -> Result<Value, WazuhError> {
    let mut query = request_query(&opts.request);
    for (key, value) in [
        ("agents_list", &opts.agents_list),
        ("search", &opts.search),
        ("select", &opts.select),
        ("sort", &opts.sort),
    ] {
        if let Some(value) = value {
            query.push((key, value.clone()));
        }
    }
    for (key, value) in &opts.filter {
        let Some(&parameter) = allowed_filters(path).iter().find(|&&name| name == key) else {
            return Err(WazuhError::Config(format!(
                "unsupported filter '{key}' for {path}"
            )));
        };
        if query.iter().any(|(name, _)| *name == parameter) {
            return Err(WazuhError::Config(format!("duplicate filter '{key}'")));
        }
        query.push((parameter, value.clone()));
    }
    if let Some(limit) = opts.limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(offset) = opts.offset {
        query.push(("offset", offset.to_string()));
    }
    let query: Vec<_> = query
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    if opts.limit.is_none() && opts.offset.is_none() {
        client.get_all_pages(path, &query, PAGE_SIZE).await
    } else {
        client.get(path, &query).await
    }
}
