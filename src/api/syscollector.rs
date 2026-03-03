use serde_json::Value;

use crate::cli::syscollector::{SyscollectorAction, SyscollectorCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: SyscollectorCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        SyscollectorAction::Hardware { agent_id } => {
            let path = format!("/syscollector/{}/hardware", agent_id);
            client.get(&path, &[]).await
        }
        SyscollectorAction::Os { agent_id } => {
            let path = format!("/syscollector/{}/os", agent_id);
            client.get(&path, &[]).await
        }
        SyscollectorAction::Packages { agent_id } => {
            let path = format!("/syscollector/{}/packages", agent_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
        SyscollectorAction::Processes { agent_id } => {
            let path = format!("/syscollector/{}/processes", agent_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
        SyscollectorAction::Ports { agent_id } => {
            let path = format!("/syscollector/{}/ports", agent_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
        SyscollectorAction::Netaddr { agent_id } => {
            let path = format!("/syscollector/{}/netaddr", agent_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
        SyscollectorAction::Netiface { agent_id } => {
            let path = format!("/syscollector/{}/netiface", agent_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
        SyscollectorAction::Netproto { agent_id } => {
            let path = format!("/syscollector/{}/netproto", agent_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
        SyscollectorAction::Hotfixes { agent_id } => {
            let path = format!("/syscollector/{}/hotfixes", agent_id);
            client.get_all_pages(&path, &[], PAGE_SIZE).await
        }
    }
}
