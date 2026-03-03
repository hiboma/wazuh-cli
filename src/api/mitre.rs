use serde_json::Value;

use crate::cli::mitre::{MitreAction, MitreCommand};
use crate::client::WazuhClient;
use crate::error::WazuhError;

const PAGE_SIZE: u32 = 500;

pub async fn run(client: &WazuhClient, cmd: MitreCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        MitreAction::Groups => client.get_all_pages("/mitre/groups", &[], PAGE_SIZE).await,
        MitreAction::Metadata => client.get("/mitre/metadata", &[]).await,
        MitreAction::Mitigations => {
            client
                .get_all_pages("/mitre/mitigations", &[], PAGE_SIZE)
                .await
        }
        MitreAction::References => {
            client
                .get_all_pages("/mitre/references", &[], PAGE_SIZE)
                .await
        }
        MitreAction::Software => {
            client
                .get_all_pages("/mitre/software", &[], PAGE_SIZE)
                .await
        }
        MitreAction::Tactics => client.get_all_pages("/mitre/tactics", &[], PAGE_SIZE).await,
        MitreAction::Techniques => {
            client
                .get_all_pages("/mitre/techniques", &[], PAGE_SIZE)
                .await
        }
    }
}
