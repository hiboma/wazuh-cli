use serde_json::Value;

use crate::client::WazuhClient;
use crate::error::WazuhError;

pub async fn run(client: &WazuhClient) -> Result<Value, WazuhError> {
    client.get("/", &[]).await
}
