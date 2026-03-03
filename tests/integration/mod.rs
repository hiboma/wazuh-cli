use wazuh_cli::client::WazuhClient;
use wazuh_cli::config::{Config, OutputFormat};
use wazuh_cli::error::WazuhError;

fn test_config() -> Config {
    Config {
        api_url: std::env::var("WAZUH_TEST_API_URL")
            .unwrap_or_else(|_| "https://localhost:55000".to_string()),
        api_user: "wazuh".to_string(),
        api_password: "wazuh".to_string(),
        ca_cert: None,
        client_cert: None,
        client_key: None,
        insecure: true,
        output_format: OutputFormat::Json,
        raw_output: false,
        progress: false,
        timeout: 30,
    }
}

fn bad_password_config() -> Config {
    Config {
        api_url: std::env::var("WAZUH_TEST_API_URL")
            .unwrap_or_else(|_| "https://localhost:55000".to_string()),
        api_user: "wazuh".to_string(),
        api_password: "wrong_password".to_string(),
        ca_cert: None,
        client_cert: None,
        client_key: None,
        insecure: true,
        output_format: OutputFormat::Json,
        raw_output: false,
        progress: false,
        timeout: 30,
    }
}

/// 認証フロー: WazuhClient::new で接続し、認証トークンの取得後に API 呼び出しが成功することを検証します。
#[tokio::test]
#[ignore]
async fn test_authentication_flow() {
    let config = test_config();
    let client = WazuhClient::new(&config).await.unwrap();
    let result = client.get("/agents/summary/status", &[]).await;
    assert!(
        result.is_ok(),
        "Authentication and API call should succeed: {:?}",
        result.err()
    );
}

/// agent list: GET /agents が成功し、JSON レスポンスに data フィールドが含まれることを検証します。
#[tokio::test]
#[ignore]
async fn test_agent_list() {
    let config = test_config();
    let client = WazuhClient::new(&config).await.unwrap();
    let result = client.get("/agents", &[]).await;
    assert!(
        result.is_ok(),
        "GET /agents should succeed: {:?}",
        result.err()
    );
    let json = result.unwrap();
    assert!(
        json.get("data").is_some(),
        "Response should contain 'data' field: {}",
        json
    );
}

/// manager info: GET /manager/info が成功し、JSON レスポンスに data フィールドが含まれることを検証します。
#[tokio::test]
#[ignore]
async fn test_manager_info() {
    let config = test_config();
    let client = WazuhClient::new(&config).await.unwrap();
    let result = client.get("/manager/info", &[]).await;
    assert!(
        result.is_ok(),
        "GET /manager/info should succeed: {:?}",
        result.err()
    );
    let json = result.unwrap();
    assert!(
        json.get("data").is_some(),
        "Response should contain 'data' field: {}",
        json
    );
}

/// 認証エラー: 不正なパスワードで WazuhClient::new を呼び出すと WazuhError::Auth が返ることを検証します。
#[tokio::test]
#[ignore]
async fn test_authentication_error() {
    let config = bad_password_config();
    let result = WazuhClient::new(&config).await;

    // WazuhClient::new は内部で認証を行わないため、クライアント作成自体は成功します。
    // 認証エラーは最初の API 呼び出し時に発生します。
    let client = result.unwrap();
    let api_result = client.get("/agents/summary/status", &[]).await;
    assert!(
        api_result.is_err(),
        "API call with wrong password should fail"
    );
    let err = api_result.unwrap_err();
    assert!(
        matches!(err, WazuhError::Auth(_)),
        "Error should be WazuhError::Auth, got: {:?}",
        err
    );
}
