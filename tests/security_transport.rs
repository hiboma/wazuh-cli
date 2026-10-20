mod support;

use serde_json::json;
use support::{Reply, config, mock};
use wazuh_cli::client::WazuhClient;

const JWT: &str = "jwt-SENTINEL";
const PASSWORD: &str = "api-password-SENTINEL";

#[tokio::test]
async fn basic_auth_trimmed_jwt_cache_and_debug_masks() {
    let server = mock(vec![
        Reply::new(200, format!("  {JWT}\n")),
        Reply::new(200, "{}"),
        Reply::new(200, "{}"),
    ]);
    let cfg = config(&server.url);
    let client = WazuhClient::new(&cfg).await.unwrap();
    client.get("/agents", &[]).await.unwrap();
    client.get("/agents", &[]).await.unwrap();
    for debug in [format!("{cfg:?}"), format!("{client:?}")] {
        assert!(!debug.contains(PASSWORD));
        assert!(!debug.contains(JWT));
        assert!(debug.contains("test")); // Usernames are public identifiers.
    }
    let requests = server.finish();
    assert!(requests[0].starts_with("POST /security/user/authenticate?raw=true "));
    let authorization = requests[0]
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .unwrap();
    assert_eq!(authorization, "Basic dGVzdDphcGktcGFzc3dvcmQtU0VOVElORUw=");
    for request in &requests[1..] {
        assert!(request.contains(&format!("Bearer {JWT}\r\n")));
    }
}

#[tokio::test]
async fn unauthorized_reauthenticates_only_once() {
    let server = mock(vec![
        Reply::new(200, JWT),
        Reply::new(401, PASSWORD),
        Reply::new(200, "new-jwt"),
        Reply::new(401, PASSWORD),
    ]);
    let client = WazuhClient::new(&config(&server.url)).await.unwrap();
    let error = client.get("/agents", &[]).await.unwrap_err().to_string();
    assert!(!error.contains(PASSWORD));
    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    assert!(requests[3].contains("Bearer new-jwt\r\n"));
}

#[tokio::test]
async fn empty_token_and_auth_error_body_are_rejected_without_reflection() {
    for reply in [Reply::new(200, " \r\n"), Reply::new(403, PASSWORD)] {
        let server = mock(vec![reply]);
        let client = WazuhClient::new(&config(&server.url)).await.unwrap();
        let error = client.get("/agents", &[]).await.unwrap_err().to_string();
        assert!(!error.contains(PASSWORD));
        assert_eq!(server.finish().len(), 1);
    }
}

#[tokio::test]
async fn redirects_never_reach_another_origin_or_plaintext_destination() {
    for scheme in ["http", "https"] {
        let destination = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let location = format!("{scheme}://{}/stolen", destination.local_addr().unwrap());
        for authenticate in [true, false] {
            let mut replies = vec![];
            if !authenticate {
                replies.push(Reply::new(200, JWT));
            }
            replies.push(Reply::redirect(&location));
            let server = mock(replies);
            let client = WazuhClient::new(&config(&server.url)).await.unwrap();
            assert!(client.get("/agents", &[]).await.is_err());
            server.finish();
            assert_eq!(
                destination.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
}

#[tokio::test]
async fn reflected_success_values_and_error_bodies_do_not_expose_secrets() {
    let user_password = "user-password-SENTINEL";
    for status in [200, 500] {
        let response = json!({"echo": format!("{PASSWORD}/{JWT}/{user_password}")});
        let server = mock(vec![
            Reply::new(200, JWT),
            Reply::new(status, response.to_string()),
        ]);
        let client = WazuhClient::new(&config(&server.url)).await.unwrap();
        let result = client
            .post(
                "/security/users",
                &json!({"username":"visible-user", "password":user_password}),
            )
            .await;
        let text = match result {
            Ok(value) => value.to_string(),
            Err(error) => error.to_string(),
        };
        for secret in [PASSWORD, JWT, user_password] {
            assert!(!text.contains(secret));
        }
        let requests = server.finish();
        assert!(requests[1].contains(user_password)); // Secret is sent only inside TLS.
    }
}

#[tokio::test]
async fn http_and_secret_bearing_urls_are_rejected_before_network() {
    for url in [
        "http://127.0.0.1:55000",
        "https://user:secret@127.0.0.1",
        "https://127.0.0.1?token=secret",
        "https://127.0.0.1#secret",
    ] {
        let error = WazuhClient::new(&config(url))
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret"));
        assert!(error.contains("HTTPS"));
    }
}

#[test]
fn cli_and_environment_http_urls_are_rejected() {
    for from_env in [false, true] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_wazuh-cli"));
        command.env_clear().env("WAZUH_API_PASSWORD", PASSWORD);
        if from_env {
            command.env("WAZUH_API_URL", "http://127.0.0.1:55000");
        } else {
            command.args(["--api-url", "http://127.0.0.1:55000"]);
        }
        let result = command.args(["agent", "list"]).output().unwrap();
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("HTTPS"), "{stderr}");
        assert!(!stderr.contains(PASSWORD));
    }
}

#[cfg(unix)]
#[test]
fn config_file_http_url_is_rejected() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!(
        "wazuh-http-config-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    writeln!(file, "[api]\nurl = \"http://127.0.0.1:55000\"").unwrap();
    drop(file);
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_wazuh-cli"))
        .env_clear()
        .env("WAZUH_API_PASSWORD", PASSWORD)
        .arg("--config")
        .arg(&path)
        .args(["agent", "list"])
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("HTTPS"), "{stderr}");
    assert!(!stderr.contains(PASSWORD));
}
