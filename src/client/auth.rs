use reqwest::Client;

use crate::error::WazuhError;

/// Sends a Basic Auth request to POST /security/user/authenticate to obtain a JWT token.
/// The ?raw=true parameter causes the token string to be returned directly.
pub async fn authenticate(
    http: &Client,
    base_url: &str,
    user: &str,
    password: &str,
) -> Result<String, WazuhError> {
    let url = format!("{}/security/user/authenticate?raw=true", base_url);

    let response = http
        .post(&url)
        .basic_auth(user, Some(password))
        .send()
        .await
        .map_err(|e| WazuhError::Auth(format!("Authentication request failed: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(WazuhError::Auth(format!(
            "Authentication failed ({}): {}",
            status.as_u16(),
            body
        )));
    }

    let token = response
        .text()
        .await
        .map_err(|e| WazuhError::Auth(format!("Failed to read authentication response: {}", e)))?;

    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(WazuhError::Auth(
            "Authentication succeeded but received empty token".to_string(),
        ));
    }

    Ok(token)
}
