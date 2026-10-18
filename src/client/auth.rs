use reqwest::Client;
use zeroize::Zeroizing;

use crate::error::WazuhError;

/// Sends a Basic Auth request to POST /security/user/authenticate to obtain a JWT token.
/// The ?raw=true parameter causes the token string to be returned directly.
pub(super) async fn authenticate(
    http: &Client,
    base_url: &str,
    user: &str,
    password: &str,
) -> Result<Zeroizing<String>, WazuhError> {
    super::tls::validate_api_url(base_url)?;
    let url = format!("{}/security/user/authenticate?raw=true", base_url);

    let response = http
        .post(&url)
        .basic_auth(user, Some(password))
        .send()
        .await
        .map_err(|_| WazuhError::Auth("Authentication request failed".into()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(WazuhError::Auth(format!(
            "Authentication failed ({})",
            status.as_u16()
        )));
    }

    let token = Zeroizing::new(
        response
            .text()
            .await
            .map_err(|_| WazuhError::Auth("Failed to read authentication response".into()))?,
    );

    let token = Zeroizing::new(token.trim().to_string());
    if token.is_empty() {
        return Err(WazuhError::Auth(
            "Authentication succeeded but received empty token".to_string(),
        ));
    }

    Ok(token)
}
