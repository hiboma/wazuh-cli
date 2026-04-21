pub mod auth;
pub mod tls;

use std::fmt;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::WazuhError;

/// Reference-counted JWT. Held as `Arc<Zeroizing<String>>` so the
/// cache can hand out cheap `clone()`s (Arc ref-count bumps, not
/// String copies of the plaintext) while still guaranteeing the
/// plaintext bytes are wiped exactly once when the last Arc is
/// dropped. This replaces the earlier `Mutex<Option<String>>` +
/// `.clone()` design, which created unzeroized heap copies for every
/// request.
type CachedToken = Arc<Zeroizing<String>>;

pub struct WazuhClient {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: String,
    pub(crate) token: Mutex<Option<CachedToken>>,
    pub(crate) credentials: Credentials,
    pub(crate) progress: bool,
}

/// Hand-written `Debug` that never prints the password or the JWT.
/// Prevents accidental leakage if a caller does `{:?}` in a log line
/// or a panic backtrace captures the client state.
impl fmt::Debug for WazuhClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token_state = match self.token.lock() {
            Ok(guard) => match &*guard {
                Some(_) => "***",
                None => "(none)",
            },
            Err(_) => "(poisoned)",
        };
        f.debug_struct("WazuhClient")
            .field("base_url", &self.base_url)
            .field("token", &token_state)
            .field("credentials", &self.credentials)
            .field("progress", &self.progress)
            .finish()
    }
}

pub struct Credentials {
    pub user: String,
    pub password: Zeroizing<String>,
}

/// Hand-written `Debug` that masks the password. `Zeroizing`'s own
/// `Debug` prints the wrapped value, so we cannot rely on deriving.
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field(
                "password",
                &if self.password.is_empty() {
                    "(empty)"
                } else {
                    "***"
                },
            )
            .finish()
    }
}

// `Credentials.password: Zeroizing<String>` and
// `WazuhClient.token: Mutex<Option<Zeroizing<String>>>` each wipe their
// bytes on drop, so no explicit `Drop` impls are needed here. Using
// `Zeroizing` at the type level means refactors cannot accidentally
// drop the wiping behavior (an explicit `impl Drop` can be removed
// without triggering a compile error; changing the type would).

impl WazuhClient {
    /// Builds a WazuhClient from Config.
    /// Creates an HTTP client with TLS/mTLS settings applied.
    pub async fn new(config: &Config) -> Result<Self, WazuhError> {
        let http = tls::build_http_client(config)?;
        let base_url = config.api_url.trim_end_matches('/').to_string();

        Ok(Self {
            http,
            base_url,
            token: Mutex::new(None),
            credentials: Credentials {
                user: config.api_user.clone(),
                password: config.api_password.clone(),
            },
            progress: config.progress,
        })
    }

    /// Returns a handle to the cached token, authenticating if the
    /// cache is empty. Returns `Arc<Zeroizing<String>>` so the caller
    /// gets a cheap ref-counted handle instead of a fresh plaintext
    /// copy.
    async fn ensure_token(&self) -> Result<CachedToken, WazuhError> {
        {
            let guard = self.token.lock().unwrap();
            if let Some(token) = guard.as_ref() {
                return Ok(Arc::clone(token));
            }
        }
        self.refresh_token().await
    }

    /// Authenticates and caches a new token. The fresh `String` from
    /// `auth::authenticate` is immediately moved into `Zeroizing` so
    /// it is wiped when the Arc chain drops.
    async fn refresh_token(&self) -> Result<CachedToken, WazuhError> {
        let raw = auth::authenticate(
            &self.http,
            &self.base_url,
            &self.credentials.user,
            &self.credentials.password,
        )
        .await?;

        let token: CachedToken = Arc::new(Zeroizing::new(raw));
        let mut guard = self.token.lock().unwrap();
        *guard = Some(Arc::clone(&token));
        Ok(token)
    }

    /// Sends a request and retries authentication once on a 401 response.
    async fn request_with_retry(
        &self,
        method: reqwest::Method,
        path: &str,
        query: Option<&[(&str, &str)]>,
        body: Option<&Value>,
    ) -> Result<Value, WazuhError> {
        let token = self.ensure_token().await?;
        let result = self
            .send_request(token.as_str(), method.clone(), path, query, body)
            .await;

        match result {
            Err(WazuhError::Api { status: 401, .. }) => {
                // On 401, retry authentication once
                let new_token = self.refresh_token().await?;
                self.send_request(new_token.as_str(), method, path, query, body)
                    .await
            }
            other => other,
        }
    }

    /// Sends an HTTP request and returns the response as JSON.
    async fn send_request(
        &self,
        token: &str,
        method: reqwest::Method,
        path: &str,
        query: Option<&[(&str, &str)]>,
        body: Option<&Value>,
    ) -> Result<Value, WazuhError> {
        let url = format!("{}{}", self.base_url, path);

        let mut request = self.http.request(method, &url).bearer_auth(token);

        if let Some(q) = query {
            request = request.query(q);
        }

        if let Some(b) = body {
            request = request.json(b);
        }

        let response = request.send().await?;
        let status = response.status();

        if status.is_success() {
            let json: Value = response.json().await?;
            Ok(json)
        } else {
            let body_text = response.text().await.unwrap_or_default();
            Err(WazuhError::Api {
                status: status.as_u16(),
                message: body_text,
            })
        }
    }

    pub async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value, WazuhError> {
        self.request_with_retry(reqwest::Method::GET, path, Some(query), None)
            .await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, WazuhError> {
        self.request_with_retry(reqwest::Method::POST, path, None, Some(body))
            .await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<Value, WazuhError> {
        self.request_with_retry(reqwest::Method::PUT, path, None, Some(body))
            .await
    }

    pub async fn delete(&self, path: &str, query: &[(&str, &str)]) -> Result<Value, WazuhError> {
        self.request_with_retry(reqwest::Method::DELETE, path, Some(query), None)
            .await
    }

    /// Fetches all pages automatically and returns a single response with merged affected_items.
    /// Sends requests from offset=0 in increments of page_size, looping until
    /// total_affected_items is reached or 0 items are returned. Stops after MAX_PAGES pages.
    pub async fn get_all_pages(
        &self,
        path: &str,
        base_query: &[(&str, &str)],
        page_size: u32,
    ) -> Result<Value, WazuhError> {
        const MAX_PAGES: u32 = 100;

        let mut all_items: Vec<Value> = Vec::new();
        let mut offset: u32 = 0;
        let mut last_response: Option<Value> = None;
        let mut page_num: u32 = 0;

        for _ in 0..MAX_PAGES {
            let limit_str = page_size.to_string();
            let offset_str = offset.to_string();

            let mut query: Vec<(&str, &str)> = base_query.to_vec();
            query.push(("limit", &limit_str));
            query.push(("offset", &offset_str));

            let response = self.get(path, &query).await?;

            let items = response
                .get("data")
                .and_then(|d| d.get("affected_items"))
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();

            let total = response
                .get("data")
                .and_then(|d| d.get("total_affected_items"))
                .and_then(|t| t.as_u64())
                .unwrap_or(0);

            let fetched = items.len() as u32;
            all_items.extend(items);
            page_num += 1;

            // Print progress to stderr from the second page onward when progress is enabled
            if self.progress && page_num >= 2 {
                eprintln!("Fetching... {}/{}", all_items.len(), total);
            }

            last_response = Some(response);

            if fetched == 0 || all_items.len() as u64 >= total {
                break;
            }

            offset += fetched;
        }

        // Reconstruct the original response structure with merged affected_items
        match last_response {
            Some(mut resp) => {
                if let Some(data) = resp.get_mut("data") {
                    data["affected_items"] = Value::Array(all_items.clone());
                    data["total_affected_items"] =
                        Value::Number(serde_json::Number::from(all_items.len()));
                }
                Ok(resp)
            }
            None => Ok(serde_json::json!({
                "data": {
                    "affected_items": [],
                    "total_affected_items": 0,
                    "total_failed_items": 0,
                    "failed_items": []
                }
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_debug_masks_password() {
        let c = Credentials {
            user: "alice".to_string(),
            password: Zeroizing::new("super-secret".to_string()),
        };
        let s = format!("{:?}", c);
        assert!(!s.contains("super-secret"));
        assert!(s.contains("alice"));
        assert!(s.contains("***"));
    }

    #[test]
    fn credentials_debug_shows_empty_marker_when_password_unset() {
        let c = Credentials {
            user: "alice".to_string(),
            password: Zeroizing::new(String::new()),
        };
        let s = format!("{:?}", c);
        assert!(s.contains("(empty)"));
        assert!(!s.contains("***"));
    }
}
