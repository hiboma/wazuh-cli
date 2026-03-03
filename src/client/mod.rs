pub mod auth;
pub mod tls;

use std::sync::Mutex;

use serde_json::Value;

use crate::config::Config;
use crate::error::WazuhError;

pub struct WazuhClient {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: String,
    pub(crate) token: Mutex<Option<String>>,
    pub(crate) credentials: Credentials,
    pub(crate) progress: bool,
}

pub struct Credentials {
    pub user: String,
    pub password: String,
}

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

    /// Returns the cached token.
    /// If no token is available, performs authentication.
    async fn ensure_token(&self) -> Result<String, WazuhError> {
        {
            let guard = self.token.lock().unwrap();
            if let Some(ref token) = *guard {
                return Ok(token.clone());
            }
        }
        self.refresh_token().await
    }

    /// Authenticates and caches a new token.
    async fn refresh_token(&self) -> Result<String, WazuhError> {
        let token = auth::authenticate(
            &self.http,
            &self.base_url,
            &self.credentials.user,
            &self.credentials.password,
        )
        .await?;

        let mut guard = self.token.lock().unwrap();
        *guard = Some(token.clone());
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
            .send_request(&token, method.clone(), path, query, body)
            .await;

        match result {
            Err(WazuhError::Api { status: 401, .. }) => {
                // On 401, retry authentication once
                let new_token = self.refresh_token().await?;
                self.send_request(&new_token, method, path, query, body)
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
