use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum WazuhError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("Partial success: {succeeded} succeeded, {failed} failed")]
    PartialSuccess { succeeded: u32, failed: u32 },

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
