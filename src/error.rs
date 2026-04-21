use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum WazuhError {
    #[error("Configuration error: {0}")]
    Config(String),

    /// An error from the credential store (macOS Keychain) that is
    /// distinct from a general configuration error. Kept as a separate
    /// variant so downstream code (and messages to the user) can point
    /// at Keychain Access.app rather than at env vars / config files.
    /// Exit code is still 1 per `specs/04-error-handling.md`.
    #[error("Credential store error: {0}")]
    CredentialStore(String),

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
