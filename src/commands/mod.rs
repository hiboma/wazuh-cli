//! Command handlers that do not translate 1:1 to a Wazuh API endpoint.
//!
//! API-backed subcommands live in `crate::api`; host-side helpers such
//! as `credentials` (which talks to the macOS Keychain, not the Wazuh
//! server) live here.

#[cfg(target_os = "macos")]
pub mod credentials;
