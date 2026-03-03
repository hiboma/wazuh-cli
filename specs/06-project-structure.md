# 06: Rust Project Structure

## Overview

This document defines the Rust project structure for `wazuh-cli`.

## Directory Structure

```
wazuh-cli/
├── Cargo.toml
├── Cargo.lock
├── specs/                      # Spec documents
├── src/
│   ├── main.rs                 # Entry point
│   ├── lib.rs                  # Library crate root
│   ├── cli/
│   │   ├── mod.rs              # CLI definitions (clap)
│   │   ├── agent.rs            # agent subcommand
│   │   ├── group.rs            # group subcommand
│   │   ├── rule.rs             # rule subcommand
│   │   ├── decoder.rs          # decoder subcommand
│   │   ├── cluster.rs          # cluster subcommand
│   │   ├── manager.rs          # manager subcommand
│   │   ├── security.rs         # security subcommand
│   │   ├── syscheck.rs         # syscheck subcommand
│   │   ├── syscollector.rs     # syscollector subcommand
│   │   ├── rootcheck.rs        # rootcheck subcommand
│   │   ├── sca.rs              # sca subcommand
│   │   ├── mitre.rs            # mitre subcommand
│   │   └── other.rs            # list, logtest, task, event, active-response, overview
│   ├── client/
│   │   ├── mod.rs              # WazuhClient struct
│   │   ├── auth.rs             # Authentication (JWT token management)
│   │   └── tls.rs              # TLS / mTLS configuration
│   ├── api/
│   │   ├── mod.rs              # API module exports
│   │   ├── active_response.rs  # /active-response endpoint
│   │   ├── agent.rs            # /agents endpoint
│   │   ├── api_info.rs         # / endpoint (API information)
│   │   ├── cluster.rs          # /cluster endpoint
│   │   ├── decoder.rs          # /decoders endpoint
│   │   ├── event.rs            # /events endpoint
│   │   ├── group.rs            # /groups endpoint
│   │   ├── list.rs             # /lists endpoint
│   │   ├── logtest.rs          # /logtest endpoint
│   │   ├── manager.rs          # /manager endpoint
│   │   ├── mitre.rs            # /mitre endpoint
│   │   ├── overview.rs         # /overview endpoint
│   │   ├── rootcheck.rs        # /rootcheck endpoint
│   │   ├── rule.rs             # /rules endpoint
│   │   ├── sca.rs              # /sca endpoint
│   │   ├── security.rs         # /security endpoint
│   │   ├── syscheck.rs         # /syscheck endpoint
│   │   ├── syscollector.rs     # /syscollector endpoint
│   │   └── task.rs             # /tasks endpoint
│   ├── config.rs               # Configuration resolution (CLI > env vars > file)
│   ├── output.rs               # Output formatter (json)
│   └── error.rs                # Error type definitions
├── tests/
│   ├── cli_conformance.rs      # CLI conformance tests
│   └── integration/            # Integration tests
│       └── mod.rs
└── docker/
    ├── docker-compose.yml      # Wazuh API test environment
    └── certs/                  # Test certificates
```

## Module Responsibilities

### `cli/` - Command-Line Definitions

Define the CLI using clap's `derive` macros. Each file is responsible for the argument definitions of a subcommand.

### `client/` - HTTP Client

The `WazuhClient` struct manages communication with the API.

```rust
pub struct WazuhClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
    credentials: Credentials,
}
```

Responsibilities:
- TLS / mTLS configuration
- JWT token acquisition, retention, and automatic renewal
- Sending requests and parsing responses

### `api/` - API Endpoints

Implement API calls for each resource. Accept `WazuhClient` as an argument and provide type-safe functions.

### `config.rs` - Configuration Resolution

Resolve configuration from CLI options, environment variables, and configuration files.

### `output.rs` - Output Formatter

Output API responses to stdout in the specified format (json, table, csv).

### `error.rs` - Error Types

Define error types using `thiserror`.

## Dependency Crates

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"

[dev-dependencies]
```

## Current Simplifications

The following features are simplified at this time.

- Configuration file support is omitted (only environment variables and CLI options).
- table / csv output is omitted (JSON only).
- Experimental endpoints are excluded.
- Some endpoints listed in 03-api-endpoints.md are not yet implemented as CLI subcommands.

## Implemented Resources

API calls for all 19 resources are implemented.

| Resource | CLI Subcommand | API Path Prefix |
|---|---|---|
| agent | `wazuh-cli agent` | /agents |
| group | `wazuh-cli group` | /groups |
| manager | `wazuh-cli manager` | /manager |
| security | `wazuh-cli security` | /security |
| rule | `wazuh-cli rule` | /rules |
| decoder | `wazuh-cli decoder` | /decoders |
| cluster | `wazuh-cli cluster` | /cluster |
| syscheck | `wazuh-cli syscheck` | /syscheck |
| syscollector | `wazuh-cli syscollector` | /syscollector |
| rootcheck | `wazuh-cli rootcheck` | /rootcheck |
| sca | `wazuh-cli sca` | /sca |
| mitre | `wazuh-cli mitre` | /mitre |
| list | `wazuh-cli list` | /lists |
| logtest | `wazuh-cli logtest` | /logtest |
| task | `wazuh-cli task` | /tasks |
| event | `wazuh-cli event` | /events |
| active-response | `wazuh-cli active-response` | /active-response |
| overview | `wazuh-cli overview` | /overview |
| api-info | `wazuh-cli api-info` | / |
