# 🦊 wazuh-cli

<p align="center">
<strong>Beta</strong>: This tool is in beta. Syntax coverage and lint rules are still limited. Expect breaking changes.
</p>

A command-line tool for the [Wazuh REST API](https://documentation.wazuh.com/current/user-manual/api/reference.html) (v4.x), written in Rust.

## Features

- Covers 19 API resource categories (agents, groups, rules, decoders, cluster, manager, security, and more)
- JWT authentication with automatic token refresh on 401
- TLS and mutual TLS (mTLS) support
- Automatic pagination for list endpoints
- JSON output with `jq`-friendly defaults (extracts `data.affected_items`)

## Installation

### Homebrew

```bash
brew install hiboma/tap/wazuh-cli
```

### Download binary

Download the latest release from [GitHub Releases](https://github.com/hiboma/wazuh-cli/releases) and place the binary in your `$PATH`.

### Build from source

```bash
git clone https://github.com/hiboma/wazuh-cli.git
cd wazuh-cli
cargo build --release
# Binary is at target/release/wazuh-cli
```

## Usage

```bash
wazuh-cli <resource> <action> [options]
```

### Examples

```bash
# List all agents
wazuh-cli agent list

# Get manager info
wazuh-cli manager info

# List security users
wazuh-cli security user list

# Get raw API response
wazuh-cli agent list --raw
```

### Resources

| Resource | Description |
|---|---|
| `agent` | Agent management |
| `group` | Group management |
| `rule` | Rule management |
| `decoder` | Decoder management |
| `cluster` | Cluster information and management |
| `manager` | Manager information and management |
| `security` | User, role, and policy management |
| `syscheck` | File integrity monitoring |
| `syscollector` | System inventory |
| `rootcheck` | Rootkit detection |
| `sca` | Security configuration assessment |
| `mitre` | MITRE ATT&CK information |
| `list` | CDB list management |
| `logtest` | Log testing |
| `task` | Task status |
| `event` | Event ingestion |
| `active-response` | Active response |
| `overview` | Overview information |
| `api-info` | API information |

### Extended Commands

Commands that combine multiple API calls for convenience. These do not map 1:1 to a REST API endpoint.

| Command | Description |
|---|---|
| `agent sca <agent_id>` | Get all SCA policies and their checks for an agent |

## Configuration

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `WAZUH_API_URL` | API URL | `https://localhost:55000` |
| `WAZUH_API_USER` | API username | `wazuh` |
| `WAZUH_API_PASSWORD` | API password | (none) |
| `WAZUH_CA_CERT` | CA certificate file path | (none) |
| `WAZUH_CLIENT_CERT` | Client certificate file path (mTLS) | (none) |
| `WAZUH_CLIENT_KEY` | Client private key file path (mTLS) | (none) |
| `WAZUH_INSECURE` | Skip TLS verification (`true`/`false`) | `false` |
| `WAZUH_OUTPUT` | Default output format | `json` |
| `WAZUH_TIMEOUT` | Request timeout in seconds | `30` |

### CLI options

CLI options override environment variables.

```
--api-url <URL>        API URL
--api-user <USER>      API username (-u)
--api-password <PASS>  API password (-p)
--ca-cert <PATH>       CA certificate path
--client-cert <PATH>   Client certificate path
--client-key <PATH>    Client private key path
--insecure             Skip TLS verification (-k)
--output <FORMAT>      Output format (-o)
--raw                  Output raw API response
--progress             Show pagination progress on stderr
```

## Development

### Prerequisites

- Rust (stable)
- Docker and Docker Compose (for integration tests)

### Build

```bash
cargo build
```

### Test

```bash
# Unit tests (single-threaded due to env var manipulation)
cargo test -- --test-threads=1

# Integration tests (requires Wazuh API)
cd docker && docker-compose up -d
cargo test --test integration
```

### Lint

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

## Specs

Design specifications are in `specs/`. See [specs/00-overview.md](specs/00-overview.md) for the project overview.

## License

[MIT](LICENSE)
