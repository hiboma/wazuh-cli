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
- JSON Lines output for list results (`data.affected_items`), enabling line-oriented processing with `jq`, `grep`, `head`

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
# List all agents (JSON Lines output)
wazuh-cli agent list

# Filter with grep
wazuh-cli agent list | grep active

# Extract fields with jq
wazuh-cli agent list | jq -r '.name'

# Get manager info (pretty-printed JSON)
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

## Shell completion

`wazuh-cli completion <SHELL>` prints a completion script to stdout. Supported shells are `bash`, `zsh`, `fish`, `elvish`, and `powershell`.

### zsh

Save the script to a directory in your `fpath` and reload the completion system:

```bash
mkdir -p ~/.zfunc
wazuh-cli completion zsh > ~/.zfunc/_wazuh-cli

# Add to ~/.zshrc if not already present:
#   fpath=(~/.zfunc $fpath)
#   autoload -Uz compinit && compinit
```

Alternatively, source the script directly for the current session:

```bash
source <(wazuh-cli completion zsh)
```

### bash

The target directory depends on the distribution — `/usr/local/etc/bash_completion.d/` on Homebrew (macOS), `/etc/bash_completion.d/` on most Linux distributions, or `~/.local/share/bash-completion/completions/` for a per-user install.

```bash
wazuh-cli completion bash > ~/.local/share/bash-completion/completions/wazuh-cli
# Or for the current session:
source <(wazuh-cli completion bash)
```

### fish

```bash
wazuh-cli completion fish > ~/.config/fish/completions/wazuh-cli.fish
```

## Configuration

### Credential storage (macOS Keychain)

On macOS, `WAZUH_API_PASSWORD` can be stored in the login Keychain
instead of an environment variable. The resolution order for the
password is:

1. `--api-password` CLI option
2. `WAZUH_API_PASSWORD` environment variable
3. macOS Keychain (service `dev.wazuh-cli`, account `api_password`)

Storing the password in the Keychain keeps it out of plaintext config
files, dotfile backups, Time Machine snapshots, and shell history, and
prevents malware running as the same uid from reading it with a simple
file read.

```bash
# Prompt for the password (hidden input) and store it:
wazuh-cli credentials set api-password

# Or read from stdin (pipe-friendly):
printf '%s' "$PASSWORD" | wazuh-cli credentials set api-password --stdin

# See whether a password is stored (value is NOT printed):
wazuh-cli credentials status

# Remove the entry:
wazuh-cli credentials delete api-password
```

There is intentionally no `credentials get` subcommand. The value never
has to leave the Keychain for any legitimate workflow; exposing one
would invite leakage into shell history, terminal scrollback, and
AI-agent transcripts.

#### Notes on Keychain prompts

- The first Keychain read prompts the user. Clicking "Always Allow"
  pins the entry and suppresses further prompts.
- The ACL is tied to the binary's code signature. Rebuilding wazuh-cli
  (e.g. via `cargo install`) re-signs the binary with a different
  identity, which will cause the Keychain to prompt again on the next
  access. If `credentials status` reports an error, open
  **Keychain Access.app**, find the `dev.wazuh-cli` entry, and re-grant
  access via the **Access Control** tab (or delete and re-store the
  entry with `credentials set api-password`).
- On non-macOS builds the Keychain backend is absent; resolution uses
  CLI + env var only.

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
