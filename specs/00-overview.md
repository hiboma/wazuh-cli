# 00: Project Overview

## Purpose

Implement a CLI tool `wazuh-cli` in Rust to operate the Wazuh REST API.

## Target API

- Wazuh Server API v4.x (OpenAPI 3.0 compliant)
- Base URL: `https://<host>:55000`
- Reference: https://documentation.wazuh.com/current/user-manual/api/reference.html

## CLI Basic Form

```
wazuh-cli <subcommand> [subcommand...] [options]
```

## Technology Stack

| Item | Selection |
|------|------|
| Language | Rust |
| CLI Framework | clap |
| HTTP Client | reqwest (rustls) |
| JSON Processing | serde, serde_json |
| Async Runtime | tokio |
| Test Environment | docker-compose (Wazuh API) |

## Development Guidelines

- Cover all endpoints based on the OpenAPI specification.
- Avoid using lesser-known crates.
- Plan tests after implementing a prototype.
- Run integration tests using a Wazuh API instance set up with docker-compose.

## API Resource Categories

CLI subcommands correspond to the following API resources.

| Subcommand | API Resource | Description |
|---|---|---|
| `agent` | /agents | Agent management |
| `group` | /groups | Group management |
| `rule` | /rules | Rule viewing and management |
| `decoder` | /decoders | Decoder viewing and management |
| `cluster` | /cluster | Cluster information and management |
| `manager` | /manager | Manager information and management |
| `security` | /security | User, role, and policy management |
| `syscheck` | /syscheck | File integrity monitoring |
| `syscollector` | /syscollector | System information collection |
| `rootcheck` | /rootcheck | Rootkit detection |
| `sca` | /sca | Security configuration assessment |
| `ciscat` | /ciscat | CIS-CAT results |
| `mitre` | /mitre | MITRE ATT&CK information |
| `list` | /lists | CDB list management |
| `logtest` | /logtest | Log testing |
| `task` | /tasks | Task status |
| `event` | /events | Event submission |
| `active-response` | /active-response | Active response |
| `overview` | /overview | Overview information |

## Spec Document Structure

| File | Content |
|---|---|
| `00-overview.md` | Project overview (this file) |
| `01-authentication.md` | Authentication and mTLS specification |
| `02-cli-design.md` | CLI command structure and output formats |
| `03-api-endpoints.md` | API endpoint list and CLI mapping |
| `04-error-handling.md` | Error handling policy |
| `05-configuration.md` | Configuration files and environment variables |
| `06-project-structure.md` | Rust project structure |
| `07-testing.md` | Testing strategy |
| `08-spec-conformance.md` | Spec conformance verification |
| `09-coverage.md` | Test coverage policy and targets |
