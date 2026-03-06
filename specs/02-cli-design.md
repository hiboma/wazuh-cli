# 02: CLI Design

## Overview

This document defines the command structure and output formats for `wazuh-cli`.

## Command Structure

```
wazuh-cli [global-options] <resource> <action> [arguments] [options]
```

### Global Options

| Option | Short | Description |
|---|---|---|
| `--api-url <URL>` | | API URL |
| `--api-user <USER>` | `-u` | API username |
| `--api-password <PASS>` | `-p` | API password |
| `--ca-cert <PATH>` | | CA certificate path |
| `--client-cert <PATH>` | | Client certificate path |
| `--client-key <PATH>` | | Client private key path |
| `--insecure` | `-k` | Skip TLS verification |
| `--output <FORMAT>` | `-o` | Output format (json, table, csv) |
| `--raw` | | Output API response as-is |
| `--quiet` | `-q` | Output results only |
| `--verbose` | `-v` | Verbose output |
| `--progress` | | Output progress messages to stderr during auto-pagination |

### Resources and Actions

The basic pattern is `wazuh-cli <resource> <action>`.

#### agent

```
wazuh-cli agent list [--status <status>] [--group <group>] [--limit <n>] [--offset <n>]
wazuh-cli agent get <agent_id>
wazuh-cli agent create --name <name> --ip <ip>
wazuh-cli agent delete <agent_id> [<agent_id>...]
wazuh-cli agent restart <agent_id> [<agent_id>...]
wazuh-cli agent restart-all
wazuh-cli agent upgrade <agent_id> [<agent_id>...]
wazuh-cli agent key <agent_id>
wazuh-cli agent groups <agent_id>
wazuh-cli agent add-group <agent_id> <group_id>
wazuh-cli agent remove-group <agent_id> [<group_id>]
wazuh-cli agent outdated
wazuh-cli agent summary-status
wazuh-cli agent summary-os
wazuh-cli agent sca <agent_id>                        # [Extended]
```

#### group

```
wazuh-cli group list [--limit <n>] [--offset <n>]
wazuh-cli group create <group_id>
wazuh-cli group delete <group_id> [<group_id>...]
wazuh-cli group agents <group_id>
wazuh-cli group config <group_id>
wazuh-cli group update-config <group_id> --file <path>
wazuh-cli group files <group_id>
wazuh-cli group file <group_id> <filename>
```

#### rule

```
wazuh-cli rule list [--group <group>] [--level <level>] [--limit <n>]
wazuh-cli rule groups
wazuh-cli rule files
wazuh-cli rule file <filename>
wazuh-cli rule update <filename> --file <path>
wazuh-cli rule delete <filename>
wazuh-cli rule requirements <requirement>
```

#### decoder

```
wazuh-cli decoder list [--limit <n>]
wazuh-cli decoder files
wazuh-cli decoder file <filename>
wazuh-cli decoder update <filename> --file <path>
wazuh-cli decoder delete <filename>
wazuh-cli decoder parents
```

#### cluster

```
wazuh-cli cluster status
wazuh-cli cluster health
wazuh-cli cluster nodes
wazuh-cli cluster local-info
wazuh-cli cluster local-config
wazuh-cli cluster node-info <node_id>
wazuh-cli cluster node-config <node_id>
wazuh-cli cluster node-stats <node_id>
wazuh-cli cluster node-logs <node_id> [--summary]
wazuh-cli cluster restart
wazuh-cli cluster ruleset-sync
wazuh-cli cluster validate-config
```

#### manager

```
wazuh-cli manager status
wazuh-cli manager info
wazuh-cli manager config
wazuh-cli manager update-config --file <path>
wazuh-cli manager stats [--hourly] [--weekly]
wazuh-cli manager logs [--summary]
wazuh-cli manager restart
wazuh-cli manager validate-config
wazuh-cli manager api-config
wazuh-cli manager version-check
```

#### security

```
wazuh-cli security login
wazuh-cli security logout
wazuh-cli security user list
wazuh-cli security user get-me
wazuh-cli security user create --username <name> --password <pass>
wazuh-cli security user update <user_id> [--password <pass>]
wazuh-cli security user delete <user_id> [<user_id>...]
wazuh-cli security role list
wazuh-cli security role create --name <name>
wazuh-cli security role update <role_id>
wazuh-cli security role delete <role_id> [<role_id>...]
wazuh-cli security policy list
wazuh-cli security policy create --name <name>
wazuh-cli security policy update <policy_id>
wazuh-cli security policy delete <policy_id> [<policy_id>...]
wazuh-cli security rule list
wazuh-cli security rule create
wazuh-cli security rule update <rule_id>
wazuh-cli security rule delete <rule_id> [<rule_id>...]
wazuh-cli security config
wazuh-cli security update-config
wazuh-cli security reset-config
```

#### syscheck

```
wazuh-cli syscheck get <agent_id> [--search <term>]
wazuh-cli syscheck last-scan <agent_id>
wazuh-cli syscheck run [<agent_id>...]
wazuh-cli syscheck clear [<agent_id>...]
```

#### syscollector

```
wazuh-cli syscollector hardware <agent_id>
wazuh-cli syscollector os <agent_id>
wazuh-cli syscollector packages <agent_id>
wazuh-cli syscollector processes <agent_id>
wazuh-cli syscollector ports <agent_id>
wazuh-cli syscollector netaddr <agent_id>
wazuh-cli syscollector netiface <agent_id>
wazuh-cli syscollector netproto <agent_id>
wazuh-cli syscollector hotfixes <agent_id>
```

#### rootcheck

```
wazuh-cli rootcheck get <agent_id>
wazuh-cli rootcheck last-scan <agent_id>
wazuh-cli rootcheck run [<agent_id>...]
wazuh-cli rootcheck clear <agent_id>
```

#### sca

```
wazuh-cli sca list <agent_id>
wazuh-cli sca checks <agent_id> <policy_id>
```

#### mitre

```
wazuh-cli mitre groups
wazuh-cli mitre metadata
wazuh-cli mitre mitigations
wazuh-cli mitre references
wazuh-cli mitre software
wazuh-cli mitre tactics
wazuh-cli mitre techniques
```

#### Others

```
wazuh-cli list get [--limit <n>]
wazuh-cli list file <filename>
wazuh-cli list update <filename> --file <path>
wazuh-cli list delete <filename>
wazuh-cli list files

wazuh-cli logtest run --log <log_entry> [--session <token>]
wazuh-cli logtest delete-session <token>

wazuh-cli task status [--limit <n>]

wazuh-cli event send --file <path>

wazuh-cli active-response run --agent <agent_id> --command <cmd>

wazuh-cli overview agents

wazuh-cli api-info
```

## Output Formats

### JSON (Default)

Extracts `data.affected_items` and outputs it as JSON. When `--raw` is specified, the API response is output as-is. This is designed for use with `jq`.

```
wazuh-cli agent list -o json
```

### Table

Outputs in a human-readable table format.

```
wazuh-cli agent list -o table
```

### CSV

```
wazuh-cli agent list -o csv
```

## Response Output

### Default Behavior (affected_items Extraction)

The Wazuh API response has the following structure.

```json
{
  "data": {
    "affected_items": [...],
    "total_affected_items": 500,
    "total_failed_items": 0,
    "failed_items": []
  },
  "message": "...",
  "error": 0
}
```

By default, `data.affected_items` is extracted and output. The fallback order is as follows.

1. If `data.affected_items` exists, it is output.
2. If `data` exists, it is output.
3. If neither exists, the original response is output as-is.

### `--raw` Option

Outputs the API response as-is. This is used when extracting arbitrary fields with `jq`.

| Option | Short | Environment Variable | Description |
|---|---|---|---|
| `--raw` | | `WAZUH_RAW` | Outputs the API response as-is |

```
wazuh-cli agent list --raw
```

## Pagination

### Manual Pagination

List commands accept `--limit` and `--offset` to specify API pagination parameters.

```
wazuh-cli agent list --limit 10 --offset 20
```

### Auto-Pagination

When both `--limit` and `--offset` are omitted, the CLI automatically fetches all items.

- Sends requests in batches of 500 items.
- Loops until `total_affected_items` is reached or the fetched count becomes 0.
- Stops at a maximum of 100 pages (50,000 items).
- If either `--limit` or `--offset` is specified, auto-pagination is disabled.
- When `--progress` is specified, progress messages are output to stderr starting from the 2nd page onward (no output if the result fits in a single page).

```
Fetching... 500/1500
Fetching... 1000/1500
Fetching... 1500/1500
```

Target commands:

- `agent list`, `agent outdated`
- `group list`, `group agents`
- `rule list`, `decoder list`
- `syscheck get`, `rootcheck get`
- Each `syscollector` action (except hardware, os)
- Each `mitre` action (except metadata)
- `security` user/role/policy/rule list
- `list get`, `task status`

## Filtering

Filter parameters supported by the API are provided as CLI options.

```
wazuh-cli agent list --status active --group default
wazuh-cli rule list --level 10-15 --group web
```
