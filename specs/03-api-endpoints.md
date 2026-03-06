# 03: API Endpoint List

## Overview

This is the mapping of all Wazuh API v4.x endpoints to their corresponding CLI commands.

## Default

| Method | Path | CLI Command |
|---|---|---|
| GET | `/` | `wazuh-cli api-info` |

## Active Response

| Method | Path | CLI Command |
|---|---|---|
| PUT | `/active-response` | `wazuh-cli active-response run` |

## Agents

| Method | Path | CLI Command |
|---|---|---|
| GET | `/agents` | `agent list` |
| POST | `/agents` | `agent create` |
| DELETE | `/agents` | `agent delete` |
| GET | `/agents/{agent_id}/config/{component}/{configuration}` | `agent config <id> <component> <config>` |
| DELETE | `/agents/{agent_id}/group` | `agent remove-group <id>` |
| GET | `/agents/{agent_id}/group/is_sync` | `agent group-sync <id>` |
| PUT | `/agents/{agent_id}/group/{group_id}` | `agent add-group <id> <group_id>` |
| DELETE | `/agents/{agent_id}/group/{group_id}` | `agent remove-group <id> <group_id>` |
| GET | `/agents/{agent_id}/key` | `agent key <id>` |
| PUT | `/agents/{agent_id}/restart` | `agent restart <id>` |
| GET | `/agents/{agent_id}/daemons/stats` | `agent daemon-stats <id>` |
| GET | `/agents/{agent_id}/stats/{component}` | `agent stats <id> <component>` |
| PUT | `/agents/upgrade` | `agent upgrade` |
| PUT | `/agents/upgrade_custom` | `agent upgrade-custom` |
| GET | `/agents/upgrade_result` | `agent upgrade-result` |
| DELETE | `/agents/group` | `agent remove-group-all` |
| PUT | `/agents/group` | `agent assign-group` |
| PUT | `/agents/group/{group_id}/restart` | `agent restart-group <group_id>` |
| POST | `/agents/insert` | `agent insert` |
| POST | `/agents/insert/quick` | `agent insert-quick` |
| GET | `/agents/no_group` | `agent no-group` |
| PUT | `/agents/node/{node_id}/restart` | `agent restart-node <node_id>` |
| GET | `/agents/outdated` | `agent outdated` |
| PUT | `/agents/reconnect` | `agent reconnect` |
| PUT | `/agents/restart` | `agent restart-all` |
| GET | `/agents/stats/distinct` | `agent stats-distinct` |
| GET | `/agents/summary/os` | `agent summary-os` |
| GET | `/agents/summary/status` | `agent summary-status` |

## Groups

| Method | Path | CLI Command |
|---|---|---|
| GET | `/groups` | `group list` |
| POST | `/groups` | `group create` |
| DELETE | `/groups` | `group delete` |
| GET | `/groups/{group_id}/agents` | `group agents <id>` |
| GET | `/groups/{group_id}/configuration` | `group config <id>` |
| PUT | `/groups/{group_id}/configuration` | `group update-config <id>` |
| GET | `/groups/{group_id}/files` | `group files <id>` |
| GET | `/groups/{group_id}/files/{file_name}` | `group file <id> <filename>` |

## CIS-CAT

| Method | Path | CLI Command |
|---|---|---|
| GET | `/ciscat/{agent_id}/results` | `ciscat results <id>` |

## Cluster

| Method | Path | CLI Command |
|---|---|---|
| GET | `/cluster/local/info` | `cluster local-info` |
| GET | `/cluster/local/config` | `cluster local-config` |
| GET | `/cluster/nodes` | `cluster nodes` |
| GET | `/cluster/healthcheck` | `cluster health` |
| GET | `/cluster/ruleset/synchronization` | `cluster ruleset-sync` |
| GET | `/cluster/status` | `cluster status` |
| GET | `/cluster/api/config` | `cluster api-config` |
| GET | `/cluster/{node_id}/status` | `cluster node-status <id>` |
| GET | `/cluster/{node_id}/info` | `cluster node-info <id>` |
| GET | `/cluster/{node_id}/configuration` | `cluster node-config <id>` |
| PUT | `/cluster/{node_id}/configuration` | `cluster update-node-config <id>` |
| GET | `/cluster/{node_id}/daemons/stats` | `cluster node-daemon-stats <id>` |
| GET | `/cluster/{node_id}/stats` | `cluster node-stats <id>` |
| GET | `/cluster/{node_id}/stats/hourly` | `cluster node-stats <id> --hourly` |
| GET | `/cluster/{node_id}/stats/weekly` | `cluster node-stats <id> --weekly` |
| GET | `/cluster/{node_id}/stats/analysisd` | `cluster node-stats <id> --analysisd` |
| GET | `/cluster/{node_id}/stats/remoted` | `cluster node-stats <id> --remoted` |
| GET | `/cluster/{node_id}/logs` | `cluster node-logs <id>` |
| GET | `/cluster/{node_id}/logs/summary` | `cluster node-logs <id> --summary` |
| PUT | `/cluster/restart` | `cluster restart` |
| GET | `/cluster/configuration/validation` | `cluster validate-config` |
| GET | `/cluster/{node_id}/configuration/{component}/{configuration}` | `cluster node-component-config <id> <comp> <conf>` |

## Lists (CDB)

| Method | Path | CLI Command |
|---|---|---|
| GET | `/lists` | `list get` |
| GET | `/lists/files` | `list files` |
| GET | `/lists/files/{filename}` | `list file <filename>` |
| PUT | `/lists/files/{filename}` | `list update <filename>` |
| DELETE | `/lists/files/{filename}` | `list delete <filename>` |

## Logtest

| Method | Path | CLI Command |
|---|---|---|
| PUT | `/logtest` | `logtest run` |
| DELETE | `/logtest/sessions/{token}` | `logtest delete-session <token>` |

## Manager

| Method | Path | CLI Command |
|---|---|---|
| GET | `/manager/status` | `manager status` |
| GET | `/manager/info` | `manager info` |
| GET | `/manager/configuration` | `manager config` |
| PUT | `/manager/configuration` | `manager update-config` |
| GET | `/manager/daemons/stats` | `manager daemon-stats` |
| GET | `/manager/stats` | `manager stats` |
| GET | `/manager/stats/hourly` | `manager stats --hourly` |
| GET | `/manager/stats/weekly` | `manager stats --weekly` |
| GET | `/manager/stats/analysisd` | `manager stats --analysisd` |
| GET | `/manager/stats/remoted` | `manager stats --remoted` |
| GET | `/manager/logs` | `manager logs` |
| GET | `/manager/logs/summary` | `manager logs --summary` |
| GET | `/manager/api/config` | `manager api-config` |
| PUT | `/manager/restart` | `manager restart` |
| GET | `/manager/configuration/validation` | `manager validate-config` |
| GET | `/manager/configuration/{component}/{configuration}` | `manager component-config <comp> <conf>` |
| GET | `/manager/version/check` | `manager version-check` |

## MITRE ATT&CK

| Method | Path | CLI Command |
|---|---|---|
| GET | `/mitre/groups` | `mitre groups` |
| GET | `/mitre/metadata` | `mitre metadata` |
| GET | `/mitre/mitigations` | `mitre mitigations` |
| GET | `/mitre/references` | `mitre references` |
| GET | `/mitre/software` | `mitre software` |
| GET | `/mitre/tactics` | `mitre tactics` |
| GET | `/mitre/techniques` | `mitre techniques` |

## Rootcheck

| Method | Path | CLI Command |
|---|---|---|
| PUT | `/rootcheck` | `rootcheck run` |
| GET | `/rootcheck/{agent_id}` | `rootcheck get <id>` |
| DELETE | `/rootcheck/{agent_id}` | `rootcheck clear <id>` |
| GET | `/rootcheck/{agent_id}/last_scan` | `rootcheck last-scan <id>` |

## Rules

| Method | Path | CLI Command |
|---|---|---|
| GET | `/rules` | `rule list` |
| GET | `/rules/groups` | `rule groups` |
| GET | `/rules/requirement/{requirement}` | `rule requirements <requirement>` |
| GET | `/rules/files` | `rule files` |
| GET | `/rules/files/{filename}` | `rule file <filename>` |
| PUT | `/rules/files/{filename}` | `rule update <filename>` |
| DELETE | `/rules/files/{filename}` | `rule delete <filename>` |

## SCA

| Method | Path | CLI Command |
|---|---|---|
| GET | `/sca/{agent_id}` | `sca list <id>` |
| GET | `/sca/{agent_id}/checks/{policy_id}` | `sca checks <id> <policy_id>` |

### Extended Commands

| CLI Command | Description |
|---|---|
| `agent sca <id>` | Fetches all SCA policies and their checks for an agent. Combines `sca list` and `sca checks` into a single command. |

## Syscheck

| Method | Path | CLI Command |
|---|---|---|
| PUT | `/syscheck` | `syscheck run` |
| GET | `/syscheck/{agent_id}` | `syscheck get <id>` |
| GET | `/syscheck/{agent_id}/last_scan` | `syscheck last-scan <id>` |

## Decoders

| Method | Path | CLI Command |
|---|---|---|
| GET | `/decoders` | `decoder list` |
| GET | `/decoders/files` | `decoder files` |
| GET | `/decoders/files/{filename}` | `decoder file <filename>` |
| PUT | `/decoders/files/{filename}` | `decoder update <filename>` |
| DELETE | `/decoders/files/{filename}` | `decoder delete <filename>` |
| GET | `/decoders/parents` | `decoder parents` |

## Experimental

| Method | Path | CLI Command |
|---|---|---|
| DELETE | `/experimental/rootcheck` | (excluded from initial implementation) |
| DELETE | `/experimental/syscheck` | (excluded from initial implementation) |
| GET | `/experimental/ciscat/results` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/hardware` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/netaddr` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/netiface` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/netproto` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/os` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/packages` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/ports` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/processes` | (excluded from initial implementation) |
| GET | `/experimental/syscollector/hotfixes` | (excluded from initial implementation) |

## Syscollector

| Method | Path | CLI Command |
|---|---|---|
| GET | `/syscollector/{agent_id}/hardware` | `syscollector hardware <id>` |
| GET | `/syscollector/{agent_id}/hotfixes` | `syscollector hotfixes <id>` |
| GET | `/syscollector/{agent_id}/netaddr` | `syscollector netaddr <id>` |
| GET | `/syscollector/{agent_id}/netiface` | `syscollector netiface <id>` |
| GET | `/syscollector/{agent_id}/netproto` | `syscollector netproto <id>` |
| GET | `/syscollector/{agent_id}/os` | `syscollector os <id>` |
| GET | `/syscollector/{agent_id}/packages` | `syscollector packages <id>` |
| GET | `/syscollector/{agent_id}/ports` | `syscollector ports <id>` |
| GET | `/syscollector/{agent_id}/processes` | `syscollector processes <id>` |

## Security

| Method | Path | CLI Command |
|---|---|---|
| POST | `/security/user/authenticate` | `security login` |
| GET | `/security/user/authenticate` | (internal: token verification) |
| DELETE | `/security/user/authenticate` | `security logout` |
| POST | `/security/user/authenticate/run_as` | `security login --run-as` |
| GET | `/security/users/me` | `security user get-me` |
| GET | `/security/users/me/policies` | `security user my-policies` |
| PUT | `/security/user/revoke` | `security revoke-tokens` |
| PUT | `/security/users/{user_id}/run_as` | `security user set-run-as <id>` |
| GET | `/security/actions` | `security actions` |
| GET | `/security/resources` | `security resources` |
| GET | `/security/users` | `security user list` |
| POST | `/security/users` | `security user create` |
| DELETE | `/security/users` | `security user delete` |
| PUT | `/security/users/{user_id}` | `security user update <id>` |
| GET | `/security/roles` | `security role list` |
| POST | `/security/roles` | `security role create` |
| DELETE | `/security/roles` | `security role delete` |
| PUT | `/security/roles/{role_id}` | `security role update <id>` |
| GET | `/security/rules` | `security rule list` |
| POST | `/security/rules` | `security rule create` |
| DELETE | `/security/rules` | `security rule delete` |
| PUT | `/security/rules/{rule_id}` | `security rule update <id>` |
| GET | `/security/policies` | `security policy list` |
| POST | `/security/policies` | `security policy create` |
| DELETE | `/security/policies` | `security policy delete` |
| PUT | `/security/policies/{policy_id}` | `security policy update <id>` |
| POST | `/security/users/{user_id}/roles` | `security user add-role <user_id> <role_id>` |
| DELETE | `/security/users/{user_id}/roles` | `security user remove-role <user_id> <role_id>` |
| POST | `/security/roles/{role_id}/policies` | `security role add-policy <role_id> <policy_id>` |
| DELETE | `/security/roles/{role_id}/policies` | `security role remove-policy <role_id> <policy_id>` |
| POST | `/security/roles/{role_id}/rules` | `security role add-rule <role_id> <rule_id>` |
| DELETE | `/security/roles/{role_id}/rules` | `security role remove-rule <role_id> <rule_id>` |
| GET | `/security/config` | `security config` |
| PUT | `/security/config` | `security update-config` |
| DELETE | `/security/config` | `security reset-config` |

## Overview

| Method | Path | CLI Command |
|---|---|---|
| GET | `/overview/agents` | `overview agents` |

## Tasks

| Method | Path | CLI Command |
|---|---|---|
| GET | `/tasks/status` | `task status` |

## Events

| Method | Path | CLI Command |
|---|---|---|
| POST | `/events` | `event send` |
