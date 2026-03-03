# 05: Configuration Files and Environment Variables

## Overview

Configuration for `wazuh-cli` is resolved in the following order of precedence.

```
CLI options > Environment variables > Configuration file > Default values
```

## Environment Variables

| Environment Variable | Description | Default |
|---|---|---|
| `WAZUH_API_URL` | API URL | `https://localhost:55000` |
| `WAZUH_API_USER` | API username | `wazuh` |
| `WAZUH_API_PASSWORD` | API password | (none) |
| `WAZUH_CA_CERT` | File path to the CA certificate | (none) |
| `WAZUH_CLIENT_CERT` | File path to the client certificate | (none) |
| `WAZUH_CLIENT_KEY` | File path to the client private key | (none) |
| `WAZUH_INSECURE` | Skip TLS verification (`true`/`false`) | `false` |
| `WAZUH_OUTPUT` | Default output format | `json` |
| `WAZUH_RAW` | Output API response as-is (`true`/`false`) | `false` |
| `WAZUH_PROGRESS` | Progress messages during auto-pagination (`true`/`false`) | `false` |
| `WAZUH_TIMEOUT` | Request timeout (seconds) | `30` |

## Configuration File

Settings can be written in `~/.config/wazuh-cli/config.toml`.

```toml
[api]
url = "https://wazuh-manager:55000"
user = "wazuh"
# Specifying the password via environment variables is recommended

[tls]
ca_cert = "/path/to/ca.pem"
client_cert = "/path/to/client.pem"
client_key = "/path/to/client-key.pem"
insecure = false

[output]
format = "json"  # json, table, csv

[request]
timeout = 30
```

### Configuration File Search Order

1. Path specified with `--config <path>`
2. Path specified with the `WAZUH_CONFIG` environment variable
3. `~/.config/wazuh-cli/config.toml`

### Prototype Phase

Configuration file support is not implemented during the prototype phase. Only environment variables and CLI options are functional.
