# 05: Configuration Files and Environment Variables

## Overview

Configuration for `wazuh-cli` is resolved in the following order of
precedence:

```
CLI options
  > Environment variables
  > Credential store (macOS Keychain, api_password only)
  > Configuration file (~/.config/wazuh-cli/config.toml)
  > Default values
```

The credential store tier only applies to `api_password`. All other
settings (URL, user, cert paths, timeout, output format, etc.) skip
the Keychain tier and consult CLI, env var, file, default in that
order.

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

Settings can be written to a TOML file. Every section and field is
optional; missing fields fall through to the next tier (env var or
default).

```toml
[api]
url = "https://wazuh-manager:55000"
user = "wazuh"
# DO NOT put `password = "..."` here. wazuh-cli intentionally
# IGNORES any `[api] password` value and prints a warning on
# startup. Use `wazuh-cli credentials set api-password` to store
# the secret in the macOS Keychain, or set `WAZUH_API_PASSWORD`.

[tls]
ca_cert = "/path/to/ca.pem"
client_cert = "/path/to/client.pem"
client_key = "/path/to/client-key.pem"
insecure = false

[output]
format = "json"   # currently only "json" is implemented
raw = false
progress = false

[request]
timeout = 30
```

Unknown fields are rejected at parse time (`deny_unknown_fields`),
so a typo like `clinet_cert` produces a clear error rather than
being silently ignored.

### Configuration File Search Order

1. Path specified with `--config <PATH>` (a missing / unreadable
   file at this path is a hard error)
2. Path in the `WAZUH_CONFIG` environment variable (same strictness)
3. `$XDG_CONFIG_HOME/wazuh-cli/config.toml`, falling back to
   `~/.config/wazuh-cli/config.toml`

For tiers (1) and (2) the file is **required**: a typo in the path
surfaces as `failed to read <path>: No such file or directory`. The
default-location file is optional; when absent, resolution simply
falls through to the next tier.

### Why the file sits below the Keychain for `api_password`

`api_password` is resolved as **CLI > env var > Keychain > file >
default**. The config file is explicitly below the Keychain because:

- A plaintext password in the file defeats the whole point of the
  Keychain backing (it would be included in Time Machine /
  iCloud / rsync snapshots, dotfile repos, etc.).
- If the file did contain a stale password, a Keychain-backed
  rotation must still win — otherwise rotating via
  `credentials set api-password` would appear to have had no
  effect.
- The `[api] password` field is accepted by the parser only so the
  startup warning can detect and reject it; the value itself is
  never consumed.

### File permissions

On startup, `wazuh-cli` warns to stderr if the config file has any
of `0o077` bits set (group or world accessible). The warning is
informational: the file is expected to contain non-secret settings,
and breaking non-sensitive configs behind the same fence would be
too aggressive. The warning is load-bearing if the user writes a
secret there anyway — in which case the log line tells them to use
`credentials set api-password` instead.

### Prototype phase note (historical)

Earlier drafts of this document noted that "configuration file
support is not implemented during the prototype phase". That
limitation is now lifted as of this commit.

## Credential store (macOS Keychain)

`api_password` can be sourced from the macOS login Keychain. Management
is exposed as a subcommand:

```
wazuh-cli credentials set api-password
wazuh-cli credentials set api-password --stdin
wazuh-cli credentials set api-password --file <PATH>   # see requirements below
wazuh-cli credentials delete api-password
wazuh-cli credentials status                           # human-readable TSV
wazuh-cli credentials status --json                    # machine-readable
```

`--file <PATH>` must satisfy **all** of:

- not a symlink (`O_NOFOLLOW`),
- a regular file,
- owned by the current effective UID,
- mode with `0o077` cleared (no group/world access).

`set` strips a single trailing `\r` / `\n` / `\r\n` from the input.
Plain trailing spaces and other whitespace are preserved byte-for-byte
so a real trailing space in a password is not silently mangled.
Interior newlines are preserved too (multi-line secrets are allowed
but unusual).

### Output format

`credentials status` emits two columns on stdout
(`{field}\t{state}`) with a header on stderr so `cut`/`awk` can
parse without stripping headers. Error rows get a third column with
the message, with TAB/CR/LF replaced by single spaces — use
`--json` if you need the original error text.

`credentials status --json` emits
`{"ok": bool, "service": "dev.wazuh-cli", "entries": {<field>: {"state": "stored"|"not-stored"|"error", "error": "..."}}}`.
`ok` is `true` iff no entry surfaced an error. The `state` vocabulary
uses the same hyphens as the TSV output.

The entry is stored under service `dev.wazuh-cli`, account
`api_password`. There is intentionally no `credentials get`: the value
never has to leave the Keychain for any legitimate workflow, and
exposing one would invite leakage into shell history, terminal
scrollback, and AI-agent transcripts.

### Store error semantics

The store returns one of two error classes:

- `Unavailable` — no credential backend on this host (non-macOS build,
  or macOS with no default keychain). Resolution silently falls through
  to the next tier. This preserves the previous env-only behavior for
  users who never opt into the Keychain.
- `Backend` — a real access failure (denied prompt, ACL mismatch,
  daemon down). Resolution **does not** fall through. The error is
  surfaced so the user investigates, rather than silently running
  against an empty / stale password.

### Non-macOS

Non-macOS builds compile without the `keyring` / `security-framework`
dependencies. `credentials` subcommands return an `Unavailable` error,
and resolution of `api_password` uses only CLI + env var.
