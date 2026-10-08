# 01: Authentication Specification

## Overview

The following authentication is required to access the Wazuh API.

1. Transport layer encryption via TLS (required)
2. Client authentication via mTLS (optional; enabled depending on the environment)
3. API layer authentication via JWT token (required)

## 1. TLS / mTLS Authentication

### Standard TLS (Required)

The Wazuh API uses HTTPS (port 55000) by default. For self-signed certificates, either specify a CA certificate for verification or skip verification.

### mTLS (Mutual TLS Authentication) - Optional

Supports environments that require client certificate authentication. mTLS is not required and is only used when mTLS is enabled on the Wazuh API side. mTLS is enabled when both `WAZUH_CLIENT_CERT` and `WAZUH_CLIENT_KEY` are set.

### Environment Variables

| Environment Variable | Description | Required |
|---|---|---|
| `WAZUH_API_URL` | API URL (e.g., `https://localhost:55000`) | Yes |
| `WAZUH_API_USER` | API username | Yes |
| `WAZUH_API_PASSWORD` | API password | Yes |
| `WAZUH_CA_CERT` | File path to the CA certificate | No |
| `WAZUH_CLIENT_CERT` | File path to the client certificate (mTLS) | No |
| `WAZUH_CLIENT_KEY` | File path to the client private key (mTLS) | No |
| `WAZUH_INSECURE` | Skip TLS verification (`true`/`false`) | No |

### CLI Options

In addition to environment variables, CLI options can also be used. CLI options take precedence over environment variables.

There is no CLI option for the password. A value passed as an argument is
recorded in shell history and is visible to `ps`, auditd `EXECVE` records,
and EDR process events, which are often forwarded to a SIEM. The former
`--api-password` / `-p` option was removed; passing it fails with exit
code 2 and a message pointing to the alternatives below. The error message
never echoes the value.

```
--api-url <URL>
--api-user <USER>
--ca-cert <PATH>
--client-cert <PATH>
--client-key <PATH>
--insecure
```

### Credential storage (macOS Keychain)

`WAZUH_API_PASSWORD` can be stored in the macOS login Keychain under
service `dev.wazuh-cli`, account `api_password`. The `credentials`
subcommand manages these entries:

```
wazuh-cli credentials set api-password      # prompts (hidden input)
wazuh-cli credentials set api-password --stdin
wazuh-cli credentials delete api-password
wazuh-cli credentials status                # shows presence, never the value
```

Resolution order for the password is:

1. `WAZUH_API_PASSWORD` environment variable
2. macOS Keychain (service `dev.wazuh-cli`, account `api_password`)
3. empty (authentication will fail)

When the Keychain is present but an access attempt fails (a denied
prompt, an ACL mismatch after re-signing the binary), wazuh-cli does
**not** fall through to the empty default. It surfaces the Backend
error so the user investigates rather than silently running against
bad credentials. A missing default keychain (non-macOS, or a clean CI
sandbox) is classified as `Unavailable` and does fall through.

## 2. JWT Authentication

### HTTP Request Headers

All HTTP requests, including authentication and retries, send
`User-Agent: wazuh-cli/<version>`. The version comes from the package version
in `Cargo.toml` at build time.

### Authentication Flow

```
1. POST /security/user/authenticate (Basic Auth)
   -> Obtain a JWT token

2. Attach the Authorization: Bearer <token> header to subsequent requests

3. If the token has expired (default 900 seconds), automatically re-authenticate
```

### Implementation Policy

- Send a request with Basic Auth to `POST /security/user/authenticate` to obtain a JWT token.
- Store the token in memory (do not persist it to a file).
- If a token expiration (401 response) is detected during an API request, automatically re-authenticate.
- Use `POST /security/user/authenticate/run_as` for `run_as` authentication.

### Security Considerations

- Passing the password via the macOS Keychain is preferred; environment
  variables are the next best option.
- Secrets are never accepted as command-line argument values. This
  applies to the API password and to user passwords set through
  `security user create` / `security user update` (see
  `02-cli-design.md`). When setting `WAZUH_API_PASSWORD`, use
  `read -s WAZUH_API_PASSWORD; export WAZUH_API_PASSWORD` so that the
  value does not enter shell history.
- After resolution, wazuh-cli removes `WAZUH_API_PASSWORD` from its own
  environment so that a subsequent `ps -E` / read of
  `/proc/<pid>/environ` does not see the plaintext for the lifetime of
  the process.
- The resolved password is zeroized on process exit (via `Drop` on the
  client credential struct), and input to `credentials set` is kept in
  `zeroize::Zeroizing<String>` from stdin/tty through the Keychain
  store call.
- `Config`'s `Debug` impl masks the password as `***` (or `(empty)` when
  unset) so stray `{:?}` in logs cannot leak it.
- Do not save JWT tokens to disk. The in-memory token is also zeroized
  on client drop.
