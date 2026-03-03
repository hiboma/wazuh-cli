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

```
--api-url <URL>
--api-user <USER>
--api-password <PASSWORD>
--ca-cert <PATH>
--client-cert <PATH>
--client-key <PATH>
--insecure
```

## 2. JWT Authentication

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

- Passing the password via environment variables is recommended.
- When passing it via CLI options, output a warning as it may be visible in the process list.
- Do not save tokens to disk.
