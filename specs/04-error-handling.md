# 04: Error Handling

## Overview

This document defines the error handling policy for the CLI.

## Error Classification

### 1. CLI Input Errors

Errors caused by invalid command-line arguments or options. clap handles these automatically.

- Unknown subcommand
- Missing required arguments
- Invalid value types

**Response**: Output the clap error message as-is and exit with exit code 2.

### 2. Configuration Errors

Errors when authentication information or connection targets are missing or invalid.

- API URL is not set
- Username/password is not set
- Certificate file does not exist

**Response**: Indicate the missing configuration item and exit with exit code 1.

### 3. Connection Errors

Errors when the connection to the API server fails.

- Network unreachable
- TLS handshake failure
- mTLS authentication failure
- Timeout

**Response**: Present the cause of the error and the settings to check, then exit with exit code 1.

### 4. Authentication Errors

Errors when API authentication fails.

- 401 Unauthorized (invalid credentials)
- 403 Forbidden (insufficient permissions)

**Response**: Output the HTTP status and the API error message, then exit with exit code 1.

### 5. API Errors

Errors when the API returns an error response.

- 400 Bad Request
- 404 Not Found
- 405 Method Not Allowed
- 429 Too Many Requests
- 500 Internal Server Error

**Response**: Output the HTTP status and the API error message, then exit with exit code 1.

### 6. Partial Success

When the `error` field in the API response is `2` (partial success).

**Response**: Output both the successful and failed items. Also display the details of `failed_items`. Exit with exit code 3.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (configuration, connection, authentication, API) |
| 2 | CLI input error |
| 3 | Partial success |

## Error Output Format

Errors are output to standard error (stderr). When `--output json` is specified, errors are also output in JSON format.

### Text Format

```
Error: Authentication failed (401)
  Message: Invalid credentials
  Hint: Check WAZUH_API_USER and WAZUH_API_PASSWORD
```

### JSON Format

```json
{
  "error": {
    "code": 401,
    "message": "Invalid credentials",
    "hint": "Check WAZUH_API_USER and WAZUH_API_PASSWORD"
  }
}
```

## Automatic Token Re-authentication

When a 401 response is received from an API request, automatic re-authentication is attempted once. If re-authentication also fails, the error is processed as-is.
