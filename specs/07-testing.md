# 07: Testing Strategy

## Overview

Tests will be planned after the prototype implementation. This document is an outline of the testing policy.

## Types of Tests

### 1. Unit Tests

Written within each module using `#[cfg(test)]`.

Targets:
- `config.rs`: Configuration priority resolution
- `output.rs`: Output format conversion
- `error.rs`: Error type conversion
- `client/auth.rs`: Token parsing

### 2. Integration Tests

Wazuh API is started with docker-compose, and tests are run against the actual API.

Targets:
- Authentication flow (JWT token acquisition and renewal)
- Primary API operations (agent list, group list, manager info, etc.)
- Error cases (invalid credentials, non-existent resources)

### 3. CLI Tests

Command-line input/output is tested using the `assert_cmd` crate.

Targets:
- Subcommand help display
- Argument validation
- Output formats

## docker-compose Environment

```yaml
# docker/docker-compose.yml
services:
  wazuh-manager:
    image: wazuh/wazuh-manager:4.9.0
    ports:
      - "55000:55000"
    environment:
      - WAZUH_API_USER=wazuh
      - WAZUH_API_PASSWORD=wazuh
```

## Running Tests

```bash
# Unit tests
cargo test --lib

# Integration tests (after starting docker-compose)
cd docker && docker-compose up -d
cargo test --test integration

# All tests
cargo test
```

## Timing of Test Planning

Tests will be detailed after verifying the following behaviors in the prototype.

1. Verification of the authentication flow
2. Verification of the agent list command
3. Verification of error handling
