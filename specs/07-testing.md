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

## Unit Test Isolation

Unit tests must be hermetic: they must not read the developer's real
environment. Three ambient sources leak in otherwise.

| Source | Leak |
| --- | --- |
| `WAZUH_*` environment variables | A developer shell that exports `WAZUH_API_URL` etc. overrides the tier under test. |
| macOS Keychain (`dev.wazuh-cli`) | `default_store()` reads the login Keychain, so a developer who ran `credentials set api-password` resolves a live secret. |
| `~/.config/wazuh-cli/config.toml` | The file tier supplies values the test did not set. |

Rules for tests in `src/config/`:

1. **Never call `Config::from_cli_and_env` from a unit test.** It
   consults the real credential store and the real config file. Use
   `Config::from_cli_env_store_and_file` with an injected
   `MemoryStore` and an explicit `file_cfg` — the `resolve_isolated`
   helper wraps the common case.
2. **Hold an `EnvGuard` for the whole test.** It clears every
   `WAZUH_*` variable on construction and restores the originals on
   `Drop`, so a panicking assertion still cleans up. A bare
   `remove_var` at the end of a test body is skipped on unwind and
   poisons every later test in the process.
3. **Never format a resolved password into an assertion.**
   `assert_eq!(config.api_password.as_str(), "")` bypasses both
   `Zeroizing` and the masking `Debug` impl on `Config`: `as_str()`
   yields a bare `&str` that `assert_eq!` prints verbatim on failure.
   If resolution unexpectedly picked up a real credential, that
   credential lands in the terminal and in CI logs. Use
   `assert_password_eq`, which compares first and reports only the
   expected value and the observed length.

These leaks are invisible in CI (no Keychain entry, no `WAZUH_*`
exports), so they surface only on developer machines. That asymmetry is
why the rules are enforced in code rather than left to review.

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
