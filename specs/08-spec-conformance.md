# 08: Spec Conformance Verification

## Overview

This document defines the approach for verifying that the implementation conforms to the specifications defined in specs/. Verification is conducted along two axes: static analysis and dynamic testing.

## Verification Targets and Methods

### Layer 1: CLI Interface Conformance

Verification against 02-cli-design.md and 03-api-endpoints.md.

#### 1a. Subcommand Existence Check (Static)

Verifies that all subcommands defined in the specification exist in the clap definitions.

Method: Run `wazuh-cli --help` and `--help` for each subcommand, and write tests that confirm the expected subcommands and options appear in the output.

```rust
// tests/spec_conformance/cli_subcommands.rs
#[test]
fn spec_agent_subcommands_exist() {
    let expected = vec![
        "list", "create", "delete", "restart", "restart-all",
        "upgrade", "key", "add-group", "remove-group",
        "outdated", "summary-status", "summary-os",
    ];
    let output = Command::new("wazuh-cli")
        .args(["agent", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    for sub in expected {
        assert!(help.contains(sub), "agent subcommand '{}' not found in help", sub);
    }
}
```

#### 1b. Global Option Existence Check (Static)

Verifies that all global options defined in 02-cli-design.md are accepted.

```rust
#[test]
fn spec_global_options_accepted() {
    let options = vec![
        ("--api-url", "https://localhost:55000"),
        ("--api-user", "wazuh"),
        ("--api-password", "wazuh"),
        ("--ca-cert", "/tmp/ca.pem"),
        ("--client-cert", "/tmp/client.pem"),
        ("--client-key", "/tmp/client-key.pem"),
        ("--output", "json"),
    ];
    // Confirm that clap parsing does not fail
    // (Combined with the help subcommand since no API connection is made)
}
```

#### 1c. Endpoint Coverage Check (Static)

Verifies that the CLI commands defined in 03-api-endpoints.md are implemented as corresponding functions in the api/ module.

Method: Parse 03-api-endpoints.md to extract the CLI command list, and create a script that uses grep to check whether corresponding implementations exist in the source code.

```bash
#!/bin/bash
# scripts/check_endpoint_coverage.sh
# Extracts CLI command columns from 03-api-endpoints.md
# and checks for the presence of implementations

SPEC="specs/03-api-endpoints.md"
MISSING=0

# Extracts entries excluding experimental and internal endpoints
grep -oP '`((?!excluded from initial implementation|internal:)[a-z][\w -]*[\w])`' "$SPEC" | \
  sort -u | while read -r cmd; do
    # Checks whether a corresponding subcommand definition exists under cli/
    if ! grep -rq "$cmd" src/cli/; then
      echo "MISSING: $cmd"
      MISSING=$((MISSING + 1))
    fi
  done

exit $MISSING
```

### Layer 2: Authentication Specification Conformance

Verification against 01-authentication.md.

#### 2a. Environment Variable Acceptance (Unit Test)

Verifies that all environment variables defined in the specification are processed by the config module.

```rust
#[test]
fn spec_all_env_vars_recognized() {
    let env_vars = vec![
        "WAZUH_API_URL",
        "WAZUH_API_USER",
        "WAZUH_API_PASSWORD",
        "WAZUH_CA_CERT",
        "WAZUH_CLIENT_CERT",
        "WAZUH_CLIENT_KEY",
        "WAZUH_INSECURE",
        "WAZUH_OUTPUT",
        "WAZUH_TIMEOUT",
    ];
    for var in env_vars {
        std::env::set_var(var, "test_value");
    }
    let config = Config::from_env();
    assert!(config.is_ok(), "Config should parse all spec-defined env vars");
    // Confirm that each field is set to "test_value"
}
```

#### 2b. mTLS Optional Behavior (Integration Test)

Verifies that a connection can be established successfully even when mTLS environment variables are not set. Also verifies that the client certificate is sent when mTLS environment variables are set.

```rust
#[test]
fn spec_mtls_is_optional() {
    // Confirm that the API connection succeeds without setting
    // WAZUH_CLIENT_CERT and WAZUH_CLIENT_KEY
}

#[test]
fn spec_mtls_enabled_when_both_cert_and_key_set() {
    // Confirm that mTLS is enabled when both are set
}
```

#### 2c. JWT Auto-Reauthentication (Integration Test)

Verifies that auto-reauthentication works when the token expires.

```rust
#[test]
fn spec_jwt_auto_reauthenticate_on_401() {
    // 1. Make an API request with a valid token
    // 2. Replace the token with an invalid value
    // 3. Confirm that the API request receives a 401,
    //    auto-reauthentication is performed, and
    //    the request ultimately succeeds
}
```

### Layer 3: Configuration Priority Conformance

Verification against 05-configuration.md.

```rust
#[test]
fn spec_config_priority_cli_over_env() {
    // Set WAZUH_API_URL via environment variable,
    // and specify a different value with the --api-url CLI option
    // Confirm that the CLI option value is used
}

#[test]
fn spec_config_priority_env_over_default() {
    // Set WAZUH_API_URL via environment variable,
    // and confirm that the environment variable value is used
    // instead of the default value (https://localhost:55000)
}
```

### Layer 4: Error Handling Conformance

Verification against 04-error-handling.md.

#### 4a. Exit Code Verification

```rust
#[test]
fn spec_exit_code_0_on_success() {
    // Confirm that exit code 0 is returned on a successful API response
}

#[test]
fn spec_exit_code_1_on_api_error() {
    // Confirm that exit code 1 is returned on 401, 403, 404, 500, etc. responses
}

#[test]
fn spec_exit_code_2_on_cli_input_error() {
    // Confirm that exit code 2 is returned for an invalid subcommand
    let status = Command::new("wazuh-cli")
        .arg("nonexistent-command")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn spec_exit_code_3_on_partial_success() {
    // Confirm that exit code 3 is returned on an error: 2 response
}
```

#### 4b. Error Output Destination Verification

```rust
#[test]
fn spec_errors_go_to_stderr() {
    // Confirm that errors are output to stderr and stdout is empty
    let output = Command::new("wazuh-cli")
        .arg("nonexistent-command")
        .output()
        .unwrap();
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
```

### Layer 5: Project Structure Conformance

Verification against 06-project-structure.md.

```bash
#!/bin/bash
# scripts/check_project_structure.sh
# Verifies that files and directories defined in the specification exist

EXPECTED_FILES=(
    "src/main.rs"
    "src/cli/mod.rs"
    "src/client/mod.rs"
    "src/client/auth.rs"
    "src/client/tls.rs"
    "src/api/mod.rs"
    "src/config.rs"
    "src/output.rs"
    "src/error.rs"
)

MISSING=0
for f in "${EXPECTED_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "MISSING: $f"
        MISSING=$((MISSING + 1))
    fi
done

if [ $MISSING -eq 0 ]; then
    echo "All expected files exist."
else
    echo "$MISSING files missing."
    exit 1
fi
```

### Layer 6: API Endpoint Behavioral Conformance (Integration)

Verifies that each CLI command defined in 03-api-endpoints.md sends requests with the correct HTTP method and path to the corresponding API endpoint.

Method: Provide a request-recording mode in `WazuhClient` that records request details without sending actual HTTP requests, and verify the method, path, and parameters.

```rust
/// A test wrapper for WazuhClient.
/// Records request contents without sending actual HTTP requests.
struct RequestRecorder {
    requests: Vec<RecordedRequest>,
}

struct RecordedRequest {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    body: Option<serde_json::Value>,
}

#[test]
fn spec_agent_list_calls_get_agents() {
    let recorder = RequestRecorder::new();
    // Execute the agent list command
    // Confirm that the request recorded in recorder is GET /agents
    let req = &recorder.requests[0];
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/agents");
}
```

## Verification Execution Timing

| Phase | Verifications to Execute |
|---|---|
| CI (always) | Layers 1a, 1b, 4b, 5 (no binary build required, or verifiable with help output only) |
| `cargo test` | Layers 1, 2a, 3, 4, 6 (mock-based) |
| `cargo test --test integration` | Layers 2b, 2c (requires docker-compose) |
| Pre-release | All layers |

## Handling Specification Changes

When a specification document is changed, the corresponding conformance tests must be updated at the same time. During PR reviews, the correspondence between specification changes and test changes is verified.

Since the specification documents use machine-extractable formats (Markdown tables, code blocks), it is possible to extend this into a system that auto-generates test cases from the specifications.
