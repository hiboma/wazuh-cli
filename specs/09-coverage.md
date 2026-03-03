# 09: Test Coverage

## Overview

This document defines the measurement policy and targets for test coverage.

## Tools

`cargo-llvm-cov` is used to measure line coverage.

```bash
# Unit test coverage (summary)
cargo llvm-cov --lib --summary-only

# Unit test coverage (detailed)
cargo llvm-cov --lib --text

# HTML report generation
cargo llvm-cov --lib --html --open

# All tests (including CLI conformance tests) coverage
cargo llvm-cov --summary-only
```

## Coverage Targets and Exclusions

### Targets

Coverage measured by unit tests (`cargo llvm-cov --lib`) is used as the primary metric.

### Exclusion Policy

The following code is excluded from coverage measurement. Reasons are provided alongside each entry.

| Target | Reason for Exclusion |
|---|---|
| run functions in `api/*.rs` | Only delegates to WazuhClient and contains no logic, so it is verified by integration tests |
| `client/auth.rs` | Requires actual HTTP communication, so it is verified by integration tests |
| HTTP method functions in `client/mod.rs` | Requires actual HTTP communication, so it is verified by integration tests |

Code excluded from coverage measurement is covered by integration tests (`cargo test -- --ignored`).

### Code to Cover Thoroughly

The following code maintains high coverage through unit tests.

| Module | Target | Reason |
|---|---|---|
| `config.rs` | 90% or above | Configuration resolution logic has many branches and is prone to bugs |
| `output.rs` | 90% or above | Accuracy of exit codes is important |
| `client/tls.rs` | 50% or above | Verifies both the normal path and error path of TLS client construction |

## Coverage Targets

| Scope | Line Coverage Target |
|---|---|
| `config.rs` | 90% or above |
| `output.rs` | 90% or above |
| `client/tls.rs` | 50% or above (normal path only) |
| Overall (`--lib`) | No target is set as it is not a meaningful metric |

Overall coverage will be low because api/* and client/* depend on HTTP communication, but this is a design constraint. Introducing unnatural mock layers to increase coverage numbers is avoided.

## Measurement in CI

```bash
# Command to run in CI
cargo llvm-cov --lib --summary-only --fail-under-lines 40 -- --test-threads=1
```

`--fail-under-lines` causes the CI to fail when coverage falls below the threshold. The threshold is set at a level that is guaranteed by the tests for config.rs and output.rs.

Tests are run serially with `--test-threads=1` because some tests manipulate environment variables. In Rust 2024 edition, `std::env::set_var` / `std::env::remove_var` are unsafe, and environment variable conflicts occur during parallel execution.

## Coverage Improvement Policy

When coverage is low, the following steps are taken in order.

1. Check whether the code under test contains logic (branching, conversion, validation).
2. Add tests for code that contains logic.
3. Leave code that contains no logic (simple delegation to the API) to integration tests.
4. When refactoring code for testability, do so within a scope that does not require specification changes.
