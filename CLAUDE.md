# wazuh-cli

A CLI tool for the Wazuh REST API, implemented in Rust.

## Specs

Specifications are defined in `specs/`. Always refer to them before implementing or modifying features.

- `specs/00-overview.md` - Project overview, tech stack, resource categories
- `specs/01-authentication.md` - TLS (required) / mTLS (optional) / JWT authentication
- `specs/02-cli-design.md` - Command structure, global options, output formats
- `specs/03-api-endpoints.md` - API endpoint to CLI command mapping
- `specs/04-error-handling.md` - Error classification, exit codes (0/1/2/3)
- `specs/05-configuration.md` - Configuration priority (CLI > env vars > config file)
- `specs/06-project-structure.md` - Directory layout, module responsibilities, dependencies
- `specs/07-testing.md` - Test strategy (unit / integration / CLI)
- `specs/08-spec-conformance.md` - Spec conformance verification approach
- `specs/09-coverage.md` - Test coverage policy and targets

## Development guidelines

- Cover endpoints based on the OpenAPI specification (Wazuh API v4.x)
- Avoid using lesser-known crates
- Implement prototypes first, then plan tests
- Run integration tests against a Wazuh API instance via docker-compose
- Update specs/ documentation before changing specifications

## GitHub Actions security policy

Follow these rules when creating or modifying workflow files in `.github/workflows/`.

### Triggers

- Do not use `pull_request_target`. Use `pull_request` instead to prevent untrusted fork code from running with elevated privileges.

### Permissions

- Set `permissions: {}` at the workflow top level to deny all permissions by default.
- Grant the minimum required permissions at the job level (e.g., `contents: read` for build jobs, `contents: write` only for release creation).

### Action pinning

- Pin all third-party actions by full commit SHA, not by tag. Add a comment with the version tag for readability.
  ```yaml
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  ```

### Expression injection prevention

- Do not use `${{ }}` expressions directly in `run:` steps. Instead, pass values through `env:` and reference them as shell variables.
  ```yaml
  # Good
  env:
    BUILD_TARGET: ${{ matrix.target }}
  run: cargo build --release --target "${BUILD_TARGET}"

  # Bad
  run: cargo build --release --target ${{ matrix.target }}
  ```
- This applies even when the expression value is trusted (e.g., matrix values defined by the workflow author), to maintain a consistent security posture.

### Secrets

- Scope secrets to the specific job that needs them. Do not expose secrets to jobs that do not use them.
- Use a dedicated PAT (`secrets.TAP_GITHUB_TOKEN`) with the minimum required scope for cross-repository operations.

### Reference

- [oss-sec: hackerbot-claw campaign exploiting weak GitHub Actions configurations](https://seclists.org/oss-sec/2026/q1/246)

## Code style

- End files with a newline (POSIX compliance)
- Run `cargo fmt --check` and `cargo clippy -- -D warnings` before committing
- Use `--test-threads=1` for tests that manipulate environment variables
