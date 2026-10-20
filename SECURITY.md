# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub Security Advisories](https://github.com/hiboma/wazuh-cli/security/advisories/new) to report the vulnerability privately.

### What to include

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 3 business days
- **Initial assessment**: within 7 business days
- **Fix and disclosure**: coordinated with the reporter

## Security Measures

### Credential protection contract

- API traffic requires HTTPS. Redirects are disabled. Base URL userinfo,
  query, and fragment are rejected without displaying their contents.
- TLS verification can be disabled only for a literal loopback IP address,
  with a warning on each invocation. Production deployments must use a
  trusted CA. Local proxies and other users on the host remain trusted
  when verification is disabled.
- Unix configuration files must be regular, owned by the effective user,
  have one hard link, and not be group/world writable. The opened file
  descriptor is checked before reading, and final symlinks are rejected.
  Protect parent directories as well. Processes running as the same user
  can still replace that user's configuration and are outside this boundary.
  Configuration files are rejected on non-Unix platforms until equivalent
  ownership/ACL checks are implemented; use CLI/environment settings there.
- Passwords and session tokens use hidden prompts, stdin, or checked
  private files. Never pass actual secrets to removed password/session
  argument options. Their hidden rejection parsers remain during 0.x to
  avoid reflecting values in diagnostics; remove them in 1.0 only with
  equivalent non-reflecting parse errors. Rejection cannot erase argv from
  shell history, process monitors, or exec-time audit records.
- `WAZUH_API_PASSWORD` is captured and removed before CLI parsing, which
  prevents inheritance by later child processes, not initial OS/EDR capture.
  Library callers own their process environment: `from_cli_and_env` reads
  without mutating it to avoid unsafe changes in multithreaded hosts. Prefer
  `from_cli_env_store_and_file` with a caller-owned zeroizing password.
- Usernames are public identifiers, not credentials: they may appear in
  argv, environment, Debug and API responses. Password prompts do not
  interpolate usernames or user IDs. Do not use sensitive personal data as
  a username if these channels are logged.
- Error bodies and request URLs are not printed. Terminal JSON output
  masks credential fields even with `--raw`. Use `--secret-output-file`
  for newly issued keys/tokens needed by subsequent commands. This option
  creates a new 0600 file on Unix and fails closed on other platforms.
  The API and proxies must redact Authorization/request bodies and disable
  or redact `/logtest/sessions/*` access logging: the upstream deletion API
  requires its token in the path, which the CLI cannot change.
- Password, JWT and input buffers use zeroizing ownership where possible.
  TLS/HTTP/JSON libraries, kernel buffers and allocators can retain derived
  copies. `Drop` does not run on abort or forced termination. Disable core
  dumps in production (`ulimit -c 0` on Unix), restrict debugger/process
  access, and do not claim protection from same-user memory inspection.
- Responses receive exact-match redaction for known sent secrets. A
  compromised server can encode or transform a secret; it is not treated
  as a safe diagnostic source or an untrusted peer that may receive secrets.

### Release validation

CI and tag releases run the same security checks on their checked-out
commit: rustfmt, Clippy, all-target tests, cargo-deny and the coverage gate.
Release builds and publication depend on these checks succeeding.

This project employs the following supply chain security measures:

- All GitHub Actions are pinned by commit SHA
- Build provenance attestation (SLSA) for release artifacts
- SHA256 checksums for all release artifacts
- Automated dependency updates via Dependabot
- License and vulnerability scanning via cargo-deny
- OpenSSF Scorecard monitoring
