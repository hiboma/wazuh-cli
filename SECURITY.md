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

This project employs the following supply chain security measures:

- All GitHub Actions are pinned by commit SHA
- Build provenance attestation (SLSA) for release artifacts
- SHA256 checksums for all release artifacts
- Automated dependency updates via Dependabot
- License and vulnerability scanning via cargo-deny
- OpenSSF Scorecard monitoring
