# Security Policy

## Supported version

This repository currently supports the `main` branch.

## Reporting a vulnerability

Please avoid filing public issues for undisclosed vulnerabilities that could materially increase exploitation risk.

Instead, send a private report with:

- affected file(s) or workflow(s)
- impact summary
- reproduction notes without live secrets
- suggested remediation if known

## Repository security baseline

- read-only default GitHub Actions permissions
- no committed runtime secrets
- runtime dependency count: 0
- security findings tracked in `docs/security-audit.md`

## Secure contribution expectations

- never commit credentials, access tokens, or private keys
- avoid `pull_request_target` unless strictly required and reviewed
- prefer pinned third-party actions and explicit permissions blocks
- do not add remote script execution in CI without strong justification and review
