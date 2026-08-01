# Security policy

OpsPilot executes diagnostics and can create external incidents, so changes to
command execution, authentication, network destinations, and live-mode controls
require careful review.

## Supported state

The repository currently represents a proof of concept. Security fixes are
applied to the latest `main` branch only.

## Reporting a vulnerability

Use a private GitHub security advisory for this repository when available. Do
not publish credentials, webhook URLs, internal addresses, customer data, or a
working exploit in a public issue.

## Non-negotiable controls

- Keep the telemetry listener on `127.0.0.1`.
- Keep diagnostic execution exact-match and `shell=False`.
- Store integration credentials outside Git with root-only permissions.
- Default integrations to `draft` and require explicit confirmation for live writes.
- Preserve idempotency so retries cannot create duplicate Jira incidents.
- Validate and back up configuration before changing systemd or Nginx state.
