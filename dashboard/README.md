# OpsPilot dashboard v1.0.0

This component contains the React NOC console, the loopback Python telemetry
sidecar, prebuilt frontend assets, the systemd service, and safe install/upgrade
scripts.

## Safety boundaries

- The telemetry sidecar listens on `127.0.0.1:3100`.
- Nginx is the only public listener for the dashboard.
- Diagnostics are selected from 172 fixed read-only commands and run with
  `shell=False`.
- Incident integration defaults to `draft`.
- Credentials are stored in `/etc/opspilot-dashboard/integrations.env` with
  root-only permissions.
- Deployment validates checksums, services, Nginx, and listener exposure and
  creates a rollback backup before changing the VM.

## Build

```bash
cd source
npm ci
npm run build
```

Copy the generated `dist/index.html`, `dist/assets/dashboard.js`, and
`dist/assets/dashboard.css` into `files/`, then regenerate `CHECKSUMS.sha256`.

The Resource activity panel in `source/src/components/ResourceActivityCharts.tsx`
uses Recharts area charts. Its synchronized hover
tracker, exact timestamp tooltips, explicit axes, and `15m` through `15d`
allowlist depend on the timestamps returned by the bundled telemetry sidecar.

## Deploy

```bash
chmod +x deploy.sh install.sh upgrade.sh configure-integrations.sh
./deploy.sh
./configure-integrations.sh
```

Run as the normal VM user. Do not run the complete deployment with sudo.

## Verify

```bash
systemctl status opspilot-dashboard-agent.service --no-pager
curl -sS http://127.0.0.1:3100/healthz | python3 -m json.tool
curl -sS http://127.0.0.1/opspilot/api/v1/dashboard | python3 -m json.tool
sudo ss -lntp '( sport = :80 or sport = :3000 or sport = :3100 )'
```

This remains a single-VM PoC. Add HTTPS, authentication, RBAC, centralized
inventory, secret-manager integration, and high availability before production.

## OpsPilot AI provider

The v1.0 backend works in two modes:

- `deterministic_fallback` is the default and requires no external key. It
  performs threshold detection, fixed command routing, structured evidence,
  and local linear-regression forecasting.
- `openai_responses` uses strict JSON Schema output with the model named by
  `OPSPILOT_AI_MODEL` (default `gpt-5.6-sol`) when
  `OPSPILOT_AI_API_KEY` is configured.

Configure the optional provider without changing Jira or Chat settings:

```bash
./configure-ai.sh
```

Remediation defaults to `draft`. The UI can prepare a one-time confirmation
and display the exact fixed command, but state-changing execution remains
locked until `OPSPILOT_REMEDIATION_MODE=enabled`. Privileged service restarts
remain blocked unless a separate reviewed broker is installed.
