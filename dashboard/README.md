# OpsPilot dashboard v0.9.0

This component contains the React NOC console, the loopback Python telemetry
sidecar, prebuilt frontend assets, the systemd service, and safe install/upgrade
scripts.

## Safety boundaries

- The telemetry sidecar listens on `127.0.0.1:3100`.
- Nginx is the only public listener for the dashboard.
- Diagnostics are selected from 171 fixed read-only commands and run with
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
