# Deployment guide

## Prerequisites

- Ubuntu 22.04 or a compatible systemd-based Linux VM
- Python 3.10 or newer
- Nginx, curl, systemd, and sudo access
- An existing loopback OpsPilot API on `127.0.0.1:3000`
- Node.js 22+ only when rebuilding the React frontend
- A dedicated Jira integration account and a Google Chat webhook

Do not install on a production server until the PoC has passed in an isolated
test VM. Keep all external integrations in `draft` during installation.

## 1. Verify the repository

```bash
./scripts/verify-all.sh
```

To rebuild the frontend:

```bash
cd dashboard/source
npm ci
npm run build
cp dist/index.html ../files/index.html
cp dist/assets/dashboard.js ../files/dashboard.js
cp dist/assets/dashboard.css ../files/dashboard.css
```

Recalculate `dashboard/CHECKSUMS.sha256` after changing deployable files.

## 2. Deploy the dashboard

```bash
cd dashboard
chmod +x deploy.sh install.sh upgrade.sh configure-integrations.sh
./deploy.sh
```

Run the script as the normal VM user. It requests sudo only for protected
operations. It validates checksums, Python syntax, Nginx, systemd services, and
loopback listeners. A failed change triggers rollback.

## 3. Configure integrations

```bash
./configure-integrations.sh
```

Enter real secrets only at the hidden prompts on the VM. The generated file is
`/etc/opspilot-dashboard/integrations.env` with root-only permissions. The mode
remains `draft`.

Confirm the safe state:

```bash
curl -sS http://127.0.0.1:3100/api/v1/integrations/status \
  | python3 -m json.tool
```

## 4. Configure on-call rotation

Edit `automation/roster-rotation/files/roster-schedule.csv` before installing.
Use approved names and optional Chat user IDs only in the private deployment
copy; do not commit live roster data to a public repository.

```bash
cd automation/roster-rotation
./verify.sh
./install.sh
```

## 5. Configure the required Jira Business Unit field

Existing v0.9 deployments can use the migration to query Jira's create metadata
and select an allowed option without creating an issue:

```bash
cd maintenance/jira-business-unit-fix
./verify.sh
./install.sh
```

The migration forces `draft`, disables the CPU timer, creates a backup, patches
the backend, restarts it, and rolls back if health checks fail.

## 6. Install CPU automation

```bash
cd automation/cpu-alert
./verify.sh
./install.sh
```

Installation rotates the action token and keeps external writes disabled. Run
`./enable-live.sh` only for an approved controlled test. Run `./disable-live.sh`
immediately after collecting evidence.

## Rollback locations

Dashboard and migration backups are stored under:

```text
/var/backups/opspilot-dashboard/
```

Do not delete backups until the deployed version has passed health, UI,
integration-validation, timer, and recovery checks.
