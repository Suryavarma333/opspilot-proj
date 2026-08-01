# OpsPilot automatic Jira CPU alert controller v1.0.1

This add-on completes the automatic path missing from OpsPilot v0.9.0:

1. Sample total VM CPU every 20 seconds.
2. Require CPU utilization at or above 90% for four consecutive samples
   (approximately 60 seconds from first breach to dispatch).
3. Ask the existing OpsPilot loopback API to create one configured Jira incident.
4. Post the resulting Jira link to the configured Google Chat space.
5. Suppress duplicates until CPU remains below 80% for three samples.

The installer operates in draft mode and performs no external write. Live mode
requires the separate `enable-live.sh` confirmation. Installation also rotates
the previously exposed action token without displaying its replacement.

Version 1.0.1 fixes installation when `integrations.env` is protected with
root-only directory and file permissions. It also blocks `enable-live.sh` with
a clear message if the controller has not been installed, and makes
`status.sh` report a missing state file without a Python traceback.

## Install

```bash
chmod +x install.sh enable-live.sh disable-live.sh test-high-cpu.sh status.sh verify.sh
./verify.sh
./install.sh
```

## Enable one controlled live test

```bash
./enable-live.sh
```

Type `ENABLE-LIVE` at the prompt, then open a second SSH session and watch:

```bash
sudo journalctl -fu opspilot-cpu-alert.service
```

In the first SSH session run:

```bash
./test-high-cpu.sh
```

Expected event:

```text
cpu_alert_dispatched jira_key="CORE-..." chat_status="posted" http_status=200
```

Only one Jira is created while the CPU incident remains open. The test load
stops automatically after 150 seconds. Disable external writes afterward with:

```bash
./disable-live.sh
```

## Logs

Show existing controller logs and return immediately:

```bash
sudo journalctl -u opspilot-cpu-alert.service -n 50 --no-pager
```

Follow future events continuously (exit with `Ctrl+C`):

```bash
sudo journalctl -fu opspilot-cpu-alert.service
```
