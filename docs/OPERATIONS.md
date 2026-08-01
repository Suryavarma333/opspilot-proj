# Operations runbook

## Service health

```bash
systemctl status opspilot-dashboard-agent.service --no-pager
curl -sS http://127.0.0.1:3100/healthz | python3 -m json.tool
sudo ss -lntp '( sport = :80 or sport = :3000 or sport = :3100 )'
```

Expected exposure:

- Nginx listens on port 80.
- The base API listens on `127.0.0.1:3000`.
- The telemetry sidecar listens on `127.0.0.1:3100`.

## Integration state

```bash
curl -sS http://127.0.0.1:3100/api/v1/integrations/status \
  | python3 -m json.tool
```

Use `draft` for installation, troubleshooting, and validation. `live` permits
external writes and must be temporary during a controlled PoC unless a formal
production approval exists.

## CPU incident state machine

| Condition | State change |
| --- | --- |
| CPU >= 90% for four checks | Dispatch one Jira incident |
| CPU remains high | Keep `incident_open=true`; suppress duplicates |
| CPU < 80% for three checks | Clear the incident state and re-arm |
| Jira succeeds, Chat fails | Record Jira key and partial result; do not create another Jira |

Useful commands:

```bash
sudo journalctl -u opspilot-cpu-alert.service -n 100 --no-pager
sudo journalctl -fu opspilot-cpu-alert.service
cd automation/cpu-alert
./status.sh
./disable-live.sh
```

`Deactivated successfully` is normal for the timer-triggered one-shot CPU
service. A line containing `cpu_alert_dispatched jira_key=...` proves Jira
creation even if `chat_status="failed"` and the combined HTTP result is 502.

## Roster rotation

```bash
systemctl list-timers opspilot-roster-rotation.timer --no-pager
sudo journalctl -u opspilot-roster-rotation.service -n 50 --no-pager
sudo /usr/local/libexec/opspilot-roster-rotation --dry-run
```

The schedule must cover every minute exactly once. Boundaries use
`Asia/Kolkata` regardless of the VM timezone.

## Safe incident response

1. Disable live mode before changing configuration.
2. Capture service status and bounded journal evidence.
3. Verify the Jira key in the local idempotency ledger before retrying.
4. Treat Jira success plus Chat failure as partial success, not a failed Jira.
5. Re-enable live mode only after read-only integration validation passes.
