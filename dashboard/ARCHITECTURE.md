# OpsPilot v0.9 implementation map

## 1. Secure diagnostic execution

Backend: `files/opspilot_dashboard_agent.py`

- `ALLOWED_COMMANDS` contains exactly 171 reviewed read-only command strings.
- `run_allowed_command()` rejects anything that is not an exact allowlist match.
- Arguments are converted to an argv list and executed with
  `subprocess.run(..., shell=False)`.
- The collector runs as the unprivileged `opspilot` account on
  `127.0.0.1:3100`.
- Every execution has an eight-second timeout and a 64 KiB combined-output
  limit.
- Results expose `stdout`, `stderr`, `exit_code`, `duration_ms`, truncation
  state, and a UTC evidence timestamp.
- Nginx exposes the same-origin `/opspilot/api/v1/dashboard` route; arbitrary
  shell, sudo, mutation, background jobs, and user-supplied arguments remain
  unavailable.

Frontend: `source/src/App.tsx`

- `executeApprovedCommand()` is the only browser command client.
- `CommandWorkspace` places the terminal result directly beneath the selected
  diagnostics row.
- The inline terminal keeps stdout and stderr visually separate and retains a
  link to the larger evidence dialog.

## 2. Historical metric ranges

Backend: `MetricStore`, `metric_sampler()`, and `RANGE_CONFIG` in
`files/opspilot_dashboard_agent.py`.

- Samples are written every five seconds to a SQLite WAL database in the
  systemd-managed state directory.
- Data is retained for 24 hours.
- Only `15m`, `30m`, `1h`, `3h`, and `6h` are accepted.
- Each range has a fixed server-side aggregation step, preventing expensive or
  attacker-controlled queries.
- `GET /api/v1/dashboard?range=30m` returns `history.range`,
  `history.step_seconds`, and the exact bucketed samples.

Frontend: `HistoryRange`, `RangeSelector`, and the history-loading effect in
`source/src/App.tsx`.

- Changing the interval passes the selected value to the backend.
- The chart rerenders from the returned historical series, updates its axis,
  and refreshes the selected range every five seconds.

## 3. Living interface components

React components in `source/src/App.tsx`:

- `MetricHardwareIcon` — animated 3D microchip/hardware SVG.
- `FluentMetricCard` — pointer-tracked border spotlight and elevated hover.
- `DualClockHeader` — live UTC and IST clocks.
- `ServerRack` — physical rack SVG with independent green/blue LEDs.
- `PolarBear` — sitting, breathing, snacking, head-turning Ask AI companion.
- `HealthCore` — radar sweep, orbital core, and animated EKG trace.

Motion, theme, responsive, reduced-motion, and terminal styles live in
`source/src/styles.css`. The prebuilt equivalents installed on the VM are
`files/dashboard.js` and `files/dashboard.css`.

## 4. Production adaptation

`MetricStore` is intentionally an adapter boundary. A Prometheus deployment
can translate `HistoryRange` into a fixed `query_range` start/end/step request;
a Zabbix deployment can translate it into fixed `time_from`/`time_till`
history queries. Keep the same five-value range allowlist and never pass an
unvalidated query expression from the browser.

## 5. Incident integration boundary

- `integration_status()` returns non-secret Jira, Chat, Meet, and roster state.
- `prepare_incident()` builds an evidence-rich draft from server-side telemetry;
  it never accepts a browser-supplied host identity or arbitrary Jira fields.
- `dispatch_incident()` is disabled unless the VM is explicitly placed in
  `live` mode, requires a separate action token and `confirm=true`, and stores a
  persistent idempotency record before a retry can create duplicates.
- Jira and Chat destinations come only from root-managed environment values;
  request payloads cannot supply URLs, preventing SSRF through the UI.
- Jira Cloud v3 uses Atlassian Document Format for the description. Google Chat
  receives a one-way alert only after Jira returns an issue key.
- The roster reader accepts a read-only local CSV sync or a directly readable
  Google Sheet CSV export. It will not silently assign the first row; a roster
  row must be explicitly marked active.
