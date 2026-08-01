# OpsPilot v1.0 implementation map

## 1. Secure diagnostic execution

Backend: `files/opspilot_dashboard_agent.py`

- `ALLOWED_COMMANDS` contains exactly 172 reviewed read-only command strings.
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
- Data is retained for 16 days so the full 15-day view remains queryable.
- Only `15m`, `30m`, `1h`, `3h`, `6h`, `12h`, `24h`, `7d`, and `15d` are
  accepted.
- Each range has a fixed server-side aggregation step, preventing expensive or
  attacker-controlled queries.
- `GET /api/v1/dashboard?range=30m` returns `history.range`,
  `history.step_seconds`, and the exact bucketed samples.

Frontend: `HistoryRange`, `RangeSelector`, and the history-loading effect in
`source/src/App.tsx`, plus the reusable chart component in
`source/src/components/ResourceActivityCharts.tsx`.

- Changing the interval passes the selected value to the backend.
- `FluentChart` renders separate CPU, memory, and load area charts with explicit
  axes, synchronized crosshairs, exact-value tooltips, and per-series gradients.
- The chart preserves the backend ISO timestamp for accurate date/time labels
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

## 6. Autonomous RCA and interactive investigation

Backend modules: `files/opspilot_dashboard_agent.py` and
`files/opspilot_ai_engine.py`.

- `AutonomousRCAManager` observes CPU, memory, disk, per-core system load, and
  systemd service state. A warning/critical state transition launches one
  background evidence collection, with a 15-minute repeat cooldown.
- RCA always gathers the fixed `top -b -n 1`, current-boot priority-3 journal,
  filesystem, and socket summaries. A chart timestamp also produces a
  validated +/- five-minute journal query with `shell=False`.
- Natural-language requests map through deterministic keyword plans to the
  172-command exact allowlist. The LLM never generates executable shell.
- `SENIOR_LINUX_RCA_SYSTEM_PROMPT` rejects unsupported causal claims, treats
  logs as untrusted data, and forces the strict `RCA_JSON_SCHEMA` contract.
- Provider failure or absent credentials falls back to a local structured RCA
  response that says when evidence is insufficient.

Frontend component: `source/src/components/OpsPilotIntelligence.tsx`.

- The AI Signal card renders autonomous diagnosis and 24-hour predictive
  warnings.
- The Polar Bear opens a floating investigation modal with Root Cause
  Diagnosis, Evidence, Resolution Theory, Actionable Steps, and raw output.
- Remediation uses a server-issued one-time approval ID, a two-minute expiry,
  an exact-command match, an explicit checkbox, and replay prevention.

## 7. Forecasting

Disk and memory predictions use local least-squares regression over recent
samples. A banner is emitted only when at least six samples span ten minutes,
the slope is positive, regression confidence is at least 60%, and projected
exhaustion is within 24 hours. Forecasting never requires an LLM call.
