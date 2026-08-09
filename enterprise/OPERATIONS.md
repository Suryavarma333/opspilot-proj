# Operations runbook

## Health

- `GET /healthz`: process is alive.
- `GET /readyz`: database can initialize.
- API journal: accepted alert ID, insert/dedup result, job ID.
- Worker journal: lease owner, job result, sanitized failures.

## Backup

Use SQLite's online backup API or `sqlite3 .backup` while the service is running; do not copy only
the main database while WAL writes are active. Back up evidence and the database as one retention
set. Periodically perform a restore test into an isolated directory.

## Failure handling

| Failure | Expected behavior | Operator action |
|---|---|---|
| Collector command missing | Partial evidence plus error | Install tool or accept documented gap |
| Collector timeout | Process group terminated; partial evidence | Inspect host load and command budget |
| BharatRouter unavailable | Deterministic fallback RCA | Retry analysis only if policy permits |
| Strict schema unsupported | Retry in JSON-object mode; validate locally | Choose a schema-capable model/route |
| Jira definite 4xx | Delivery `failed` | Correct config, then explicitly retry phase |
| Jira timeout | Search by event label; else `unknown` | Read-only verify Jira before retry |
| Slack timeout | Delivery `unknown` | Check channel manually before explicit retry |
| Worker crash | Lease reclaimed after expiry | Confirm old worker is dead; inspect attempt count |
| DB full/corrupt | Processing stops | Preserve files, restore tested backup, investigate disk |

## Controlled synthetic validation

Run only on an approved test VM and use an explicit duration:

```bash
stress-ng --cpu 2 --timeout 90s --metrics-brief
```

Expected evidence:

- exact `/usr/bin/stress-ng ...` argv in `/proc` snapshot;
- sampled CPU near the top of the process list;
- deterministic `known-tool:stress-ng` finding;
- final classification `manually_injected_load`;
- exact redacted command in Summary and Evidence;
- no automatic service restart.

## Promotion gates

1. Unit/static tests pass.
2. Duplicate alert replay produces one job and one delivery.
3. Five firing/resolved cycles produce one flapping assessment with `complete_cycles=5`.
4. Provider timeout produces a valid fallback RCA.
5. Jira and Slack timeout drills create `unknown`, not duplicate posts.
6. Secrets do not appear in evidence, journal, Jira, or Slack.
7. A non-allowlisted service remediation is denied.
8. An expired or actor-mismatched approval is denied.
9. Host CPU/memory overhead remains within the agreed telemetry budget.
10. Rollback and disable procedures are exercised.

