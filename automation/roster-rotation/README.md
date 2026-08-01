# OpsPilot automatic roster rotation v1.0.0

This add-on converts a validated three-shift schedule into the current on-call
CSV consumed by OpsPilot.

| Shift | IST time | Example primary |
| --- | ---: | --- |
| Morning (`M`) | 06:00–14:00 | Morning Engineer |
| Evening (`E`) | 14:00–22:00 | Evening Engineer |
| Night (`N`) | 22:00–06:00 | Night Engineer |

The end time is exclusive. All calculations use `Asia/Kolkata`, regardless of
the VM timezone.

## Safety

- Installation requires `draft` mode.
- The timer has no network access and runs as the unprivileged `opspilot` user.
- Atomic file replacement and a process lock protect the active roster.
- The schedule must cover every minute exactly once without gaps or overlaps.
- Validation never creates a Jira issue or sends a Chat message.

Replace the example engineer names in `files/roster-schedule.csv` only in the
private deployment copy.

```bash
./verify.sh
./install.sh
```

Boundary test without changing the live roster:

```bash
/usr/local/libexec/opspilot-roster-rotation \
  --at 2026-08-01T14:00:00 \
  --dry-run
```
