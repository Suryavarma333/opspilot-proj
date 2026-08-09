# Security model

## Non-negotiable invariants

1. No `shell=True`, `bash -c`, `eval`, or executable model output.
2. Telemetry commands are internal fixed argument vectors and binaries resolve only from trusted
   system directories.
3. Alert data never becomes a command argument.
4. Router device IDs are URL-encoded and used only in a configured GET path.
5. Secrets use environment/configuration injection and are redacted from logs/evidence.
6. Evidence is redacted before the LLM, Jira, or Slack boundary.
7. The model has no functions/tools and cannot authorize remediation.
8. State-changing runbooks require an independent policy decision and audit record.
9. Unknown external-write outcomes are not blindly retried.
10. Every inbound mutation is authenticated over the exact raw body with a replay window.

## Threats addressed

- Prompt injection in logs, argv, interface descriptions, and historical text.
- Shell injection and path confusion.
- Duplicate incidents from webhook replay or worker retries.
- Duplicate external posts after timeouts.
- Secret leakage in telemetry and structured logs.
- Synthetic tests misclassified as organic failures.
- Model hallucination of commands, evidence, history, or completed actions.
- Arbitrary service restart through user/model-controlled parameters.

## Threats requiring deployment controls

- Root compromise of the monitored host.
- Kernel-level tampering with `/proc` or journals.
- Compromise of Jira, Slack, BharatRouter, or the network controller.
- Traffic interception when TLS verification is disabled by the environment.
- Database/evidence theft without encrypted storage.
- Malicious operator holding both webhook and approval secrets.
- Denial of service through excessive distinct valid alerts.

Use separate identities and secret scopes for inbound alerts, BharatRouter, Jira, Slack, router
read-only access, and remediation approvals. Rotate them independently.

## Recommended permissions

- API/worker user: read the required journal and `/proc` views; write only the state/evidence
  directory; no sudo.
- Router credential: read interfaces/counters only.
- Jira credential: browse/create/comment in one project only.
- Slack credential: one approved incident channel.
- Remediation executor: separate service, root only where systemd control requires it, with a
  service-name allowlist.

## Incident response for OpsPilot itself

If a secret may be exposed:

1. disable the affected service or egress;
2. revoke the specific credential;
3. preserve the ledger, journal, and evidence hashes;
4. search Jira/Slack/provider activity for unauthorized use;
5. rotate credentials and approval secrets independently;
6. validate configuration and run regression tests before re-enable;
7. document the control failure and prevention change.

