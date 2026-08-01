# Jira Business Unit migration v1.0.1

This migration updates an existing OpsPilot v0.9 backend when Jira requires a
single-select or multi-select Business Unit custom field during issue creation.

The field ID is read from
`OPSPILOT_JIRA_BUSINESS_UNIT_FIELD_ID`; no organization-specific field ID is
committed. The migration queries Jira create metadata, displays only permitted
options, and asks the operator to select one.

Safety behavior:

- forces `draft` mode;
- disables the CPU alert timer;
- performs Jira `GET` metadata requests only;
- creates a backup under `/var/backups/opspilot-dashboard/`;
- rolls back the backend and configuration if health validation fails;
- leaves external writes disabled.

```bash
./verify.sh
./install.sh
```

Run as the normal VM user. Do not enable live mode until the read-only
integration validation succeeds.
