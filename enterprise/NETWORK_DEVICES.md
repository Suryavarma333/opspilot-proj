# OpsPilot Network Devices

This module adds switch and router inventory to the existing OpsPilot Enterprise service. It uses
the same SQLite file configured by `OPSPILOT_STATE_DB`; no second database is created.

## Files

- `src/opspilot_enterprise/devices.py`: validation, encrypted credential storage, and SQLite CRUD.
- `src/opspilot_enterprise/devices_api.py`: `/api/devices` FastAPI router.
- `src/opspilot_enterprise/snmp_worker.py`: asynchronous ICMP and read-only SNMP polling.
- `sql/002_network_devices.sql`: standalone schema reference; the ledger applies the same schema.
- `deploy/systemd/opspilot-enterprise-snmp-poller.service`: hardened worker service.
- `deploy/nginx/opspilot-network-devices.conf`: same-origin page/API routing snippet.
- `../dashboard/files/network_devices.html`: inventory page.
- `../dashboard/files/network_devices.css`: page theme and responsive layout.
- `../dashboard/files/network_devices.js`: browser CRUD and live refresh logic.

## Python dependencies

The versions validated for this module are PySNMP 7.1.28 and cryptography 50.0.0:

```bash
/opt/opspilot-enterprise/venv/bin/python -m pip install --require-virtualenv \
    "pysnmp==7.1.28" \
    "cryptography==50.0.0"
```

Installing the project from `pyproject.toml` also installs compatible versions:

```bash
/opt/opspilot-enterprise/venv/bin/python -m pip install --require-virtualenv .
```

## Credential encryption

Generate the Fernet key once on the VM:

```bash
/opt/opspilot-enterprise/venv/bin/python -c \
    'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Store the output only in `/etc/opspilot-enterprise/opspilot.env`:

```text
OPSPILOT_SNMP_CREDENTIAL_KEY=<generated-key>
OPSPILOT_SNMP_POLL_SECONDS=30
OPSPILOT_SNMP_TIMEOUT_SECONDS=2
OPSPILOT_SNMP_RETRIES=1
OPSPILOT_SNMP_MAX_CONCURRENCY=20
OPSPILOT_ICMP_TIMEOUT_SECONDS=2
```

Keep that file owned by `root:opspilot` with mode `0600`. Back up the key separately from the
database. Losing it makes stored SNMP credentials unrecoverable. Never commit it to Git.

The API accepts a community string for SNMP v2c. SNMPv3 does not use community strings, so the
v3 form uses username, security level, authentication protocol/password, and privacy
protocol/password. Secrets are encrypted before insertion and are never returned by GET.

## API

```text
POST   /api/devices              Add a device (201)
GET    /api/devices              List devices and non-secret configuration (200)
PATCH  /api/devices/{device_id}  Rename, pause, or enable monitoring (200)
DELETE /api/devices/{device_id}  Remove a device (204)
```

Example SNMP v2c request:

```json
{
  "hostname": "10.20.30.40",
  "device_name": "Core Switch 01",
  "snmp_version": "v2c",
  "snmp_port": 161,
  "community": "read-only-community"
}
```

Example SNMPv3 request:

```json
{
  "hostname": "core-router.example.net",
  "device_name": "Core Router 01",
  "snmp_version": "v3",
  "snmp_port": 161,
  "snmpv3_username": "opspilot-monitor",
  "snmpv3_security_level": "authPriv",
  "snmpv3_auth_protocol": "SHA256",
  "snmpv3_auth_password": "replace-on-the-wire",
  "snmpv3_priv_protocol": "AES128",
  "snmpv3_priv_password": "replace-on-the-wire"
}
```

## Polling behavior

Each cycle reads enabled devices, limits concurrency, and performs ICMP and SNMP in parallel. The
displayed `status` is `UP` or `DOWN` from ICMP, as required. `snmp_status` is independent, so a
device that blocks ping but answers SNMP is shown as ICMP down / SNMP up rather than losing the
useful SNMP evidence.

The worker reads only standard MIB-2 objects:

- `sysDescr.0`, `sysObjectID.0`, `sysUpTime.0`, `sysName.0`, and `ifNumber.0`.
- `ifOperStatus` with a bounded GETBULK walk (maximum 512 rows).

It never sends SNMP SET requests. Run one diagnostic cycle before enabling the service:

```bash
sudo -u opspilot /opt/opspilot-enterprise/venv/bin/opspilot-snmp-poller --once
```

## Web routing

Install the three network page files into the existing dashboard paths:

```text
/var/www/opspilot-dashboard/network_devices.html
/var/www/opspilot-dashboard/assets/network_devices.css
/var/www/opspilot-dashboard/assets/network_devices.js
```

Merge the locations from `deploy/nginx/opspilot-network-devices.conf` into the existing private
OpsPilot `server` block, validate with `nginx -t`, and reload nginx. The page will be available at:

```text
http://<opspilot-host>/opspilot/network-devices/
```

Keep the Enterprise API on loopback (`127.0.0.1:8088`). Do not expose UDP/161 or the API listener
to the public Internet. Allow outbound UDP/161 and ICMP only from the OpsPilot VM to managed
device subnets. The current private-LAN nginx boundary is not a replacement for user
authentication if the portal is later exposed beyond the trusted network.
