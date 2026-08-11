-- OpsPilot schema v2: SNMP-managed network device inventory.
-- Applied automatically by IncidentLedger.initialize() to the existing
-- OPSPILOT_STATE_DB SQLite file. SNMP credentials are Fernet ciphertext.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS network_devices (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL COLLATE NOCASE UNIQUE,
    device_name TEXT NOT NULL,
    snmp_version TEXT NOT NULL CHECK(snmp_version IN ('v2c', 'v3')),
    snmp_port INTEGER NOT NULL DEFAULT 161 CHECK(snmp_port BETWEEN 1 AND 65535),
    snmp_security_level TEXT NOT NULL
        CHECK(snmp_security_level IN ('community', 'noAuthNoPriv', 'authNoPriv', 'authPriv')),
    credentials_encrypted BLOB NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK(status IN ('UNKNOWN', 'UP', 'DOWN')),
    ping_latency_ms REAL,
    snmp_status TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK(snmp_status IN ('UNKNOWN', 'UP', 'DOWN')),
    sys_name TEXT,
    sys_description TEXT,
    sys_object_id TEXT,
    uptime_seconds INTEGER,
    interface_total INTEGER,
    interface_up INTEGER,
    interface_down INTEGER,
    interface_unknown INTEGER,
    last_polled_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_network_devices_poll
    ON network_devices(enabled, hostname);
CREATE INDEX IF NOT EXISTS idx_network_devices_status
    ON network_devices(status, snmp_status);
