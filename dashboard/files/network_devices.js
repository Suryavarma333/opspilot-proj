"use strict";

const API_URL = "/opspilot/api/devices";
const state = { devices: [], loading: false, toastTimer: null };

const elements = {
  rows: document.querySelector("#device-rows"),
  tableWrap: document.querySelector("#table-wrap"),
  tableMessage: document.querySelector("#table-message"),
  emptyState: document.querySelector("#empty-state"),
  search: document.querySelector("#device-search"),
  refresh: document.querySelector("#refresh-devices"),
  total: document.querySelector("#summary-total"),
  up: document.querySelector("#summary-up"),
  down: document.querySelector("#summary-down"),
  snmp: document.querySelector("#summary-snmp"),
  dialog: document.querySelector("#device-dialog"),
  form: document.querySelector("#device-form"),
  formError: document.querySelector("#form-error"),
  save: document.querySelector("#save-device"),
  version: document.querySelector("#snmp-version"),
  v2Fields: document.querySelector("#v2c-fields"),
  v3Fields: document.querySelector("#v3-fields"),
  securityLevel: document.querySelector("#v3-security-level"),
  toast: document.querySelector("#toast"),
  sidebar: document.querySelector("#sidebar"),
  scrim: document.querySelector("#nav-scrim"),
};

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined && text !== null) item.textContent = String(text);
  return item;
}

function setVisible(item, visible) {
  item.hidden = !visible;
}

function formatError(payload, fallback) {
  if (!payload) return fallback;
  if (typeof payload.detail === "string") return payload.detail;
  if (Array.isArray(payload.detail)) {
    return payload.detail
      .map((entry) => entry.msg || "Invalid value")
      .filter((message, index, all) => all.indexOf(message) === index)
      .join("; ");
  }
  return fallback;
}

async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}) },
    ...options,
  });
  if (response.status === 204) return null;
  let payload = null;
  try { payload = await response.json(); } catch { payload = null; }
  if (!response.ok) throw new Error(formatError(payload, `Request failed with HTTP ${response.status}`));
  return payload;
}

function showToast(message, tone = "success") {
  window.clearTimeout(state.toastTimer);
  elements.toast.textContent = message;
  elements.toast.className = `toast${tone === "error" ? " error" : ""}`;
  setVisible(elements.toast, true);
  state.toastTimer = window.setTimeout(() => setVisible(elements.toast, false), 3600);
}

function formatUptime(seconds) {
  if (!Number.isFinite(seconds)) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatLastPoll(value) {
  if (!value) return { relative: "Not polled", absolute: "Waiting for the SNMP worker" };
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return { relative: "Unknown", absolute: value };
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  let relative;
  if (seconds < 10) relative = "Just now";
  else if (seconds < 60) relative = `${seconds}s ago`;
  else if (seconds < 3600) relative = `${Math.floor(seconds / 60)}m ago`;
  else if (seconds < 86400) relative = `${Math.floor(seconds / 3600)}h ago`;
  else relative = `${Math.floor(seconds / 86400)}d ago`;
  return { relative, absolute: date.toLocaleString() };
}

function statusPill(status, latency) {
  const normalized = ["UP", "DOWN"].includes(status) ? status.toLowerCase() : "unknown";
  const pill = node("span", `status-pill ${normalized}`);
  pill.append(node("i"), document.createTextNode(status || "UNKNOWN"));
  if (status === "UP" && Number.isFinite(latency)) pill.title = `ICMP latency ${latency.toFixed(1)} ms`;
  return pill;
}

function buildRow(device) {
  const row = node("tr", device.enabled ? "" : "row-paused");
  row.dataset.deviceId = device.id;

  const statusCell = node("td");
  statusCell.append(statusPill(device.enabled ? device.status : "UNKNOWN", device.ping_latency_ms));

  const deviceCell = node("td");
  const deviceName = node("span", "device-name");
  deviceName.append(node("strong", "", device.device_name));
  deviceName.append(node("small", "", device.sys_name || (device.enabled ? "Awaiting SNMP identity" : "Monitoring paused")));
  if (device.last_error) deviceName.title = device.last_error;
  deviceCell.append(deviceName);

  const addressCell = node("td", "address", device.hostname);

  const snmpCell = node("td");
  const snmp = node("span", "snmp-cell");
  snmp.append(node("span", "", `${device.snmp_version.toUpperCase()} · UDP ${device.snmp_port}`));
  const snmpStatus = device.enabled ? device.snmp_status.toLowerCase() : "unknown";
  const snmpHealth = node("span", `snmp-health ${snmpStatus}`);
  snmpHealth.append(node("i"), document.createTextNode(`SNMP ${device.enabled ? device.snmp_status : "PAUSED"}`));
  snmp.append(snmpHealth);
  snmpCell.append(snmp);

  const uptimeCell = node("td", device.uptime_seconds === null ? "muted" : "", formatUptime(device.uptime_seconds));

  const interfaceCell = node("td");
  if (Number.isFinite(device.interface_total)) {
    const interfaces = node("span", "interface-cell");
    interfaces.append(node("strong", "", `${device.interface_up || 0} / ${device.interface_total} up`));
    const track = node("span", "interface-track");
    const progress = node("i");
    progress.style.width = `${device.interface_total ? Math.round((device.interface_up || 0) * 100 / device.interface_total) : 0}%`;
    track.append(progress);
    interfaces.append(track);
    interfaceCell.append(interfaces);
  } else {
    interfaceCell.className = "muted";
    interfaceCell.textContent = "—";
  }

  const pollCell = node("td");
  const poll = formatLastPoll(device.last_polled_at);
  const lastPoll = node("span", "last-poll");
  lastPoll.append(node("strong", "", poll.relative), node("small", "", device.enabled ? "30s schedule" : "Paused"));
  lastPoll.title = poll.absolute;
  pollCell.append(lastPoll);

  const actionsCell = node("td");
  const actions = node("span", "row-actions");
  const toggle = node("button", "", device.enabled ? "Pause" : "Enable");
  toggle.type = "button";
  toggle.dataset.action = "toggle";
  toggle.dataset.enabled = String(device.enabled);
  toggle.title = device.enabled ? "Pause monitoring" : "Resume monitoring";
  const remove = node("button", "danger", "Delete");
  remove.type = "button";
  remove.dataset.action = "delete";
  remove.title = "Delete device";
  actions.append(toggle, remove);
  actionsCell.append(actions);

  row.append(statusCell, deviceCell, addressCell, snmpCell, uptimeCell, interfaceCell, pollCell, actionsCell);
  return row;
}

function updateSummary() {
  elements.total.textContent = String(state.devices.length);
  elements.up.textContent = String(state.devices.filter((device) => device.enabled && device.status === "UP").length);
  elements.down.textContent = String(state.devices.filter((device) => device.enabled && device.status === "DOWN").length);
  elements.snmp.textContent = String(state.devices.filter((device) => device.enabled && device.snmp_status === "UP").length);
}

function renderDevices() {
  const search = elements.search.value.trim().toLowerCase();
  const filtered = state.devices.filter((device) =>
    `${device.device_name} ${device.hostname} ${device.sys_name || ""}`.toLowerCase().includes(search)
  );
  elements.rows.replaceChildren(...filtered.map(buildRow));
  updateSummary();

  const hasDevices = state.devices.length > 0;
  setVisible(elements.emptyState, !hasDevices);
  setVisible(elements.tableWrap, hasDevices && filtered.length > 0);
  if (hasDevices && filtered.length === 0) {
    elements.tableMessage.textContent = "No devices match this search.";
    elements.tableMessage.className = "table-message";
    setVisible(elements.tableMessage, true);
  } else {
    setVisible(elements.tableMessage, false);
  }
}

async function loadDevices({ silent = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  elements.refresh.classList.add("loading");
  if (!silent && state.devices.length === 0) {
    elements.tableMessage.textContent = "Loading network inventory…";
    elements.tableMessage.className = "table-message";
    setVisible(elements.tableMessage, true);
  }
  try {
    const payload = await apiRequest(API_URL);
    state.devices = Array.isArray(payload.devices) ? payload.devices : [];
    renderDevices();
  } catch (error) {
    elements.tableMessage.textContent = error.message;
    elements.tableMessage.className = "table-message error";
    setVisible(elements.tableMessage, true);
    setVisible(elements.tableWrap, false);
    setVisible(elements.emptyState, false);
    if (silent) showToast(error.message, "error");
  } finally {
    state.loading = false;
    elements.refresh.classList.remove("loading");
  }
}

function syncSecurityFields() {
  const isV3 = elements.version.value === "v3";
  elements.v2Fields.disabled = isV3;
  setVisible(elements.v2Fields, !isV3);
  elements.v3Fields.disabled = !isV3;
  setVisible(elements.v3Fields, isV3);

  const level = elements.securityLevel.value;
  document.querySelectorAll(".auth-field").forEach((label) => { label.hidden = !isV3 || level === "noAuthNoPriv"; });
  document.querySelectorAll(".privacy-field").forEach((label) => { label.hidden = !isV3 || level !== "authPriv"; });
  const username = elements.form.elements.namedItem("snmpv3_username");
  const authPassword = elements.form.elements.namedItem("snmpv3_auth_password");
  const privPassword = elements.form.elements.namedItem("snmpv3_priv_password");
  username.required = isV3;
  authPassword.required = isV3 && level !== "noAuthNoPriv";
  privPassword.required = isV3 && level === "authPriv";
}

function openDialog() {
  elements.form.reset();
  elements.formError.textContent = "";
  setVisible(elements.formError, false);
  syncSecurityFields();
  elements.dialog.showModal();
  window.setTimeout(() => elements.form.elements.namedItem("hostname").focus(), 0);
}

function closeDialog() {
  if (elements.dialog.open) elements.dialog.close();
}

function buildPayload(formData) {
  const version = String(formData.get("snmp_version"));
  const payload = {
    hostname: String(formData.get("hostname") || "").trim(),
    device_name: String(formData.get("device_name") || "").trim(),
    snmp_version: version,
    snmp_port: Number(formData.get("snmp_port")),
  };
  if (version === "v2c") {
    payload.community = String(formData.get("community") || "");
    return payload;
  }
  const securityLevel = String(formData.get("snmpv3_security_level"));
  payload.snmpv3_username = String(formData.get("snmpv3_username") || "").trim();
  payload.snmpv3_security_level = securityLevel;
  if (securityLevel !== "noAuthNoPriv") {
    payload.snmpv3_auth_protocol = String(formData.get("snmpv3_auth_protocol"));
    payload.snmpv3_auth_password = String(formData.get("snmpv3_auth_password") || "");
  }
  if (securityLevel === "authPriv") {
    payload.snmpv3_priv_protocol = String(formData.get("snmpv3_priv_protocol"));
    payload.snmpv3_priv_password = String(formData.get("snmpv3_priv_password") || "");
  }
  return payload;
}

async function saveDevice(event) {
  event.preventDefault();
  syncSecurityFields();
  if (!elements.form.reportValidity()) return;
  elements.save.disabled = true;
  elements.save.textContent = "Adding…";
  setVisible(elements.formError, false);
  try {
    await apiRequest(API_URL, { method: "POST", body: JSON.stringify(buildPayload(new FormData(elements.form))) });
    closeDialog();
    showToast("Network device added. The next poll will populate live metrics.");
    await loadDevices();
  } catch (error) {
    elements.formError.textContent = error.message;
    setVisible(elements.formError, true);
  } finally {
    elements.save.disabled = false;
    elements.save.textContent = "Add device";
  }
}

async function handleRowAction(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const row = button.closest("tr[data-device-id]");
  const device = state.devices.find((item) => item.id === row?.dataset.deviceId);
  if (!device) return;
  button.disabled = true;
  try {
    if (button.dataset.action === "delete") {
      if (!window.confirm(`Delete ${device.device_name} (${device.hostname}) from OpsPilot?`)) return;
      await apiRequest(`${API_URL}/${encodeURIComponent(device.id)}`, { method: "DELETE" });
      showToast("Network device deleted.");
    } else {
      await apiRequest(`${API_URL}/${encodeURIComponent(device.id)}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !device.enabled }),
      });
      showToast(device.enabled ? "Network monitoring paused." : "Network monitoring enabled.");
    }
    await loadDevices();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function toggleNavigation(open) {
  elements.sidebar.classList.toggle("open", open);
  elements.scrim.classList.toggle("open", open);
}

document.querySelectorAll("#open-add-device, #empty-add-device").forEach((button) => button.addEventListener("click", openDialog));
document.querySelectorAll("#close-add-device, #cancel-add-device").forEach((button) => button.addEventListener("click", closeDialog));
document.querySelector("#open-navigation").addEventListener("click", () => toggleNavigation(true));
document.querySelector("#close-navigation").addEventListener("click", () => toggleNavigation(false));
elements.scrim.addEventListener("click", () => toggleNavigation(false));
elements.version.addEventListener("change", syncSecurityFields);
elements.securityLevel.addEventListener("change", syncSecurityFields);
elements.form.addEventListener("submit", saveDevice);
elements.rows.addEventListener("click", handleRowAction);
elements.search.addEventListener("input", renderDevices);
elements.refresh.addEventListener("click", () => loadDevices());
elements.dialog.addEventListener("click", (event) => {
  if (event.target === elements.dialog) closeDialog();
});
document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.querySelector(`#${CSS.escape(button.dataset.togglePassword)}`);
    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    button.textContent = reveal ? "Hide" : "Show";
  });
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") loadDevices({ silent: true });
});

syncSecurityFields();
loadDevices();
window.setInterval(() => {
  if (document.visibilityState === "visible") loadDevices({ silent: true });
}, 15000);
