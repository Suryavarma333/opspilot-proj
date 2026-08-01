"use client";

import { Fragment, useEffect, useMemo, useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  FluentProvider,
  Menu,
  MenuItem,
  MenuList,
  MenuPopover,
  MenuTrigger,
  webDarkTheme,
  webLightTheme,
} from "@fluentui/react-components";
import {
  Alert24Regular,
  Apps24Regular,
  ArrowSync24Regular,
  Bot24Regular,
  DataTrending24Regular,
  DesktopPulse24Regular,
  DocumentText24Regular,
  Gauge24Regular,
  MoreVertical24Regular,
  Navigation24Regular,
  PeopleTeam24Regular,
  Search24Regular,
  Server24Regular,
  Shield24Regular,
  Storage24Regular,
  TicketDiagonal24Regular,
  WeatherMoon24Regular,
  WeatherSunny24Regular,
  Wrench24Regular,
} from "@fluentui/react-icons";

type View =
  | "pulse"
  | "infrastructure"
  | "metrics"
  | "logs"
  | "processes"
  | "services"
  | "network"
  | "storage"
  | "users"
  | "security"
  | "commands"
  | "ai"
  | "incidents";

type CommandSpec = {
  id: string;
  command: string;
  description: string;
  category: string;
  risk: "safe" | "review";
};

type MetricSample = {
  cpu: number;
  memory: number;
  disk: number;
  load: number;
  rx: number;
  tx: number;
};

type NodeState = "online" | "warning" | "offline";
type Theme = "dark" | "light";
type HistoryRange = "15m" | "30m" | "1h" | "3h" | "6h";

const historyRanges: HistoryRange[] = ["15m", "30m", "1h", "3h", "6h"];
const historyMinutes: Record<HistoryRange, number> = { "15m": 15, "30m": 30, "1h": 60, "3h": 180, "6h": 360 };

const commandGroups: Record<string, [string, string][]> = {
  "Host & OS": [
    ["uptime", "Current uptime and load averages"],
    ["uptime -p", "Human-readable uptime"],
    ["uptime -s", "Boot timestamp"],
    ["hostname", "Short host name"],
    ["hostname -f", "Fully qualified host name"],
    ["hostname -I", "Assigned IP addresses"],
    ["hostnamectl", "Host, OS, kernel and virtualization"],
    ["uname -a", "Complete kernel identity"],
    ["uname -r", "Kernel release"],
    ["uname -m", "Machine architecture"],
    ["cat /etc/os-release", "Operating-system release metadata"],
    ["cat /proc/version", "Kernel build details"],
    ["cat /proc/cmdline", "Kernel boot parameters"],
    ["cat /proc/uptime", "Raw uptime and idle-time counters"],
    ["timedatectl", "Clock, timezone and NTP state"],
    ["date -u", "Current UTC time"],
    ["who -b", "Last system boot time"],
    ["systemd-detect-virt", "Virtualization technology"],
    ["lsb_release -a", "Distribution release details"],
  ],
  Compute: [
    ["lscpu", "CPU architecture and topology"],
    ["nproc --all", "Available logical processors"],
    ["cat /proc/cpuinfo", "Per-processor details"],
    ["cat /proc/loadavg", "Scheduler load and run queue"],
    ["vmstat 1 2", "CPU, memory and scheduler sample"],
    ["vmstat -s", "Kernel counter summary"],
    ["mpstat -P ALL 1 1", "Per-CPU utilization when sysstat exists"],
    ["ps -eo pid,ppid,user,stat,pcpu,pmem,comm --sort=-pcpu", "Top CPU consumers"],
    ["ps -eo pid,psr,stat,comm", "Process-to-CPU placement"],
    ["pidstat 1 1", "Per-process CPU sample when sysstat exists"],
    ["top", "One-shot top-style CPU and process snapshot"],
    ["top -b -n 1", "Batch-mode top snapshot"],
    ["cat /proc/pressure/cpu", "CPU pressure-stall information"],
    ["cat /proc/pressure/io", "I/O pressure-stall information"],
    ["cat /proc/interrupts", "Interrupt distribution"],
    ["cat /proc/softirqs", "Soft interrupt counters"],
    ["getconf CLK_TCK", "Kernel clock ticks per second"],
    ["cat /proc/sys/fs/file-nr", "Allocated kernel file handles"],
    ["cat /proc/sys/fs/inode-nr", "Allocated kernel inode counters"],
  ],
  Memory: [
    ["free -h", "Memory and swap summary"],
    ["free -w -h", "Detailed memory availability"],
    ["cat /proc/meminfo", "Kernel memory counters"],
    ["cat /proc/pressure/memory", "Memory pressure-stall information"],
    ["vmstat -a", "Active and inactive memory"],
    ["vmstat -m", "Kernel slab cache summary"],
    ["swapon --show", "Configured swap devices"],
    ["ps -eo pid,user,pmem,rss,vsz,comm --sort=-rss", "Top resident-memory users"],
    ["pmap -x 1", "PID 1 memory map summary"],
    ["cat /proc/1/status", "PID 1 memory and capability state"],
    ["sysctl vm.swappiness", "Swap tendency"],
    ["sysctl vm.overcommit_memory", "Memory overcommit policy"],
    ["sysctl vm.dirty_ratio", "Dirty-page writeback threshold"],
    ["sysctl vm.min_free_kbytes", "Reserved free-memory target"],
  ],
  Storage: [
    ["lsblk", "Block-device topology"],
    ["lsblk -f", "Filesystems and UUIDs"],
    ["lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS", "Operational block-device view"],
    ["lsblk --json -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS", "Machine-readable block-device inventory"],
    ["df -hT", "Filesystem capacity by type"],
    ["df -ih", "Filesystem inode utilization"],
    ["findmnt", "Mount hierarchy"],
    ["findmnt -D", "Mount capacity overview"],
    ["findmnt /", "Root filesystem source and options"],
    ["findmnt --verify", "Validate fstab and mount consistency"],
    ["mount", "All active mounts"],
    ["cat /proc/mounts", "Kernel mount table"],
    ["cat /proc/diskstats", "Block-device I/O counters"],
    ["stat -f /", "Root filesystem metadata"],
    ["du -xhd1 /var", "Top-level /var usage"],
    ["du -xhd1 /home", "Top-level /home usage"],
    ["iostat -xz 1 1", "Extended disk latency when sysstat exists"],
    ["blkid", "Visible block identifiers"],
    ["ls -lah /var/log", "Log-directory footprint"],
    ["journalctl --disk-usage", "Journal storage consumption"],
    ["journalctl --verify", "Verify journal-file integrity"],
  ],
  Network: [
    ["ip -br address", "Compact interface addresses"],
    ["ip -br link", "Compact interface state"],
    ["ip address show", "Detailed interface addresses"],
    ["ip -s link", "Interface errors, drops and bytes"],
    ["ip -details link show", "Detailed interface link properties"],
    ["ip route show", "IPv4 routing table"],
    ["ip -6 route show", "IPv6 routing table"],
    ["ip rule show", "Policy-routing rules"],
    ["ss -lntup", "Listening TCP and UDP sockets"],
    ["ss -s", "Socket statistics summary"],
    ["ss -tan state established", "Established TCP sessions"],
    ["ss -tan state time-wait", "TCP TIME-WAIT sessions"],
    ["ss -o state established", "Established sockets with timers"],
    ["cat /proc/net/dev", "Kernel interface counters"],
    ["cat /proc/net/route", "Kernel IPv4 routes"],
    ["cat /etc/resolv.conf", "Resolver configuration"],
    ["resolvectl status", "Per-link DNS status"],
    ["getent hosts localhost", "Name-service resolution test"],
    ["ip neigh show", "Neighbor cache"],
    ["sysctl net.ipv4.ip_forward", "IPv4 forwarding state"],
    ["sysctl net.ipv4.tcp_syncookies", "SYN-cookie protection"],
    ["sysctl net.core.somaxconn", "Listen backlog ceiling"],
  ],
  Processes: [
    ["ps aux", "BSD-style process inventory"],
    ["ps -ef", "Full-format process inventory"],
    ["ps -e --forest", "Process hierarchy"],
    ["ps -eo pid,ppid,lstart,etime,stat,comm", "Process age and state"],
    ["ps -eo state,pid,comm | sort", "Processes grouped by state"],
    ["pgrep -a nginx", "nginx process arguments"],
    ["pgrep -a python", "Python process arguments"],
    ["pgrep -a sshd", "SSH daemon processes"],
    ["cat /proc/1/cgroup", "PID 1 control groups"],
    ["cat /proc/1/limits", "PID 1 resource limits"],
    ["ls -l /proc/1/fd", "PID 1 open file descriptors"],
    ["systemd-cgls", "Systemd control-group tree"],
    ["systemd-cgtop -b -n 1", "One-shot cgroup resource view"],
    ["lsns", "Linux namespace inventory"],
    ["ulimit -a", "Service-user shell limits"],
  ],
  Services: [
    ["systemctl --failed --no-pager", "Failed systemd units"],
    ["systemctl list-units --type=service --state=running --no-pager", "Running services"],
    ["systemctl list-units --type=service --state=failed --no-pager", "Failed services"],
    ["systemctl list-unit-files --type=service --no-pager", "Installed service-unit policy"],
    ["systemctl list-timers --all --no-pager", "Scheduled timers"],
    ["systemctl status nginx --no-pager", "nginx runtime status"],
    ["systemctl status opspilot.service --no-pager", "OpsPilot API runtime status"],
    ["systemctl status opspilot-dashboard-agent.service --no-pager", "Dashboard agent status"],
    ["systemctl show nginx -p ActiveState,SubState,MainPID,MemoryCurrent", "nginx machine-readable state"],
    ["systemctl show opspilot.service -p ActiveState,SubState,MainPID,MemoryCurrent", "OpsPilot API state"],
    ["systemctl is-system-running", "Overall systemd health"],
    ["systemctl list-dependencies nginx --no-pager", "nginx dependency graph"],
    ["systemctl list-sockets --no-pager", "Socket-activated units"],
    ["systemd-analyze", "Boot-time summary"],
    ["systemd-analyze blame", "Units ordered by startup duration"],
    ["systemd-analyze critical-chain", "Critical boot dependency chain"],
    ["systemd-analyze security opspilot-dashboard-agent.service", "Dashboard-agent sandbox review"],
    ["loginctl list-sessions --no-pager", "Active login sessions"],
    ["loginctl list-users --no-pager", "Logged-in users known to systemd"],
  ],
  Logs: [
    ["journalctl -p err -n 50 --no-pager", "Recent error-priority events"],
    ["journalctl -p warning -n 80 --no-pager", "Recent warnings and errors"],
    ["journalctl -b -n 100 --no-pager", "Recent events from this boot"],
    ["journalctl -b -1 -n 80 --no-pager", "Previous boot tail"],
    ["journalctl -u nginx -n 80 --no-pager", "Recent nginx journal"],
    ["journalctl -u opspilot.service -n 80 --no-pager", "Recent OpsPilot API journal"],
    ["journalctl -u opspilot-dashboard-agent.service -n 80 --no-pager", "Recent dashboard-agent journal"],
    ["journalctl -k -n 80 --no-pager", "Recent kernel events"],
    ["journalctl --since '1 hour ago' --no-pager", "Events from the last hour"],
    ["journalctl --list-boots --no-pager", "Recorded boot sessions"],
    ["dmesg --level=err,warn", "Kernel warning and error ring buffer"],
    ["tail -n 80 /var/log/auth.log", "Recent authentication log"],
    ["tail -n 80 /var/log/syslog", "Recent system log"],
    ["last -n 20", "Recent login history"],
    ["lastb -n 20", "Recent failed-login history"],
  ],
  "Users & Security": [
    ["who", "Current login sessions"],
    ["w", "Logged-in users and activity"],
    ["users", "Current usernames"],
    ["lastlog", "Last login per local account"],
    ["getent passwd", "Account database"],
    ["getent group", "Group database"],
    ["getent group sudo", "Sudo-group membership"],
    ["awk -F: '$3==0 {print $1}' /etc/passwd", "UID-zero identities"],
    ["awk -F: '$7 !~ /(nologin|false)$/ {print $1,$7}' /etc/passwd", "Interactive-shell accounts"],
    ["stat /etc/passwd /etc/group /etc/sudoers", "Identity-file metadata"],
    ["ls -la /etc/sudoers.d", "Sudo policy fragments"],
    ["sshd -T", "Effective SSH daemon configuration"],
    ["grep -Ev '^(#|$)' /etc/ssh/sshd_config", "Active SSH configuration"],
    ["sysctl kernel.randomize_va_space", "ASLR policy"],
    ["sysctl kernel.kptr_restrict", "Kernel pointer exposure policy"],
    ["sysctl fs.protected_hardlinks", "Hardlink protection"],
    ["sysctl fs.protected_symlinks", "Symlink protection"],
    ["find /tmp -xdev -type f -perm -0002 -ls", "World-writable files in /tmp"],
  ],
  Packages: [
    ["dpkg-query -W", "Installed Debian packages"],
    ["dpkg -l", "Package states"],
    ["apt list --upgradable", "Available package upgrades"],
    ["apt-cache policy", "Configured package sources and priorities"],
    ["grep -Rh '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d", "Configured APT repositories"],
    ["uname -r", "Running kernel release"],
    ["ls -1 /boot/vmlinuz-*", "Installed kernel images"],
    ["systemctl status unattended-upgrades --no-pager", "Automatic-update service state"],
    ["journalctl -u unattended-upgrades -n 50 --no-pager", "Automatic-update history"],
    ["test -f /var/run/reboot-required && cat /var/run/reboot-required || echo no", "Reboot requirement"],
  ],
};

const commands: CommandSpec[] = Object.entries(commandGroups).flatMap(
  ([category, items]) =>
    items.map(([command, description], index) => ({
      id: `${category.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${index + 1}`,
      command,
      description,
      category,
      risk: command.includes("du ") || command.includes("lastb") || command.includes("sshd -T") ? "review" : "safe",
    })),
);

const nav: { group: string; items: { id: View; label: string; icon: string; badge?: string }[] }[] = [
  {
    group: "OBSERVE",
    items: [
      { id: "pulse", label: "Mission control", icon: "⌁" },
      { id: "infrastructure", label: "Infrastructure", icon: "⬡" },
      { id: "metrics", label: "Metrics studio", icon: "⌁" },
      { id: "logs", label: "Log explorer", icon: "≡", badge: "24" },
      { id: "processes", label: "Live processes", icon: "◫" },
    ],
  },
  {
    group: "OPERATE",
    items: [
      { id: "services", label: "Services", icon: "⎈" },
      { id: "network", label: "Network", icon: "⌘" },
      { id: "storage", label: "Storage", icon: "◉" },
      { id: "users", label: "Users & access", icon: "♙" },
      { id: "security", label: "Security", icon: "◇", badge: "1" },
    ],
  },
  {
    group: "INVESTIGATE",
    items: [
      { id: "commands", label: "Command center", icon: ">_", badge: String(commands.length) },
      { id: "ai", label: "OpsPilot AI", icon: "✦" },
      { id: "incidents", label: "Incidents", icon: "!" },
    ],
  },
];

const initialSamples: MetricSample[] = [
  { cpu: 18, memory: 43, disk: 31, load: .18, rx: 2.8, tx: 1.2 },
  { cpu: 24, memory: 44, disk: 31, load: .27, rx: 4.3, tx: 1.8 },
  { cpu: 17, memory: 44, disk: 31, load: .2, rx: 3.4, tx: 1.4 },
  { cpu: 33, memory: 45, disk: 31, load: .41, rx: 5.8, tx: 2.7 },
  { cpu: 29, memory: 44, disk: 31, load: .34, rx: 4.7, tx: 2.1 },
  { cpu: 48, memory: 46, disk: 31, load: .61, rx: 8.1, tx: 3.8 },
  { cpu: 37, memory: 45, disk: 31, load: .46, rx: 6.6, tx: 3 },
  { cpu: 54, memory: 47, disk: 31, load: .72, rx: 9.2, tx: 4.6 },
  { cpu: 31, memory: 46, disk: 31, load: .39, rx: 5.2, tx: 2.5 },
  { cpu: 26, memory: 45, disk: 31, load: .31, rx: 4.5, tx: 2 },
  { cpu: 42, memory: 46, disk: 31, load: .55, rx: 7.3, tx: 3.6 },
  { cpu: 23, memory: 45, disk: 31, load: .28, rx: 3.9, tx: 1.7 },
];

const outputFor = (command: string) => {
  if (command === "uptime") return " 09:42:31 up  4:19,  1 user,  load average: 0.23, 0.31, 0.28";
  if (command === "lsblk") return "NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\nsda           8:0    0  100G  0 disk\n├─sda1        8:1    0    1G  0 part /boot/efi\n├─sda2        8:2    0    2G  0 part /boot\n└─sda3        8:3    0   97G  0 part\n  └─ubuntu--vg-ubuntu--lv 253:0 0 96G 0 lvm /\nsdb           8:16   0  100G  0 disk";
  if (command === "free -h") return "               total        used        free      shared  buff/cache   available\nMem:           7.6Gi       3.4Gi       2.6Gi        43Mi       1.6Gi       4.1Gi\nSwap:             0B          0B          0B";
  if (command === "df -hT") return "Filesystem                         Type   Size  Used Avail Use% Mounted on\n/dev/mapper/ubuntu--vg-ubuntu--lv ext4    96G   30G   67G  31% /\n/dev/sda2                          ext4   2.0G  368M  1.6G  19% /boot\n/dev/sda1                          vfat   1.0G   62M  962M   7% /boot/efi";
  if (command.startsWith("systemctl --failed")) return "  UNIT LOAD ACTIVE SUB DESCRIPTION\n0 loaded units listed.";
  if (command === "ss -lntup") return "Netid State  Local Address:Port  Process\nudp   UNCONN 127.0.0.53:53       users:((systemd-resolve))\ntcp   LISTEN 0.0.0.0:22          users:((sshd))\ntcp   LISTEN 0.0.0.0:80          users:((nginx))\ntcp   LISTEN 127.0.0.1:3000      users:((python))\ntcp   LISTEN 127.0.0.1:3100      users:((python))";
  if (command.startsWith("journalctl -p err")) return "Jul 31 09:25:14 opspilot-node-01 apt[1841]: mirror timeout recovered on retry\n-- No unresolved priority-3 events in the current boot --";
  return `[simulated hosted result]\n$ ${command}\nCommand completed successfully on opspilot-node-01.\nThe VM package returns the real command output, exit code, duration and timestamp.`;
};

type CommandResult = { status: string; output?: string; stdout?: string; stderr?: string; message?: string; exit_code?: number; duration_ms?: number; generated_at?: string };
type IncidentDraft = {
  status: string;
  mode: "draft" | "live";
  summary: string;
  description: string;
  priority: string;
  severity: string;
  jira: { project_key: string; issue_type: string; url: string };
  google_chat: { space: string };
  meet_url: string;
  on_call: { status: string; name?: string; email?: string; message?: string };
  guardrails: { external_write_performed: boolean; explicit_confirmation_required: boolean; action_token_required: boolean };
};
type DispatchResult = { status: string; message?: string; jira?: { key: string; url: string }; chat?: { status: string; space: string; message?: string }; meet_url?: string };

async function executeApprovedCommand(command: CommandSpec, signal?: AbortSignal): Promise<CommandResult> {
  try {
    const response = await fetch("api/v1/dashboard", { method: "POST", headers: { "Content-Type": "application/json", "X-OpsPilot-Action": "diagnostic" }, body: JSON.stringify({ command: command.command }), signal });
    const result = await response.json() as CommandResult;
    if (!response.ok) throw new Error(result.message || `Diagnostic returned HTTP ${response.status}`);
    return result;
  } catch (error) {
    if (typeof window !== "undefined" && window.location.hostname.endsWith("chatgpt.site")) return { status: "completed", output: outputFor(command.command), stdout: outputFor(command.command), stderr: "", exit_code: 0, duration_ms: 42, generated_at: new Date().toISOString() };
    throw error;
  }
}

async function prepareIncident(metric: string, priority: string, signal?: AbortSignal): Promise<IncidentDraft> {
  try {
    const response = await fetch("api/v1/dashboard", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "prepare_incident", metric, priority }), signal });
    const result = await response.json() as IncidentDraft & { message?: string };
    if (!response.ok) throw new Error(result.message || `Incident preparation returned HTTP ${response.status}`);
    return result;
  } catch (error) {
    if (typeof window !== "undefined" && window.location.hostname.endsWith("chatgpt.site")) return {
      status: "prepared", mode: "draft", summary: `[OpsPilot][SEV-2] ${metric} on opspilot-node-01`,
      description: `OpsPilot detected ${metric}. Live telemetry, host identity, the fixed Meet bridge, and read-only evidence are attached.`,
      priority, severity: priority === "Highest" ? "SEV-1" : priority === "High" ? "SEV-2" : "SEV-3",
      jira: { project_key: "OPS", issue_type: "INCIDENT", url: "https://your-domain.atlassian.net" },
      google_chat: { space: "NOC-Alerts" }, meet_url: "https://meet.google.com/your-bridge",
      on_call: { status: "pending_access", message: "Roster access will be validated on the VM" },
      guardrails: { external_write_performed: false, explicit_confirmation_required: true, action_token_required: true },
    };
    throw error;
  }
}

async function dispatchIncident(metric: string, priority: string, actionToken: string, idempotencyKey: string): Promise<DispatchResult> {
  const response = await fetch("api/v1/dashboard", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-OpsPilot-Action-Token": actionToken, "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({ action: "dispatch_incident", metric, priority, confirm: true }),
  });
  const result = await response.json() as DispatchResult;
  if (!response.ok && result.status !== "partial") throw new Error(result.message || `Incident dispatch returned HTTP ${response.status}`);
  return result;
}

function path(values: number[], width = 640, height = 170, max = 100) {
  return values
    .map((value, index) => {
      const x = index * (width / Math.max(1, values.length - 1));
      const y = height - Math.max(0, Math.min(max, value)) / max * height;
      return `${index ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

function Spark({ values, color = "#68f0b5" }: { values: number[]; color?: string }) {
  const d = path(values, 120, 42);
  return <svg className="spark" viewBox="0 0 120 42" preserveAspectRatio="none" aria-hidden="true"><path d={`${d} L120,42 L0,42Z`} fill={`${color}18`} /><path d={d} stroke={color} fill="none" strokeWidth="2" /></svg>;
}

function Status({ children, tone = "good" }: { children: React.ReactNode; tone?: "good" | "warn" | "bad" | "info" }) {
  return <span className={`status ${tone}`}><i />{children}</span>;
}

function MetricCard({ label, value, detail, values, color, onClick }: { label: string; value: string; detail: string; values: number[]; color: string; onClick?: () => void }) {
  return <button className="metric-card" onClick={onClick} style={{ "--accent": color } as React.CSSProperties}><span className="metric-label">{label}<em>LIVE</em></span><div><strong>{value}</strong><Spark values={values} color={color} /></div><small>{detail}</small></button>;
}

function Panel({ title, kicker, children, action, className = "" }: { title: string; kicker?: string; children: React.ReactNode; action?: React.ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><header className="panel-head"><div>{kicker && <span>{kicker}</span>}<h2>{title}</h2></div>{action}</header>{children}</section>;
}

function TimeChart({ samples }: { samples: MetricSample[] }) {
  const cpu = path(samples.map(x => x.cpu));
  const mem = path(samples.map(x => x.memory));
  const load = path(samples.map(x => x.load * 52));
  return <div className="time-chart">
    <div className="chart-legend"><span><i className="lime" />CPU <b>{samples.at(-1)!.cpu}%</b></span><span><i className="violet" />Memory <b>{samples.at(-1)!.memory}%</b></span><span><i className="blue" />Load <b>{samples.at(-1)!.load}</b></span><em>5-second pulse</em></div>
    <div className="chart-canvas">
      <svg viewBox="0 0 640 170" preserveAspectRatio="none">
        <defs><linearGradient id="cpuFill" x1="0" y1="0" x2="0" y2="1"><stop stopColor="#68f0b5" stopOpacity=".24" /><stop offset="1" stopColor="#68f0b5" stopOpacity="0" /></linearGradient></defs>
        {[0, 42.5, 85, 127.5, 170].map(y => <line key={y} x1="0" x2="640" y1={y} y2={y} className="grid-line" />)}
        <path d={`${cpu} L640,170 L0,170Z`} fill="url(#cpuFill)" />
        <path d={cpu} className="cpu-path" />
        <path d={mem} className="memory-path" />
        <path d={load} className="load-path" />
        <line x1="380" x2="380" y1="0" y2="170" className="event-line" />
      </svg>
      <span className="annotation" style={{ left: "55%" }}><i />nginx reload</span>
      <div className="y-axis"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div>
      <div className="x-axis"><span>-30m</span><span>-24m</span><span>-18m</span><span>-12m</span><span>-6m</span><span>now</span></div>
    </div>
  </div>;
}

function ServerTopology({ onOpen }: { onOpen: () => void }) {
  return <button className="server-visual" onClick={onOpen} aria-label="Open infrastructure">
    <div className="scan-ring r1" /><div className="scan-ring r2" />
    <div className="server-case">
      <header><span>NODE / 01</span><Status>online</Status></header>
      <div className="server-grid">
        <div className="cpu-bank"><span>CPU</span><div className="fan"><i /><i /><i /><b /></div><div className="fan"><i /><i /><i /><b /></div><small>23%</small></div>
        <div className="ram-bank"><span>MEM</span>{[0, 1, 2, 3, 4, 5].map(item => <i key={item}><b /></i>)}<small>3.5 / 7.6 GB</small></div>
        <div className="disk-bank"><span>NVMe</span>{[0, 1, 2].map(item => <i key={item}><b /><em /></i>)}<small>31%</small></div>
        <div className="nic-bank"><span>NIC</span><div><i /><i /><i /><i /></div><small>3.9 MB/s</small></div>
      </div>
      <footer><span><i />PWR</span><span><i />HEALTH</span><b>opspilot-node-01</b></footer>
    </div>
    <span className="topology-label"><i />Live hardware map <b>Click to inspect</b></span>
  </button>;
}

function MissionControl({ samples, navigate, run, nodeState, setNodeState }: { samples: MetricSample[]; navigate: (view: View) => void; run: (command: CommandSpec) => void; nodeState: NodeState; setNodeState: (state: NodeState) => void }) {
  const current = samples.at(-1)!;
  return <div className="view">
    <section className={`node-banner ${nodeState}`}>
      <div><span className="node-pulse"><i /></span><span><small>NODE STATE</small><b>{nodeState === "online" ? "Telemetry stable" : nodeState === "warning" ? "Degraded signal detected" : "Host heartbeat lost"}</b></span></div>
      <p>{nodeState === "online" ? "All live probes are returning within policy." : nodeState === "warning" ? "The host is reachable, but one or more health thresholds need investigation." : "The dashboard has stopped receiving a valid heartbeat from opspilot-node-01."}</p>
      <div className="state-lab"><small>DEMO CONTROLS</small><button className={nodeState === "online" ? "active" : ""} onClick={() => setNodeState("online")}>Online</button><button className={nodeState === "warning" ? "active" : ""} onClick={() => setNodeState("warning")}>Warning</button><button className={nodeState === "offline" ? "active" : ""} onClick={() => setNodeState("offline")}>Outage</button></div>
    </section>
    <section className="hero-grid">
      <div className="hero-copy"><span className="eyebrow"><i />NODE ONLINE · UBUNTU 22.04.5 LTS</span><h1>See the signal.<br /><em>Prove the cause.</em></h1><p>A unified server operations workspace combining live telemetry, evidence-first diagnostics, and AI-assisted investigation.</p><div className="hero-actions"><button className="primary" onClick={() => navigate("ai")}>✦ Ask OpsPilot AI</button><button onClick={() => navigate("commands")}>Open {commands.length} commands</button></div><div className="host-facts"><span><b>192.0.2.10</b><small>ens160 · /24</small></span><span><b>4 vCPU</b><small>KVM / QEMU</small></span><span><b>04h 19m</b><small>uptime</small></span></div></div>
      <ServerTopology onOpen={() => navigate("infrastructure")} />
      <aside className="ai-brief"><header><span className="ai-orb">✦</span><div><b>OpsPilot AI</b><small>EVIDENCE ENGINE</small></div><Status>ready</Status></header><h2>System is composed.</h2><p>No sustained resource pressure. One SSH exposure review is the only open security signal.</p><div className="confidence"><span>Confidence</span><b>94%</b><i><em /></i></div><ol><li><i className="good" /><span><b>Capacity</b><small>CPU and memory have healthy runway</small></span></li><li><i className="warn" /><span><b>Exposure</b><small>Port 22 listens on all interfaces</small></span></li><li><i className="good" /><span><b>Services</b><small>All monitored units active</small></span></li></ol><button onClick={() => navigate("ai")}>Open investigation →</button></aside>
    </section>

    <section className="metric-grid">
      <MetricCard label="CPU UTILIZATION" value={`${current.cpu}%`} detail="4 vCPU · 0.2% iowait" values={samples.map(x => x.cpu)} color="#68f0b5" onClick={() => navigate("metrics")} />
      <MetricCard label="MEMORY ACTIVE" value={`${current.memory}%`} detail="3.5 of 7.6 GB · no swap" values={samples.map(x => x.memory)} color="#9e86ff" onClick={() => navigate("metrics")} />
      <MetricCard label="ROOT FILESYSTEM" value={`${current.disk}%`} detail="29.7 of 96 GB · ext4" values={samples.map(x => x.disk)} color="#ffb35c" onClick={() => navigate("storage")} />
      <MetricCard label="NETWORK RECEIVE" value={`${current.rx.toFixed(1)} MB/s`} detail={`TX ${current.tx.toFixed(1)} MB/s · 0 drops`} values={samples.map(x => x.rx * 7)} color="#62b9ff" onClick={() => navigate("network")} />
    </section>

    <section className="dashboard-grid">
      <Panel kicker="METRICS STUDIO" title="Infrastructure pressure" className="wide" action={<div className="range"><button>15m</button><button className="active">30m</button><button>1h</button><button>6h</button></div>}><TimeChart samples={samples} /></Panel>
      <Panel kicker="HEALTH COMPOSITION" title="Resource posture" action={<Status>98 / 100</Status>}><div className="health-donut"><div><span><b>98</b><small>COMPOSURE</small></span></div><ul><li><i className="cpu" />Compute <b>Healthy</b></li><li><i className="memory" />Memory <b>Healthy</b></li><li><i className="disk" />Storage <b>Normal</b></li><li><i className="network" />Network <b>Healthy</b></li></ul></div></Panel>
      <Panel kicker="ACTIVE SIGNALS" title="Event stream"><div className="event-list"><button onClick={() => navigate("security")}><i className="warn" /><span><b>SSH boundary review</b><small>Port 22 · all interfaces</small></span><time>6m</time></button><button onClick={() => navigate("services")}><i className="good" /><span><b>Health sweep completed</b><small>5 / 5 critical checks</small></span><time>9m</time></button><button onClick={() => navigate("logs")}><i className="info" /><span><b>nginx reloaded</b><small>Configuration validated</small></span><time>18m</time></button></div></Panel>
      <Panel kicker="FAST DIAGNOSTICS" title="One-click evidence"><div className="quick-command-list">{commands.filter(item => ["uptime", "lsblk", "free -h", "df -hT", "ss -lntup"].includes(item.command)).map(item => <button key={item.id} onClick={() => run(item)}><code>$ {item.command}</code><span>Run <b>→</b></span></button>)}</div></Panel>
      <Panel kicker="LIVE PROCESSES" title="Resource consumers" action={<button className="text-action" onClick={() => navigate("processes")}>View all →</button>}><div className="process-list">{[["opspilot", "4001", "6.8", "2.4"], ["nginx", "870", "2.1", ".7"], ["systemd-journal", "612", "1.3", "1.1"], ["sshd", "934", ".8", ".5"]].map(row => <div key={row[0]}><span className="process-icon">{row[0][0].toUpperCase()}</span><span><b>{row[0]}</b><small>PID {row[1]}</small></span><em>{row[2]}%<small>CPU</small></em><em>{row[3]}%<small>MEM</small></em></div>)}</div></Panel>
    </section>
  </div>;
}

function InfrastructureView({ navigate }: { navigate: (view: View) => void }) {
  return <div className="view"><PageTitle kicker="HOST MAP" title="Infrastructure" description="A physical and logical model of opspilot-node-01, from compute and memory to public ingress and protected loopback services." />
    <section className="infra-layout"><ServerTopology onOpen={() => navigate("metrics")} /><Panel kicker="NODE IDENTITY" title="opspilot-node-01"><dl className="facts"><div><dt>Address</dt><dd>192.0.2.10</dd></div><div><dt>Operating system</dt><dd>Ubuntu 22.04.5 LTS</dd></div><div><dt>Kernel</dt><dd>5.15.0-186-generic</dd></div><div><dt>Virtualization</dt><dd>KVM / QEMU</dd></div><div><dt>Architecture</dt><dd>x86_64</dd></div><div><dt>Timezone</dt><dd>UTC</dd></div></dl></Panel></section>
    <section className="dependency-flow"><article><span>PUBLIC</span><b>Windows / Browser</b><small>198.51.100.42</small></article><i>→</i><article><span>INGRESS</span><b>nginx :80</b><small>/opspilot/</small></article><i>→</i><article className="protected"><span>LOOPBACK</span><b>OpsPilot API</b><small>127.0.0.1:3000</small></article><i>+</i><article className="protected"><span>LOOPBACK</span><b>Ops Agent</b><small>127.0.0.1:3100</small></article></section>
    <section className="inventory-grid">{[["CPU", "4 vCPU", "23% active", "metrics"], ["Memory", "7.6 GB", "4.1 GB available", "metrics"], ["Storage", "196 GB", "100 GB unallocated", "storage"], ["Network", "ens160", "0 drops / errors", "network"], ["Services", "12 units", "0 failed", "services"], ["Accounts", "8 identities", "1 human online", "users"]].map(item => <button key={item[0]} onClick={() => navigate(item[3] as View)}><span>{item[0].slice(0, 2).toUpperCase()}</span><div><b>{item[0]}</b><strong>{item[1]}</strong><small>{item[2]}</small></div><em>↗</em></button>)}</section>
  </div>;
}

function MetricsView({ samples }: { samples: MetricSample[] }) {
  return <div className="view"><PageTitle kicker="GRAFANA-STYLE EXPLORATION" title="Metrics studio" description="Correlate compute, memory, scheduler, storage and network signals across one synchronized time range." actions={<><button>Export CSV</button><button className="primary">Create alert</button></>} />
    <div className="variable-bar"><label>HOST<select><option>opspilot-node-01</option></select></label><label>SIGNAL<select><option>All resources</option><option>Compute</option><option>Memory</option></select></label><label>RANGE<select><option>Last 30 minutes</option><option>Last 1 hour</option></select></label><span><i />auto-refresh 5s</span></div>
    <section className="metric-grid"><MetricCard label="CPU UTILIZATION" value={`${samples.at(-1)!.cpu}%`} detail="P95 54% · iowait .2%" values={samples.map(x => x.cpu)} color="#68f0b5" /><MetricCard label="MEMORY USED" value={`${samples.at(-1)!.memory}%`} detail="Swap 0 B · cache 1.3 GB" values={samples.map(x => x.memory)} color="#9e86ff" /><MetricCard label="LOAD / CORE" value={(samples.at(-1)!.load / 4).toFixed(2)} detail="Queue depth normal" values={samples.map(x => x.load * 60)} color="#ffb35c" /><MetricCard label="NETWORK RX" value={`${samples.at(-1)!.rx} MB/s`} detail="No errors or drops" values={samples.map(x => x.rx * 7)} color="#62b9ff" /></section>
    <section className="metrics-panels"><Panel kicker="CORRELATED SIGNALS" title="CPU × memory × load" className="wide"><TimeChart samples={samples} /></Panel><Panel kicker="PRESSURE STALL" title="Where work is waiting"><div className="bars">{[["CPU some", 4, ".04%"], ["Memory some", 1, "0%"], ["I/O some", 12, ".12%"], ["I/O full", 1, "0%"]].map(row => <div key={row[0]}><span>{row[0]}</span><i><b style={{ width: `${row[1]}%` }} /></i><strong>{row[2]}</strong></div>)}</div></Panel><Panel kicker="SATURATION" title="Capacity runway"><div className="gauge-row">{[["CPU", 23, "#68f0b5"], ["Memory", 45, "#9e86ff"], ["Disk", 31, "#ffb35c"], ["Inodes", 12, "#62b9ff"]].map(item => <span key={item[0]} style={{ "--value": `${item[1]}`, "--tone": item[2] } as React.CSSProperties}><i /><b>{item[1]}%</b><small>{item[0]}</small></span>)}</div></Panel></section>
  </div>;
}

function TableView({ view, run, navigate }: { view: View; run: (cmd: CommandSpec) => void; navigate: (view: View) => void }) {
  const configs: Record<string, { kicker: string; title: string; description: string; category: string; heads: string[]; rows: string[][] }> = {
    logs: { kicker: "JOURNAL EXPLORER", title: "Logs & events", description: "Search authentication, kernel, systemd, nginx and application evidence with level and unit context.", category: "Logs", heads: ["TIME", "LEVEL", "UNIT", "MESSAGE", "CONTEXT"], rows: [["09:32:42", "INFO", "opspilot", "Telemetry sweep completed", "41 ms"], ["09:31:01", "WARN", "sshd", "Failed publickey for invalid user admin", "198.51.100.23"], ["09:30:00", "INFO", "myname", "Scheduled automation finished", "exit 0"], ["09:25:14", "ERROR", "apt", "Mirror retry completed after timeout", "recovered"], ["09:22:02", "INFO", "kernel", "EXT4-fs mounted with ordered data mode", "/dev/dm-0"]] },
    processes: { kicker: "LIVE PROCESS VIEW", title: "Processes", description: "Find resource consumers, state anomalies, runtime age and ownership without opening an SSH session.", category: "Processes", heads: ["PROCESS", "PID", "OWNER", "CPU", "MEMORY", "STATE"], rows: [["opspilot", "4001", "opspilot", "6.8%", "2.4%", "running"], ["nginx", "870", "www-data", "2.1%", ".7%", "sleeping"], ["systemd-journal", "612", "root", "1.3%", "1.1%", "sleeping"], ["sshd", "934", "root", ".8%", ".5%", "running"], ["telemetry-agent", "4128", "opspilot", ".2%", ".8%", "running"]] },
    services: { kicker: "SYSTEMD CONTROL PLANE", title: "Services", description: "Inspect unit state, ownership, dependencies, recovery policy, timers and recent transitions.", category: "Services", heads: ["UNIT", "DESCRIPTION", "ACTIVE", "SUBSTATE", "PID", "MEMORY"], rows: [["nginx.service", "Reverse proxy · port 80", "active", "running", "812", "14.2 MB"], ["opspilot.service", "FastAPI · 127.0.0.1:3000", "active", "running", "4001", "42.6 MB"], ["opspilot-dashboard-agent.service", "Telemetry · 127.0.0.1:3100", "active", "running", "4128", "31.8 MB"], ["ssh.service", "Remote access · port 22", "active", "running", "934", "9.4 MB"], ["myname.timer", "Lab automation · every 2 min", "active", "waiting", "—", "—"]] },
    network: { kicker: "NETWORK PERFORMANCE", title: "Network", description: "Trace interfaces, traffic, routes, DNS and socket exposure from public ingress to private backends.", category: "Network", heads: ["PROTO", "LOCAL ADDRESS", "PROCESS", "BOUNDARY", "STATE", "VERDICT"], rows: [["TCP", "0.0.0.0:22", "sshd", "All interfaces", "LISTEN", "review"], ["TCP", "0.0.0.0:80", "nginx", "All interfaces", "LISTEN", "expected"], ["TCP", "127.0.0.1:3000", "opspilot", "Loopback", "LISTEN", "protected"], ["TCP", "127.0.0.1:3100", "ops-agent", "Loopback", "LISTEN", "protected"], ["UDP", "127.0.0.53:53", "resolved", "Local", "UNCONN", "protected"]] },
    storage: { kicker: "FILESYSTEM & BLOCK I/O", title: "Storage", description: "Review block topology, mount capacity, inode pressure, I/O signals and unallocated devices.", category: "Storage", heads: ["DEVICE", "MOUNT", "TYPE", "SIZE", "USED", "INODES"], rows: [["/dev/mapper/ubuntu--vg-ubuntu--lv", "/", "ext4", "96 GB", "31%", "12%"], ["/dev/sda2", "/boot", "ext4", "2 GB", "18%", "4%"], ["/dev/sda1", "/boot/efi", "vfat", "1 GB", "6%", "1%"], ["/dev/sdb", "—", "disk", "100 GB", "unallocated", "—"]] },
    users: { kicker: "IDENTITY & ACCESS", title: "Users & sessions", description: "Audit human and service identities, interactive shells, privileged groups and active sessions without exposing credentials.", category: "Users & Security", heads: ["IDENTITY", "UID", "TYPE", "GROUPS", "SHELL", "SESSIONS"], rows: [["root", "0", "superuser", "root", "/bin/bash", "0"], ["user", "1000", "human", "sudo, adm, systemd-journal", "/bin/bash", "1"], ["opspilot", "998", "service", "opspilot", "/usr/sbin/nologin", "0"], ["www-data", "33", "service", "www-data", "/usr/sbin/nologin", "0"], ["backup", "997", "service", "backup", "/usr/sbin/nologin", "0"]] },
    security: { kicker: "HOST HARDENING", title: "Security posture", description: "Turn SSH, account, kernel, patch and network evidence into a prioritized review queue.", category: "Users & Security", heads: ["CONTROL", "STATE", "EVIDENCE", "SEVERITY", "OWNER", "NEXT CHECK"], rows: [["SSH root login", "disabled", "PermitRootLogin no", "pass", "platform", "sshd -T"], ["Password auth", "disabled", "PasswordAuthentication no", "pass", "platform", "sshd -T"], ["Backend exposure", "protected", "3000/3100 loopback", "pass", "opspilot", "ss -lntup"], ["SSH boundary", "review", "0.0.0.0:22", "medium", "network", "ip route show"], ["Package updates", "7 pending", "apt inventory", "info", "platform", "apt list --upgradable"]] },
  };
  const config = configs[view];
  const quick = commands.filter(command => command.category === config.category).slice(0, 5);
  return <div className="view"><PageTitle kicker={config.kicker} title={config.title} description={config.description} actions={<button className="primary" onClick={() => navigate("commands")}>Open command center</button>} />
    <div className="table-toolbar"><label>⌕ <input placeholder={`Filter ${config.title.toLowerCase()}…`} /></label><button>All</button><button>Warnings</button><button>Export</button><span>LIVE · 5s</span></div>
    <Panel title={`${config.title} inventory`} kicker="REAL-TIME SNAPSHOT" className="data-panel"><div className="data-table"><table><thead><tr>{config.heads.map(head => <th key={head}>{head}</th>)}</tr></thead><tbody>{config.rows.map((row, index) => <tr key={index}>{row.map((cell, col) => <td key={col}>{col === 0 ? <b>{cell}</b> : col === 1 && (view === "processes" || view === "users") ? <code>{cell}</code> : cell}</td>)}</tr>)}</tbody></table></div></Panel>
    <Panel title="Recommended diagnostics" kicker="SAFE READ-ONLY COMMANDS"><div className="command-cards">{quick.map(command => <button key={command.id} onClick={() => run(command)}><span><code>$ {command.command}</code><small>{command.description}</small></span><b>RUN</b></button>)}</div></Panel>
  </div>;
}

function CommandsView({ run }: { run: (command: CommandSpec) => void }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const filtered = commands.filter(item => (category === "All" || item.category === category) && `${item.command} ${item.description}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="view command-view"><PageTitle kicker="ALLOWLISTED DIAGNOSTICS" title={`${commands.length} server commands`} description="Run accurate, read-only Linux diagnostics from the browser. No arbitrary shell input, pipes from user input, sudo, mutation, or background jobs." actions={<Status>token protected</Status>} />
    <section className="command-safety"><div><span>01</span><b>Fixed allowlist</b><small>Every command and argument is reviewed in code</small></div><div><span>02</span><b>Hard timeout</b><small>8 seconds with a 64 KB output ceiling</small></div><div><span>03</span><b>Audit ledger</b><small>Actor, source, command, duration and exit code</small></div><div><span>04</span><b>Least privilege</b><small>Non-root service with systemd hardening</small></div></section>
    <div className="command-filter"><label>⌕<input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search command or outcome — try lsblk, uptime, sockets, users…" /></label><select value={category} onChange={event => setCategory(event.target.value)}><option>All</option>{Object.keys(commandGroups).map(group => <option key={group}>{group}</option>)}</select><span><b>{filtered.length}</b> visible</span></div>
    <div className="category-tabs"><button className={category === "All" ? "active" : ""} onClick={() => setCategory("All")}>All <b>{commands.length}</b></button>{Object.entries(commandGroups).map(([group, items]) => <button className={category === group ? "active" : ""} onClick={() => setCategory(group)} key={group}>{group} <b>{items.length}</b></button>)}</div>
    <section className="command-table"><header><span>COMMAND</span><span>WHAT IT PROVES</span><span>CLASS</span><span>ACCESS</span><span /></header>{filtered.map(command => <article key={command.id}><span><i>&gt;_</i><code>{command.command}</code></span><p>{command.description}</p><em>{command.category}</em><Status tone={command.risk === "review" ? "warn" : "good"}>{command.risk === "review" ? "scoped" : "read only"}</Status><button onClick={() => run(command)}>Run <b>↗</b></button></article>)}</section>
  </div>;
}

function AIView({ run }: { run: (command: CommandSpec) => void }) {
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<{ role: "user" | "ai"; text: string }[]>([
    { role: "ai", text: "I have the current host snapshot: CPU 23%, memory 45%, root filesystem 31%, no failed units, and one SSH exposure review. Ask me to investigate a symptom or explain command evidence." },
  ]);
  const ask = (value?: string) => {
    const text = (value || question).trim();
    if (!text) return;
    setMessages(current => [...current, { role: "user", text }, { role: "ai", text: "The strongest evidence points to a healthy host with no saturation. For a defensible answer, I would run uptime, vmstat 1 2, systemctl --failed, ss -lntup, and journalctl -p err -n 50. I will explain each result and keep execution behind your approval." }]);
    setQuestion("");
  };
  const suggested = commands.filter(command => ["uptime", "vmstat 1 2", "systemctl --failed --no-pager", "ss -lntup", "journalctl -p err -n 50 --no-pager"].includes(command.command));
  return <div className="view"><PageTitle kicker="AI-ASSISTED OPERATIONS" title="OpsPilot AI investigator" description="Natural-language reasoning grounded in current metrics and approved command evidence. The model recommends diagnostics; you remain in control of execution." actions={<Status>server-side key</Status>} />
    <section className="ai-layout"><div className="ai-chat panel"><header><div className="ai-orb">✦</div><div><b>Investigation thread</b><small>GPT-5.6 · Responses API · evidence only</small></div><Status>ready</Status></header><div className="messages">{messages.map((message, index) => <article className={message.role} key={index}><span>{message.role === "ai" ? "✦" : "SV"}</span><p>{message.text}</p></article>)}</div><div className="prompt-box"><textarea value={question} onChange={event => setQuestion(event.target.value)} placeholder="Ask: Why is the server slow? Is storage healthy? Who is logged in?" /><footer><span>Output is redacted and truncated before AI analysis</span><button onClick={() => ask()}>Investigate ✦</button></footer></div></div>
      <aside className="evidence-rail"><Panel kicker="CURRENT EVIDENCE" title="Host context"><div className="evidence-list"><span><i className="good" /><b>CPU</b><em>23% · normal</em></span><span><i className="good" /><b>Memory</b><em>45% · no swap</em></span><span><i className="good" /><b>Disk</b><em>31% · 66 GB free</em></span><span><i className="warn" /><b>SSH</b><em>0.0.0.0:22</em></span><span><i className="good" /><b>Services</b><em>0 failed</em></span></div></Panel><Panel kicker="AI GUARDRAILS" title="What AI can do"><ul className="guardrail-list"><li>Explain metrics and command output</li><li>Correlate signals into likely causes</li><li>Recommend allowlisted checks</li><li>Build a read-only investigation plan</li><li className="blocked">Cannot execute without your click</li><li className="blocked">Cannot run sudo or mutate the VM</li></ul></Panel></aside></section>
    <Panel kicker="RECOMMENDED NEXT CHECKS" title="Evidence plan"><div className="ai-plan">{suggested.map((command, index) => <button key={command.id} onClick={() => run(command)}><span>{String(index + 1).padStart(2, "0")}</span><div><code>$ {command.command}</code><small>{command.description}</small></div><b>Run →</b></button>)}</div></Panel>
    <div className="prompt-chips">{["Why did CPU spike?", "Check whether disk is safe", "Explain the SSH exposure", "Build a senior health check"].map(item => <button onClick={() => ask(item)} key={item}>✦ {item}</button>)}</div>
  </div>;
}

function IncidentsView({ navigate }: { navigate: (view: View) => void }) {
  return <div className="view"><PageTitle kicker="RESPONSE WORKSPACE" title="Incidents" description="Tie alerts, evidence, commands, annotations, ownership and AI findings into one defensible operational timeline." actions={<button className="primary">Create incident</button>} />
    <section className="incident-summary"><article><span>OPEN</span><b>1</b><small>No critical incidents</small></article><article><span>MTTA</span><b>2m 14s</b><small>Lab rolling average</small></article><article><span>MTTR</span><b>18m</b><small>Last 30 days</small></article><article><span>CHANGE RISK</span><b>Low</b><small>No deployment regression</small></article></section>
    <Panel kicker="ACTIVE INVESTIGATION" title="INC-0042 · SSH boundary review" action={<Status tone="warn">SEV-3</Status>}><div className="incident-body"><div className="incident-main"><header><span>Owner <b>On-call Engineer</b></span><span>Started <b>6 minutes ago</b></span><span>Status <b>Investigating</b></span></header><h3>SSH is listening on all interfaces</h3><p>The listener is expected for remote administration, but the source boundary should be validated against the VM network controls before production use.</p><div className="incident-actions"><button onClick={() => navigate("network")}>Open network evidence</button><button onClick={() => navigate("ai")}>Ask AI for investigation</button><button onClick={() => navigate("commands")}>Run safe checks</button></div></div><ol><li><time>09:31</time><i className="warn" /><span><b>Authentication warning observed</b><small>Invalid user admin · 198.51.100.23</small></span></li><li><time>09:33</time><i className="info" /><span><b>Socket evidence attached</b><small>ss -lntup · 0.0.0.0:22</small></span></li><li><time>09:35</time><i className="good" /><span><b>Root login policy verified</b><small>PermitRootLogin no</small></span></li></ol></div></Panel>
  </div>;
}

function PageTitle({ kicker, title, description, actions }: { kicker: string; title: string; description: string; actions?: React.ReactNode }) {
  return <header className="page-title"><div><span>{kicker}</span><h1>{title}</h1><p>{description}</p></div>{actions && <div className="page-actions">{actions}</div>}</header>;
}

function TerminalModal({ command, close, explain }: { command: CommandSpec; close: () => void; explain: () => void }) {
  const [phase, setPhase] = useState<"running" | "done">("running");
  useEffect(() => { const timer = window.setTimeout(() => setPhase("done"), 650); return () => window.clearTimeout(timer); }, []);
  return <div className="modal-layer" onMouseDown={close}><section className="terminal-modal" onMouseDown={event => event.stopPropagation()}><header><div><span>&gt;_</span><b>Command evidence</b><small>opspilot-node-01 · token authorized</small></div><button onClick={close}>×</button></header><div className="terminal-meta"><span><small>COMMAND</small><code>{command.command}</code></span><span><small>POLICY</small><Status>read only</Status></span><span><small>TIMEOUT</small><b>8 seconds</b></span><span><small>AUDIT</small><b>recorded</b></span></div><pre><code><i>$ {command.command}</i>{"\n"}{phase === "running" ? "Running allowlisted diagnostic…" : outputFor(command.command)}{phase === "done" && "\n\n[exit 0 · 42 ms · 2026-07-31T09:42:31Z]"}</code></pre><footer><span>{phase === "done" ? "✓ Output captured within 64 KB policy" : "● Executing as unprivileged opspilot service"}</span><div><button onClick={() => navigator.clipboard?.writeText(outputFor(command.command))}>Copy output</button><button className="primary" disabled={phase !== "done"} onClick={explain}>✦ Explain with AI</button></div></footer></section></div>;
}

// Kept temporarily as a parity reference while the Fluent experience replaces v0.6.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function LegacyHome() {
  const [view, setView] = useState<View>("pulse");
  const [samples, setSamples] = useState(initialSamples);
  const [mobileNav, setMobileNav] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [command, setCommand] = useState<CommandSpec | null>(null);
  const [search, setSearch] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [notice, setNotice] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => typeof window !== "undefined" && window.localStorage.getItem("opspilot-theme") === "light" ? "light" : "dark");
  const [nodeState, setNodeState] = useState<NodeState>("online");

  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);

  const toggleTheme = () => setTheme(current => {
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("opspilot-theme", next);
    return next;
  });

  useEffect(() => {
    const timer = window.setInterval(() => setSamples(current => {
      const last = current.at(-1)!;
      const drift = (value: number, amount: number, min: number, max: number) => Math.max(min, Math.min(max, value + (Math.random() - .48) * amount));
      return [...current.slice(1), { cpu: Math.round(drift(last.cpu, 15, 10, 72)), memory: Math.round(drift(last.memory, 3, 40, 54)), disk: 31, load: +drift(last.load, .17, .1, 1.1).toFixed(2), rx: +drift(last.rx, 2, 1.2, 10).toFixed(1), tx: +drift(last.tx, 1, .5, 5).toFixed(1) }];
    }), 5000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setSearchOpen(true); }
      if (event.key === "Escape") { setSearchOpen(false); setCommand(null); setNotice(false); setMobileNav(false); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const active = nav.flatMap(group => group.items).find(item => item.id === view)!;
  const navigate = (next: View) => { setView(next); setMobileNav(false); setSearchOpen(false); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const run = (next: CommandSpec) => setCommand(next);
  const searchItems = useMemo(() => {
    const text = search.toLowerCase();
    return [
      ...nav.flatMap(group => group.items).filter(item => item.label.toLowerCase().includes(text)).map(item => ({ type: "view" as const, id: item.id, label: item.label, detail: "Open workspace" })),
      ...commands.filter(item => `${item.command} ${item.description}`.toLowerCase().includes(text)).slice(0, 8).map(item => ({ type: "command" as const, id: item.id, label: item.command, detail: item.description })),
    ].slice(0, 12);
  }, [search]);

  const content = () => {
    if (view === "pulse") return <MissionControl samples={samples} navigate={navigate} run={run} nodeState={nodeState} setNodeState={setNodeState} />;
    if (view === "infrastructure") return <InfrastructureView navigate={navigate} />;
    if (view === "metrics") return <MetricsView samples={samples} />;
    if (view === "commands") return <CommandsView run={run} />;
    if (view === "ai") return <AIView run={run} />;
    if (view === "incidents") return <IncidentsView navigate={navigate} />;
    return <TableView view={view} run={run} navigate={navigate} />;
  };

  return <main className={`app ${collapsed ? "collapsed" : ""} state-${nodeState}`}>
    <aside className={`sidebar ${mobileNav ? "open" : ""}`}>
      <header className="brand"><button onClick={() => navigate("pulse")}><span className="logo"><i /><i /><i /></span><div><b>OpsPilot</b><small>AI SERVER OPERATIONS</small></div></button><button className="collapse" onClick={() => setCollapsed(value => !value)}>{collapsed ? "›" : "‹"}</button><button className="mobile-close" onClick={() => setMobileNav(false)}>×</button></header>
      <button className="host-card" onClick={() => navigate("infrastructure")}><span className="host-node"><i />01</span><div><small>CONNECTED NODE</small><b>opspilot-node-01</b><em>192.0.2.10</em></div><Status>live</Status></button>
      <nav>{nav.map(group => <section key={group.group}><span>{group.group}</span>{group.items.map(item => <button className={item.id === view ? "active" : ""} onClick={() => navigate(item.id)} key={item.id} title={item.label}><i>{item.icon}</i><b>{item.label}</b>{item.badge && <em>{item.badge}</em>}</button>)}</section>)}</nav>
      <div className="agent-state"><span className="agent-orbit"><i /><b /></span><div><b>Collector online</b><small>Pulse 2 seconds ago</small></div><i className="live-dot" /></div>
      <footer><span>v0.5 ADVANCED</span><b>DEMO / READ ONLY</b></footer>
    </aside>
    {mobileNav && <button className="scrim" onClick={() => setMobileNav(false)} />}
    <section className="workspace">
      <header className="topbar"><button className="menu" onClick={() => setMobileNav(true)}>☰</button><div className="crumb"><span>INFRASTRUCTURE</span><i>/</i><b>opspilot-node-01</b><i>/</i><strong>{active.label}</strong></div><div className="top-controls"><label>ENV<select><option>lab</option><option>prod</option></select></label><label>RANGE<select><option>30m</option><option>1h</option><option>6h</option></select></label><span className="refresh"><i />5s</span><button className="global-search" onClick={() => setSearchOpen(true)}>⌕ <span>Search metrics, logs or commands</span><kbd>Ctrl K</kbd></button><button className="theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}><span>{theme === "dark" ? "☀" : "☾"}</span><b>{theme === "dark" ? "Light" : "Dark"}</b></button><button className="notification" onClick={() => setNotice(value => !value)}>♢<i /></button><button className="profile"><span>SV</span><div><b>On-call Engineer</b><small>Server engineer</small></div></button></div>{notice && <div className="notifications"><header><b>Operational signals</b><span>3 unread</span></header><button onClick={() => navigate("security")}><i className="warn" /><span><b>SSH boundary review</b><small>Port 22 · 6m ago</small></span></button><button onClick={() => navigate("services")}><i className="good" /><span><b>Core services healthy</b><small>5 / 5 · 9m ago</small></span></button><button onClick={() => navigate("logs")}><i className="info" /><span><b>nginx reload</b><small>Validated · 18m ago</small></span></button></div>}</header>
      <div className="content">{content()}<footer className="page-footer"><span><i />Hosted demonstration uses realistic simulated data · VM package connects to real read-only telemetry and command evidence</span><span>OpsPilot v0.5 · 5s pulse · AI optional</span></footer></div>
    </section>

    {command && <TerminalModal command={command} close={() => setCommand(null)} explain={() => { setCommand(null); navigate("ai"); }} />}
    {nodeState === "offline" && <section className="outage-mode" role="alert" aria-live="assertive">
      <div className="storm-layer"><i /><i /><i /><i /></div><div className="ember-layer">{Array.from({ length: 18 }, (_, index) => <i key={index} />)}</div>
      <div className="outage-core"><span className="outage-mark"><i /><b>!</b></span><small>SEV-1 · HEARTBEAT FAILURE</small><h1>opspilot-node-01<br /><em>is unreachable</em></h1><p>No valid telemetry response has arrived within the outage threshold. The last loaded dashboard remains active so you can see the alarm even while the VM reboots or hangs.</p><div className="outage-facts"><span><small>LAST SIGNAL</small><b>12 seconds ago</b></span><span><small>ADDRESS</small><b>192.0.2.10</b></span><span><small>DETECTION</small><b>3 failed probes</b></span></div><div className="outage-actions"><button onClick={() => { setNodeState("warning"); navigate("incidents"); }}>Open incident room</button><button onClick={() => setNodeState("online")}>Restore demo signal</button></div><footer><i />OpsPilot AI has prepared a reboot/down-state investigation plan</footer></div>
    </section>}
    {searchOpen && <div className="modal-layer" onMouseDown={() => setSearchOpen(false)}><section className="search-modal" onMouseDown={event => event.stopPropagation()}><header>⌕<input autoFocus value={search} onChange={event => setSearch(event.target.value)} placeholder="Search metrics, logs, users or a Linux command…" /><kbd>ESC</kbd></header><span>RESULTS</span>{searchItems.map(item => <button key={`${item.type}-${item.id}`} onClick={() => item.type === "view" ? navigate(item.id as View) : run(commands.find(command => command.id === item.id)!)}><i>{item.type === "view" ? "⌁" : ">_"}</i><div><b>{item.label}</b><small>{item.detail}</small></div><em>{item.type === "view" ? "OPEN" : "RUN"} →</em></button>)}</section></div>}
  </main>;
}

type FluentView = "pulse" | "metrics" | "services" | "logs" | "commands" | "users" | "security" | "incidents" | "ai";
type DetailMetric = "CPU" | "Memory" | "Root filesystem" | "System load" | null;

const fluentNav: { group: string; items: { id: FluentView; label: string; badge?: string }[] }[] = [
  { group: "MONITOR", items: [
    { id: "pulse", label: "Overview" },
    { id: "metrics", label: "Metrics explorer" },
    { id: "services", label: "Services" },
    { id: "logs", label: "Live logs", badge: "24" },
  ] },
  { group: "OPERATE", items: [
    { id: "commands", label: "Diagnostics", badge: String(commands.length) },
    { id: "users", label: "Users & access" },
    { id: "security", label: "Security posture", badge: "1" },
    { id: "incidents", label: "Incidents" },
  ] },
  { group: "INTELLIGENCE", items: [{ id: "ai", label: "OpsPilot AI" }] },
];

function FluentIcon({ view }: { view: FluentView }) {
  const icons: Record<FluentView, React.ReactNode> = {
    pulse: <Apps24Regular />,
    metrics: <DataTrending24Regular />,
    services: <Server24Regular />,
    logs: <DocumentText24Regular />,
    commands: <Wrench24Regular />,
    users: <PeopleTeam24Regular />,
    security: <Shield24Regular />,
    incidents: <Alert24Regular />,
    ai: <Bot24Regular />,
  };
  return icons[view];
}

function FluentStatus({ tone = "good", children }: { tone?: "good" | "warn" | "bad" | "info"; children: React.ReactNode }) {
  return <span className={`f-status ${tone}`}><i />{children}</span>;
}

function LoginView({ onComplete }: { onComplete: () => void }) {
  const [password, setPassword] = useState("");
  const [phase, setPhase] = useState<"idle" | "handshake" | "success" | "error">("idle");
  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (password.trim().length < 4) { setPhase("error"); return; }
    setPhase("handshake");
    window.setTimeout(() => {
      setPhase("success");
      window.setTimeout(onComplete, 760);
    }, 1100);
  };
  return <main className={`f-login ${phase}`}>
    <div className="f-login-photo" />
    <div className="f-login-grid" />
    <header className="f-login-brand">
      <span className="f-mark"><i /><b>O</b></span>
      <div><strong>OpsPilot</strong><small>SECURE INFRASTRUCTURE INTELLIGENCE</small></div>
      <span className="f-login-live"><i /> Demo DC · Link secure</span>
    </header>
    <section className="f-login-copy">
      <span className="f-eyebrow">NOC COMMAND CENTER · NODE 01</span>
      <h1>Inside the signal.<br /><em>Ahead of the incident.</em></h1>
      <p>Unrivaled Insight. Precision Control.</p>
      <div className="f-login-facts"><span><b>01</b><small>CONNECTED NODE</small></span><span><b>{commands.length}</b><small>SAFE DIAGNOSTICS</small></span><span><b>5s</b><small>LIVE PULSE</small></span></div>
    </section>
    <form className="f-handshake" onSubmit={submit}>
      <header><span className="f-core-icon"><i /><b /></span><div><small>AUTHORIZED ACCESS</small><h2>NOC Command Center</h2><p>for OpsPilot Node</p></div></header>
      <label htmlFor="secure-key">Secure passphrase or console token</label>
      <div className="f-key-field"><Shield24Regular /><input id="secure-key" type="password" value={password} onChange={event => { setPassword(event.target.value); setPhase("idle"); }} placeholder="Enter secure credential" autoComplete="current-password" /><span>{password ? "••" : ""}</span></div>
      <div className="f-trace"><i style={{ width: `${Math.min(100, password.length * 10)}%` }} /></div>
      <div className="f-handshake-state" aria-live="polite">
        <span className={password.length > 0 ? "active" : ""}><i />Identity channel</span>
        <span className={password.length > 3 ? "active" : ""}><i />Token integrity</span>
        <span className={phase === "handshake" || phase === "success" ? "active" : ""}><i />Core handshake</span>
      </div>
      {phase === "error" && <p className="f-login-error">Enter at least four characters to initiate the secure demo handshake.</p>}
      <Button appearance="primary" size="large" type="submit" className="f-unlock" disabled={phase === "handshake"}>{phase === "handshake" ? <><ArrowSync24Regular className="f-spin" /> Negotiating secure handshake…</> : phase === "success" ? <>✓ Server core unlocked</> : <>Initiate secure handshake</>}</Button>
      <footer><span><i />TLS tunnel ready</span><span>Demo: any 4+ characters</span></footer>
    </form>
    <footer className="f-login-footer"><span>OPS / LIVINGSTON / OPSPILOT-NODE-01</span><span>Protected operations boundary · Read-only diagnostics</span></footer>
  </main>;
}

function FluentSpark({ values, color }: { values: number[]; color: string }) {
  const d = path(values, 180, 54);
  return <svg className="f-spark" viewBox="0 0 180 54" preserveAspectRatio="none" aria-hidden="true"><path d={`${d} L180,54 L0,54Z`} fill={`${color}1f`} /><path d={d} stroke={color} strokeWidth="2.5" fill="none" /></svg>;
}
function buildDemoHistory(range: HistoryRange): MetricSample[] {
  const points = range === "15m" ? 36 : range === "30m" ? 48 : range === "1h" ? 60 : 72;
  const last = initialSamples.at(-1)!;
  return Array.from({ length: points }, (_, index) => {
    const phase = index / Math.max(1, points - 1);
    const wave = Math.sin(phase * Math.PI * 5.5) + Math.sin(phase * Math.PI * 13) * .35;
    return {
      cpu: Math.max(4, Math.min(92, Math.round(last.cpu + wave * 11 + (phase - .5) * 4))),
      memory: Math.max(20, Math.min(94, Math.round(last.memory + Math.sin(phase * Math.PI * 2.2) * 3))),
      disk: last.disk,
      load: Math.max(.04, +(last.load + wave * .09).toFixed(2)),
      rx: Math.max(.1, +(last.rx + wave * .8).toFixed(1)),
      tx: Math.max(.1, +(last.tx + wave * .35).toFixed(1)),
    };
  });
}

function PolarBear({ size = "medium", mood = "snacking" }: { size?: "small" | "medium" | "large"; mood?: "snacking" | "watching" }) {
  return <span className={`polar-bear ${size} ${mood}`} aria-label="OpsPilot polar bear AI companion">
    <svg viewBox="0 0 88 88" role="img">
      <ellipse className="bear-shadow" cx="44" cy="78" rx="28" ry="6" />
      <g className="bear-body">
        <ellipse cx="44" cy="57" rx="25" ry="23" className="bear-fur" />
        <circle cx="27" cy="25" r="10" className="bear-ear" />
        <circle cx="61" cy="25" r="10" className="bear-ear" />
        <circle cx="44" cy="36" r="25" className="bear-head" />
        <g className="bear-face">
          <circle cx="36" cy="34" r="2.4" className="bear-eye" />
          <circle cx="52" cy="34" r="2.4" className="bear-eye" />
          <ellipse cx="44" cy="43" rx="8" ry="6" className="bear-muzzle" />
          <path d="M41 41 Q44 38 47 41 Q44 45 41 41Z" className="bear-nose" />
          <path d="M44 44 Q43 48 39 48 M44 44 Q45 48 49 48" className="bear-mouth" />
        </g>
        <ellipse cx="27" cy="59" rx="8" ry="14" className="bear-paw left" />
        <g className="snack-arm"><ellipse cx="61" cy="59" rx="8" ry="14" className="bear-paw" /><rect x="58" y="49" width="10" height="12" rx="3" className="bear-snack" /><circle cx="61" cy="52" r="1" /><circle cx="65" cy="56" r="1" /></g>
        <ellipse cx="31" cy="75" rx="11" ry="7" className="bear-foot" />
        <ellipse cx="57" cy="75" rx="11" ry="7" className="bear-foot" />
      </g>
      <circle cx="72" cy="18" r="4" className="bear-ai-led" />
    </svg>
  </span>;
}

function MetricHardwareIcon({ metric }: { metric: string }) {
  const kind = metric.toLowerCase().replace(/\s+/g, "-");
  return <span className={`metric-hardware-icon ${kind}`} aria-hidden="true">
    <svg viewBox="0 0 48 48">
      <g className="hardware-cube">
        <path d="M14 14 27 8l10 7-13 7z" />
        <path d="m14 14 10 8v15L14 30z" />
        <path d="m24 22 13-7v15l-13 7z" />
        <path className="hardware-glow" d="M19 17 27 13l5 3-8 4z" />
      </g>
      <g className="hardware-pins">
        <path d="M9 17h6M9 24h6M9 31h6M36 18h5M36 25h5M36 32h5M19 8V4M26 8V4M32 11V6M19 37v6M26 37v6M32 34v6" />
      </g>
    </svg>
  </span>;
}

function ServerRack({ state }: { state: NodeState }) {
  return <div className={`server-rack ${state}`} aria-label={`Animated server rack: ${state}`}>
    <svg viewBox="0 0 128 92" role="img">
      <defs><linearGradient id="rackMetal" x1="0" x2="1"><stop stopColor="#172433" /><stop offset=".5" stopColor="#36516a" /><stop offset="1" stopColor="#111b26" /></linearGradient></defs>
      <rect x="8" y="5" width="112" height="82" rx="9" className="rack-shell" />
      {[0,1,2,3].map(row => <g key={row} transform={`translate(0 ${row * 18})`}>
        <rect x="17" y="13" width="94" height="13" rx="3" className="rack-unit" />
        <path d="M24 18h35M24 22h25" className="rack-slot" />
        <circle cx="91" cy="19.5" r="2.3" className="rack-led green" />
        <circle cx="100" cy="19.5" r="2.3" className="rack-led blue" />
      </g>)}
      <path d="M30 87h68" className="rack-floor" />
      <path d="M64 8v76" className="rack-scan" />
    </svg>
    <span><i />LIVE I/O</span>
  </div>;
}

function DualClockHeader({ nodeState, setNodeState }: { nodeState: NodeState; setNodeState: (state: NodeState) => void }) {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => { const timer = window.setInterval(() => setNow(new Date()), 1000); return () => window.clearInterval(timer); }, []);
  const clock = (zone: string) => new Intl.DateTimeFormat("en-GB", { timeZone: zone, hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(now);
  return <section className={`f-state-banner time-server-header ${nodeState}`}>
    <div className="health-radar-mini"><span /><i /><b /></div>
    <div className="clock-cluster"><small>LIVINGSTON SERVER · NODE 01</small><div className="dual-clocks"><article><span>UTC</span><time>{clock("UTC")}</time><small>Coordinated universal</small></article><article><span>IST</span><time>{clock("Asia/Kolkata")}</time><small>Asia / Kolkata</small></article></div></div>
    <ServerRack state={nodeState} />
    <div className="f-state-controls"><span>SIMULATE</span>{(["online","warning","offline"] as NodeState[]).map(state => <button key={state} className={nodeState === state ? "active" : ""} onClick={() => setNodeState(state)}>{state === "offline" ? "Outage" : state[0].toUpperCase() + state.slice(1)}</button>)}</div>
  </section>;
}

function HealthCore({ score, state }: { score: number; state: NodeState }) {
  return <div className={`health-core ${state}`} style={{ "--score": score } as React.CSSProperties}>
    <div className="health-orbit one" /><div className="health-orbit two" /><div className="radar-sweep" />
    <svg viewBox="0 0 180 76" aria-hidden="true"><path className="ekg-base" d="M4 42h36l8-18 11 38 12-31 8 11h35l8-21 12 42 11-33 9 12h22" /><path className="ekg-live" pathLength="1" d="M4 42h36l8-18 11 38 12-31 8 11h35l8-21 12 42 11-33 9 12h22" /></svg>
    <span><b>{score}</b><small>{state === "online" ? "COMPOSED" : state === "warning" ? "ATTENTION" : "OFFLINE"}</small></span>
  </div>;
}

function RangeSelector({ value, onChange, loading }: { value: HistoryRange; onChange: (range: HistoryRange) => void; loading?: boolean }) {
  return <div className={`f-segmented range-selector ${loading ? "loading" : ""}`} aria-label="Historical metric range">
    {historyRanges.map(range => <button key={range} className={value === range ? "active" : ""} onClick={() => onChange(range)} aria-pressed={value === range}>{range}</button>)}
  </div>;
}

function MetricMenu({ metric, onOpen, onJira, onAI }: { metric: string; onOpen: () => void; onJira: () => void; onAI: () => void }) {
  const actions: Record<string, string[]> = {
    CPU: ["View processes", "Configure thresholds", "Check historical data"],
    Memory: ["Inspect consumers", "Review swap policy", "Check historical data"],
    "Root filesystem": ["Inspect large paths", "Review inode usage", "Forecast capacity"],
    "System load": ["Inspect run queue", "Correlate I/O pressure", "Check historical data"],
  };
  return <Menu positioning="below-end">
    <MenuTrigger disableButtonEnhancement><Button appearance="subtle" icon={<MoreVertical24Regular />} aria-label={`More options for ${metric}`} className="f-more" /></MenuTrigger>
    <MenuPopover className="f-menu-pop"><MenuList>
      {(actions[metric] || []).map(item => <MenuItem key={item} onClick={onOpen}>{item}</MenuItem>)}
      <MenuItem icon={<Bot24Regular />} onClick={onAI}>Ask OpsPilot AI</MenuItem>
      <MenuItem icon={<TicketDiagonal24Regular />} onClick={onJira}>Create Jira ticket</MenuItem>
    </MenuList></MenuPopover>
  </Menu>;
}

function FluentMetricCard({ label, value, detail, icon, color, values, tone, onOpen, onJira, onAI }: { label: string; value: string; detail: string; icon: React.ReactNode; color: string; values: number[]; tone?: "normal" | "warning" | "critical"; onOpen: () => void; onJira: () => void; onAI: () => void }) {
  const trackSpotlight = (event: React.PointerEvent<HTMLElement>) => { const box = event.currentTarget.getBoundingClientRect(); event.currentTarget.style.setProperty("--spot-x", `${event.clientX - box.left}px`); event.currentTarget.style.setProperty("--spot-y", `${event.clientY - box.top}px`); };
  return <article className={`f-metric-card ${tone || "normal"}`} onPointerMove={trackSpotlight} style={{ "--metric": color, "--spot-x": "50%", "--spot-y": "0px" } as React.CSSProperties}>
    <header><span className="f-metric-icon"><MetricHardwareIcon metric={label} /><span className="legacy-metric-icon">{icon}</span></span><div><small>{label}</small><FluentStatus tone={tone === "critical" ? "bad" : tone === "warning" ? "warn" : "good"}>{tone === "critical" ? "critical" : tone === "warning" ? "attention" : "healthy"}</FluentStatus></div><MetricMenu metric={label} onOpen={onOpen} onJira={onJira} onAI={onAI} /></header>
    <button className="f-metric-main" onClick={onOpen}><strong>{value}</strong><span>{detail}</span><FluentSpark values={values} color={color} /></button>
    {tone === "critical" && <Button appearance="primary" icon={<TicketDiagonal24Regular />} className="f-jira-inline" onClick={onJira}>Create Jira Ticket</Button>}
  </article>;
}

function FluentChart({ samples, range, loading = false }: { samples: MetricSample[]; range: HistoryRange; loading?: boolean }) {
  const cpu = path(samples.map(item => item.cpu), 720, 220);
  const memory = path(samples.map(item => item.memory), 720, 220);
  const load = path(samples.map(item => item.load * 32), 720, 220);
  const minutes = historyMinutes[range];
  const tick = (position: number) => { const remaining = Math.round(minutes * (1 - position)); return remaining === 0 ? "Now" : remaining >= 60 ? `-${+(remaining / 60).toFixed(1)}h` : `-${remaining}m`; };
  return <div className="f-chart">
    <header><div><span><i className="cpu" />CPU <b>{samples.at(-1)!.cpu}%</b></span><span><i className="memory" />Memory <b>{samples.at(-1)!.memory}%</b></span><span><i className="load" />Load <b>{samples.at(-1)!.load}</b></span></div><em><i />{loading ? "QUERYING HISTORY" : `${range} · exact interval`}</em></header>
    <div className="f-chart-canvas"><svg viewBox="0 0 720 220" preserveAspectRatio="none" role="img" aria-label="CPU, memory, and system load over the last 30 minutes">
      <defs><linearGradient id="fluentCpu" x1="0" y1="0" x2="0" y2="1"><stop stopColor="#0f6cbd" stopOpacity=".27" /><stop offset="1" stopColor="#0f6cbd" stopOpacity="0" /></linearGradient></defs>
      {[0,55,110,165,220].map(y => <line key={y} x1="0" x2="720" y1={y} y2={y} className="f-gridline" />)}
      <path d={`${cpu} L720,220 L0,220Z`} fill="url(#fluentCpu)" /><path d={cpu} className="f-cpu-line" /><path d={memory} className="f-memory-line" /><path d={load} className="f-load-line" />
      <line x1="472" x2="472" y1="0" y2="220" className="f-event-line" />
    </svg><span className="f-annotation">nginx config reload · 09:24</span>{loading && <span className="history-loading">Loading historical samples…</span>}</div>
    <footer>{[0,.2,.4,.6,.8,1].map(position => <span key={position}>{tick(position)}</span>)}</footer>
  </div>;
}

function FluentPanel({ eyebrow, title, action, children, className = "" }: { eyebrow: string; title: string; action?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return <section className={`f-panel ${className}`}><header className="f-panel-head"><div><small>{eyebrow}</small><h2>{title}</h2></div>{action}</header>{children}</section>;
}

function OverviewView({ samples, historySamples, historyRange, setHistoryRange, historyLoading, setView, openDetail, openJira, openAI, nodeState, setNodeState }: { samples: MetricSample[]; historySamples: MetricSample[]; historyRange: HistoryRange; setHistoryRange: (range: HistoryRange) => void; historyLoading: boolean; setView: (view: FluentView) => void; openDetail: (metric: DetailMetric) => void; openJira: (metric: string) => void; openAI: () => void; nodeState: NodeState; setNodeState: (state: NodeState) => void }) {
  const current = samples.at(-1)!;
  const diskTone = current.disk >= 90 ? "critical" : current.disk >= 80 ? "warning" : "normal";
  return <div className="f-view">
    <DualClockHeader nodeState={nodeState} setNodeState={setNodeState} />
    <section className="f-metrics-grid">
      <FluentMetricCard label="CPU" value={`${current.cpu}%`} detail="4 vCPU · 0.2% iowait" icon={<DesktopPulse24Regular />} color="#0f6cbd" values={samples.map(item => item.cpu)} onOpen={() => openDetail("CPU")} onJira={() => openJira("CPU utilization")} onAI={openAI} />
      <FluentMetricCard label="Memory" value={`${current.memory}%`} detail="Live memory utilization" icon={<Gauge24Regular />} color="#8764b8" values={samples.map(item => item.memory)} tone={current.memory >= 90 ? "critical" : current.memory >= 80 ? "warning" : "normal"} onOpen={() => openDetail("Memory")} onJira={() => openJira("Memory utilization")} onAI={openAI} />
      <FluentMetricCard label="Root filesystem" value={`${current.disk}%`} detail={`${Math.max(0, 100-current.disk)}% capacity remaining`} icon={<Storage24Regular />} color={current.disk >= 80 ? "#c4314b" : "#0f7b0f"} values={samples.map(item => item.disk)} tone={diskTone} onOpen={() => openDetail("Root filesystem")} onJira={() => openJira("Critical root filesystem usage")} onAI={openAI} />
      <FluentMetricCard label="System load" value={current.load.toFixed(2)} detail="1 min · 0.36 per core" icon={<Gauge24Regular />} color="#0f7b0f" values={samples.map(item => item.load * 35)} onOpen={() => openDetail("System load")} onJira={() => openJira("System load review")} onAI={openAI} />
    </section>
    <section className="f-dashboard-grid">
      <FluentPanel eyebrow="LIVE TELEMETRY" title="Resource activity" className="f-wide" action={<RangeSelector value={historyRange} onChange={setHistoryRange} loading={historyLoading} />}><FluentChart samples={historySamples} range={historyRange} loading={historyLoading} /></FluentPanel>
      <FluentPanel eyebrow="AI SIGNAL" title="What needs your attention" action={<button className="f-text-action" onClick={openAI}>Investigate with AI →</button>}><div className="f-ai-signal"><PolarBear size="large" /><div><FluentStatus tone={current.disk >= 90 ? "bad" : current.disk >= 80 ? "warn" : "good"}>{current.disk >= 80 ? "Action recommended" : "System composed"}</FluentStatus><h3>{current.disk >= 90 ? "Root storage is above the critical threshold." : current.disk >= 80 ? "Root storage is approaching the warning threshold." : "No sustained resource pressure is visible."}</h3><p>{current.disk >= 80 ? "OpsPilot recommends confirming filesystem capacity and locating the fastest-growing path." : "CPU, memory, load, and root filesystem remain inside the current operating policy."}</p><div><button onClick={() => openDetail(current.disk >= 80 ? "Root filesystem" : "CPU")}>Review evidence</button>{current.disk >= 80 && <button onClick={() => openJira("Critical root filesystem usage")}>Create Jira ticket</button>}</div></div></div></FluentPanel>
      <FluentPanel eyebrow="RESOURCE POSTURE" title="Health composition" action={<strong className="f-health-score">82 / 100</strong>}><div className="f-donut-wrap"><HealthCore score={82} state={nodeState} /><ul><li><i className="blue" />Compute <b>Healthy</b></li><li><i className="violet" />Memory <b>Attention</b></li><li><i className="red" />Storage <b>Critical</b></li><li><i className="green" />Network <b>Healthy</b></li></ul></div></FluentPanel>
      <FluentPanel eyebrow="FAST EVIDENCE" title="One-click diagnostics" action={<button className="f-text-action" onClick={() => setView("commands")}>All {commands.length} commands →</button>}><div className="f-quick-commands">{commands.filter(item => ["uptime", "lsblk", "free -h", "df -hT", "ss -lntup"].includes(item.command)).map(item => <button key={item.id} onClick={() => window.dispatchEvent(new CustomEvent("opspilot-command", { detail: item }))}><span>&gt;_</span><code>{item.command}</code><b>Run</b></button>)}</div></FluentPanel>
      <FluentPanel eyebrow="SERVICE PULSE" title="Critical services"><div className="f-service-list">{[["nginx.service","Reverse proxy","Healthy"],["opspilot.service","API · :3000","Healthy"],["dashboard-agent","Telemetry · :3100","Healthy"],["ssh.service","Remote access","Review"]].map(row => <button key={row[0]} onClick={() => setView("services")}><span className="f-service-glyph"><Server24Regular /></span><span><b>{row[0]}</b><small>{row[1]}</small></span><FluentStatus tone={row[2] === "Review" ? "warn" : "good"}>{row[2]}</FluentStatus></button>)}</div></FluentPanel>
    </section>
  </div>;
}

const tableConfig: Record<Exclude<FluentView, "pulse" | "metrics" | "commands" | "ai">, { eyebrow: string; title: string; description: string; heads: string[]; rows: string[][] }> = {
  services: { eyebrow: "SYSTEMD CONTROL PLANE", title: "Services", description: "Inspect state, dependencies, recovery policy, resource usage, and recent transitions.", heads: ["UNIT","DESCRIPTION","STATE","PID","MEMORY","LAST CHANGE"], rows: [["nginx.service","Reverse proxy · port 80","Active","812","14.2 MB","18m ago"],["opspilot.service","FastAPI · loopback :3000","Active","4001","42.6 MB","4h ago"],["dashboard-agent.service","Telemetry · loopback :3100","Active","4128","31.8 MB","2h ago"],["ssh.service","Remote access · port 22","Active","934","9.4 MB","4h ago"],["myname.timer","Lab automation · every 2 min","Waiting","—","—","46s ago"]] },
  logs: { eyebrow: "JOURNAL EXPLORER", title: "Live logs", description: "Correlate authentication, kernel, systemd, Nginx, and application evidence.", heads: ["TIME","LEVEL","UNIT","MESSAGE","CONTEXT"], rows: [["09:32:42","Info","opspilot","Telemetry sweep completed","41 ms"],["09:31:01","Warning","sshd","Failed publickey for invalid user admin","198.51.100.23"],["09:30:00","Info","myname","Scheduled automation finished","exit 0"],["09:25:14","Error","apt","Mirror retry recovered after timeout","recovered"],["09:24:10","Info","nginx","Configuration reload completed","validated"]] },
  users: { eyebrow: "IDENTITY & ACCESS", title: "Users & access", description: "Audit human and service identities, interactive shells, groups, and sessions without exposing credentials.", heads: ["IDENTITY","UID","TYPE","GROUPS","SHELL","SESSION"], rows: [["root","0","Superuser","root","/bin/bash","Offline"],["user","1000","Human","sudo, adm, systemd-journal","/bin/bash","Active"],["opspilot","998","Service","opspilot","/usr/sbin/nologin","None"],["www-data","33","Service","www-data","/usr/sbin/nologin","None"],["backup","997","Service","backup","/usr/sbin/nologin","None"]] },
  security: { eyebrow: "HOST HARDENING", title: "Security posture", description: "Turn SSH, account, kernel, patch, and network evidence into a prioritized review queue.", heads: ["CONTROL","STATE","EVIDENCE","SEVERITY","OWNER","NEXT CHECK"], rows: [["SSH root login","Disabled","PermitRootLogin no","Pass","Platform","sshd -T"],["Password auth","Disabled","PasswordAuthentication no","Pass","Platform","sshd -T"],["Backend exposure","Protected","3000/3100 loopback","Pass","OpsPilot","ss -lntup"],["SSH boundary","Review","0.0.0.0:22","Medium","Network","ip route show"],["Package updates","7 pending","APT inventory","Info","Platform","apt list --upgradable"]] },
  incidents: { eyebrow: "RESPONSE WORKSPACE", title: "Incidents", description: "Connect alerts, evidence, AI findings, ownership, Jira tickets, and recovery actions.", heads: ["INCIDENT","SEVERITY","STATUS","OWNER","AGE","JIRA"], rows: [["INC-0043 · Root filesystem pressure","SEV-2","Investigating","On-call Engineer","8m","OPSP-184"],["INC-0042 · SSH boundary review","SEV-3","Monitoring","Platform","32m","OPSP-181"],["INC-0041 · APT mirror timeout","SEV-4","Resolved","Automation","2h","OPSP-176"]] },
};

function DataWorkspace({ view, openJira, goCommands }: { view: keyof typeof tableConfig; openJira: (metric: string) => void; goCommands: () => void }) {
  const config = tableConfig[view];
  return <div className="f-view"><header className="f-page-title"><div><small>{config.eyebrow}</small><h1>{config.title}</h1><p>{config.description}</p></div><div><Button onClick={goCommands}>Open diagnostics</Button>{view === "incidents" && <Button appearance="primary" icon={<TicketDiagonal24Regular />} onClick={() => openJira("New server incident")}>Create Jira Ticket</Button>}</div></header>
    <div className="f-toolbar"><label><Search24Regular /><input placeholder={`Filter ${config.title.toLowerCase()}…`} /></label><button className="active">All</button><button>Warnings</button><button>Export</button><span><i /> LIVE · 5s</span></div>
    <FluentPanel eyebrow="REAL-TIME SNAPSHOT" title={`${config.title} inventory`}><div className="f-data-table"><table><thead><tr>{config.heads.map(head => <th key={head}>{head}</th>)}</tr></thead><tbody>{config.rows.map((row, index) => <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cellIndex === 0 ? <b>{cell}</b> : cell}</td>)}</tr>)}</tbody></table></div></FluentPanel>
    <section className="f-insight-strip"><PolarBear size="small" mood="watching" /><div><small>OPSPILOT AI · CONTEXTUAL INSIGHT</small><b>{view === "logs" ? "A recovered APT mirror timeout is the only recent error-priority event." : view === "security" ? "The SSH listener is expected for administration; validate its upstream network boundary." : `No unexplained regression detected in the current ${config.title.toLowerCase()} evidence.`}</b></div><Button onClick={goCommands}>Prove with evidence</Button></section>
  </div>;
}

function MetricsWorkspace({ samples, historySamples, historyRange, setHistoryRange, historyLoading, openDetail, openJira, openAI }: { samples: MetricSample[]; historySamples: MetricSample[]; historyRange: HistoryRange; setHistoryRange: (range: HistoryRange) => void; historyLoading: boolean; openDetail: (metric: DetailMetric) => void; openJira: (metric: string) => void; openAI: () => void }) {
  const current = samples.at(-1)!;
  const diskTone = current.disk >= 90 ? "critical" : current.disk >= 80 ? "warning" : "normal";
  return <div className="f-view"><header className="f-page-title"><div><small>METRICS EXPLORER</small><h1>Correlated telemetry</h1><p>Explore compute, memory, storage, network, events, and pressure signals on one synchronized timeline.</p></div><div><Button>Export CSV</Button><Button appearance="primary">Create alert rule</Button></div></header>
    <div className="f-variable-bar"><label>HOST<select><option>opspilot-node-01</option></select></label><label>SIGNAL<select><option>All resources</option><option>Compute</option><option>Storage</option></select></label><label>RANGE<select value={historyRange} onChange={event => setHistoryRange(event.target.value as HistoryRange)}>{historyRanges.map(range => <option value={range} key={range}>Last {range}</option>)}</select></label><span><i />{historyLoading ? "Loading history" : "Auto-refresh 5s"}</span></div>
    <section className="f-metrics-grid compact"><FluentMetricCard label="CPU" value={`${current.cpu}%`} detail="Live collector sample" icon={<DesktopPulse24Regular />} color="#0f6cbd" values={samples.map(item => item.cpu)} onOpen={() => openDetail("CPU")} onJira={() => openJira("CPU utilization")} onAI={openAI} /><FluentMetricCard label="Memory" value={`${current.memory}%`} detail="Live collector sample" icon={<Gauge24Regular />} color="#8764b8" values={samples.map(item => item.memory)} onOpen={() => openDetail("Memory")} onJira={() => openJira("Memory utilization")} onAI={openAI} /><FluentMetricCard label="Root filesystem" value={`${current.disk}%`} detail={`${Math.max(0,100-current.disk)}% capacity remaining`} icon={<Storage24Regular />} color={current.disk >= 80 ? "#c4314b" : "#0f7b0f"} values={samples.map(item => item.disk)} tone={diskTone} onOpen={() => openDetail("Root filesystem")} onJira={() => openJira("Critical root filesystem usage")} onAI={openAI} /><FluentMetricCard label="System load" value={current.load.toFixed(2)} detail="Current 1-minute load" icon={<Gauge24Regular />} color="#0f7b0f" values={samples.map(item => item.load * 35)} onOpen={() => openDetail("System load")} onJira={() => openJira("System load review")} onAI={openAI} /></section>
    <FluentPanel eyebrow="CORRELATED SIGNALS" title="CPU × memory × load × events" className="f-full-chart" action={<RangeSelector value={historyRange} onChange={setHistoryRange} loading={historyLoading} />}><FluentChart samples={historySamples} range={historyRange} loading={historyLoading} /></FluentPanel>
  </div>;
}

function CommandWorkspace({ run }: { run: (command: CommandSpec) => void }) {
  const [query, setQuery] = useState(""); const [category, setCategory] = useState("All");
  const [executions, setExecutions] = useState<Record<string, { state: "running" | "complete" | "error"; result?: CommandResult; error?: string }>>({});
  const filtered = commands.filter(item => (category === "All" || item.category === category) && `${item.command} ${item.description}`.toLowerCase().includes(query.toLowerCase()));
  const runInline = async (item: CommandSpec) => { setExecutions(current => ({ ...current, [item.id]: { state: "running" } })); try { const result = await executeApprovedCommand(item); setExecutions(current => ({ ...current, [item.id]: { state: "complete", result } })); } catch (error) { setExecutions(current => ({ ...current, [item.id]: { state: "error", error: error instanceof Error ? error.message : String(error) } })); } };
  return <div className="f-view"><header className="f-page-title"><div><small>SAFE SERVER DIAGNOSTICS</small><h1>{commands.length} commands. Zero SSH required.</h1><p>Every action maps to reviewed, read-only executable arguments with an 8-second timeout, 64 KB output ceiling, and audit record.</p></div><FluentStatus>allowlist enforced</FluentStatus></header>
    <section className="f-safety-grid"><div><span>01</span><b>Fixed arguments</b><small>No user-controlled shell parsing</small></div><div><span>02</span><b>Least privilege</b><small>Non-root collector on loopback</small></div><div><span>03</span><b>Audited evidence</b><small>Actor, command, duration, exit code</small></div><div><span>04</span><b>AI explainable</b><small>Selected output becomes grounded context</small></div></section>
    <div className="f-command-search"><label><Search24Regular /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search uptime, top, lsblk, services, logs, users, sockets…" /></label><select value={category} onChange={event => setCategory(event.target.value)}><option>All</option>{Object.keys(commandGroups).map(group => <option key={group}>{group}</option>)}</select><span><b>{filtered.length}</b> results</span></div>
    <section className="f-command-list"><header><span>COMMAND</span><span>WHAT IT PROVES</span><span>CATEGORY</span><span>POLICY</span><span /></header>{filtered.map(item => <Fragment key={item.id}><article className={executions[item.id] ? "has-output" : ""}><span><i>&gt;_</i><code>{item.command}</code></span><p>{item.description}</p><em>{item.category}</em><FluentStatus tone={item.risk === "review" ? "warn" : "good"}>{item.risk === "review" ? "scoped" : "read only"}</FluentStatus><Button appearance="primary" disabled={executions[item.id]?.state === "running"} onClick={() => void runInline(item)}>{executions[item.id]?.state === "running" ? "Running…" : "Run"}</Button></article>{executions[item.id] && <section className="f-inline-terminal" aria-live="polite"><header><span><i /><i /><i /></span><code>$ {item.command}</code><b>{executions[item.id].state}</b><button onClick={() => setExecutions(current => { const next = { ...current }; delete next[item.id]; return next; })}>×</button></header><div>{executions[item.id].state === "running" ? <pre>Executing fixed arguments as the unprivileged OpsPilot collector…</pre> : executions[item.id].state === "error" ? <pre className="stderr">{executions[item.id].error}</pre> : <><small>STDOUT</small><pre>{executions[item.id].result?.stdout || executions[item.id].result?.output || "(no stdout)"}</pre>{executions[item.id].result?.stderr && <><small>STDERR</small><pre className="stderr">{executions[item.id].result?.stderr}</pre></>}<footer><span>exit {executions[item.id].result?.exit_code ?? "—"}</span><span>{executions[item.id].result?.duration_ms ?? 0} ms</span><span>{executions[item.id].result?.generated_at || "now"}</span><button onClick={() => run(item)}>Open evidence tools</button></footer></>}</div></section>}</Fragment>)}</section>
  </div>;
}

function AIWorkspace({ run, samples }: { run: (command: CommandSpec) => void; samples: MetricSample[] }) {
  const [question, setQuestion] = useState(""); const [asked, setAsked] = useState(false);
  const current = samples.at(-1)!;
  const evidence = commands.filter(item => ["uptime","df -hT","du -xhd1 /var","journalctl -p err -n 50 --no-pager","systemctl --failed --no-pager"].includes(item.command));
  return <div className="f-view"><header className="f-page-title"><div><small>AMBIENT AI OPERATIONS</small><h1>OpsPilot understands the whole host.</h1><p>AI connects metrics, logs, events, users, services, and approved command evidence without becoming an uncontrolled remote shell.</p></div><FluentStatus>evidence grounded</FluentStatus></header>
    <section className="f-ai-workspace"><div className="f-ai-conversation"><header><PolarBear size="large" mood="watching" /><div><b>OpsPilot Investigator</b><small>Watching live CPU, memory, disk, load, network, service, and command evidence</small></div><FluentStatus>ready</FluentStatus></header><div className="f-ai-messages"><article><PolarBear size="small" mood="watching" /><p>{`Current live evidence: CPU ${current.cpu}%, memory ${current.memory}%, root filesystem ${current.disk}%, and 1-minute load ${current.load.toFixed(2)}. ${current.disk >= 80 ? "Storage is the strongest condition to investigate first." : "No current resource is above the storage warning boundary."}`}</p></article>{asked && <><article className="user"><span>SV</span><p>{question || "Build the safest investigation plan."}</p></article><article><PolarBear size="small" mood="watching" /><p>Start with the recommended allowlisted checks below. OpsPilot will use the actual exit code and output as evidence; no destructive action is required.</p></article></>}</div><div className="f-ai-prompt"><textarea value={question} onChange={event => setQuestion(event.target.value)} placeholder="Ask why the server is slow, what changed, or what to check next…" /><Button appearance="primary" onClick={() => setAsked(true)}>Investigate with AI</Button></div></div>
      <aside><FluentPanel eyebrow="EVIDENCE PLAN" title="AI-recommended checks"><div className="f-evidence-plan">{evidence.map((item, index) => <button key={item.id} onClick={() => run(item)}><span>{String(index + 1).padStart(2,"0")}</span><div><code>{item.command}</code><small>{item.description}</small></div><b>Run →</b></button>)}</div></FluentPanel><FluentPanel eyebrow="GUARDRAILS" title="Human control remains absolute"><ul className="f-guardrails"><li>✓ Explain live metrics and approved output</li><li>✓ Recommend evidence-first next steps</li><li>✓ Prepare Jira-ready incident context</li><li>× No sudo, restarts, kills, writes, or deletes</li><li>× No arbitrary shell input</li></ul></FluentPanel></aside>
    </section>
  </div>;
}

function MetricDrawer({ metric, close, run, sample }: { metric: DetailMetric; close: () => void; run: (command: CommandSpec) => void; sample: MetricSample }) {
  if (!metric) return null;
  const isCpu = metric === "CPU"; const checks = commands.filter(item => isCpu ? ["top","lscpu","vmstat 1 2"].includes(item.command) : metric === "Root filesystem" ? ["df -hT","df -ih","du -xhd1 /var"].includes(item.command) : ["free -h","cat /proc/loadavg","systemctl --failed --no-pager"].includes(item.command)).slice(0,3);
  const value = metric === "Root filesystem" ? sample.disk : metric === "Memory" ? sample.memory : metric === "System load" ? Math.round(sample.load * 25) : sample.cpu;
  const critical = metric === "Root filesystem" && value >= 90;
  return <div className="f-drawer-layer" onMouseDown={close}><aside className="f-detail-drawer" onMouseDown={event => event.stopPropagation()}><header><div><small>CONTEXTUAL HARDWARE LENS</small><h2>{metric}</h2></div><Button appearance="subtle" onClick={close}>✕</Button></header>{isCpu ? <div className="f-cpu-machine"><div className="f-chip"><span>CPU</span><div className="f-fan"><i /><i /><i /><b /></div><div className="f-fan"><i /><i /><i /><b /></div><small>4 logical cores · live utilization {sample.cpu}%</small></div><div className="f-core-grid">{[.82,1.08,.94,1.16].map(factor => Math.min(100,Math.round(sample.cpu*factor))).map((core,index) => <span key={index}><i style={{ height: `${core}%` }} /><b>Core {index}</b><small>{core}%</small></span>)}</div></div> : <div className={`f-resource-visual ${critical ? "critical" : ""}`}><span><b>{value}</b><small>{metric === "System load" ? "LOAD INDEX" : "PERCENT USED"}</small></span></div>}<div className="f-drawer-facts"><div><small>STATUS</small><FluentStatus tone={critical ? "bad" : value >= 80 ? "warn" : "good"}>{critical ? "critical" : value >= 80 ? "attention" : "healthy"}</FluentStatus></div><div><small>LAST SAMPLE</small><b>Live collector</b></div><div><small>AI CONTEXT</small><b>Evidence ready</b></div></div><section><small>RECOMMENDED EVIDENCE</small>{checks.map(item => <button key={item.id} onClick={() => run(item)}><code>$ {item.command}</code><span>Run →</span></button>)}</section></aside></div>;
}

function JiraDialog({ open, metric, close }: { open: boolean; metric: string; close: () => void }) {
  const [priority, setPriority] = useState(metric.toLowerCase().includes("heartbeat") ? "Highest" : "High");
  const [draft, setDraft] = useState<IncidentDraft | null>(null);
  const [result, setResult] = useState<DispatchResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [actionToken, setActionToken] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  const prepare = async () => {
    setBusy(true); setError(""); setResult(null);
    try { setDraft(await prepareIncident(metric, priority)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  const dispatch = async () => {
    if (!confirmed || !actionToken) return;
    setBusy(true); setError("");
    const idempotencyKey = globalThis.crypto?.randomUUID?.() || `opspilot-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    try { setResult(await dispatchIncident(metric, priority, actionToken, idempotencyKey)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); setActionToken(""); }
  };

  const finished = result?.jira?.key;
  return <Dialog open={open} onOpenChange={(_, data) => { if (!data.open) close(); }}><DialogSurface className="f-jira-dialog"><DialogBody><DialogTitle>{finished ? "Incident workflow completed" : "Create Jira Ticket"}</DialogTitle><DialogContent>{finished ? <div className="f-jira-success"><span>✓</span><h3>{result?.jira?.key} created</h3><p>Jira received the live evidence. NOC-Alerts status: {result?.chat?.status || "unknown"}. The Meet bridge is attached.</p><a href={result?.jira?.url} target="_blank" rel="noreferrer">Open Jira issue →</a></div> : <div className="f-jira-form"><div className="f-jira-banner"><TicketDiagonal24Regular /><span><b>{busy ? "Preparing incident evidence…" : `${draft?.severity || "INCIDENT"} · ${draft?.mode === "live" ? "Live routing available" : "Safe draft mode"}`}</b><small>opspilot-node-01 · 192.0.2.10</small></span></div><label>Summary<input readOnly value={draft?.summary || `[OpsPilot] ${metric} on opspilot-node-01`} /></label><div><label>Project<input readOnly value={`${draft?.jira.project_key || "OPS"} · ${draft?.jira.issue_type || "INCIDENT"}`} /></label><label>Priority<select value={priority} onChange={event => setPriority(event.target.value)}><option>Highest</option><option>High</option><option>Medium</option></select></label></div><label>Description<textarea readOnly value={draft?.description || "Click Prepare incident draft to collect current telemetry and evidence."} /></label><div className="f-route-grid"><span><small>GOOGLE CHAT</small><b>{draft?.google_chat.space || "NOC-Alerts"}</b><em>Notification preview</em></span><span><small>MEET BRIDGE</small><b>your-bridge</b><a href={draft?.meet_url || "https://meet.google.com/your-bridge"} target="_blank" rel="noreferrer">Open bridge</a></span><span><small>ON-CALL</small><b>{draft?.on_call.name || "Pending roster"}</b><em>{draft?.on_call.status || "not checked"}</em></span></div><span className="f-attachment">✓ Telemetry snapshot · ✓ AI evidence summary · ✓ Host identity · ✓ Bridge link</span>{draft?.mode === "live" ? <div className="f-live-approval"><label>Action token<input type="password" value={actionToken} onChange={event => setActionToken(event.target.value)} autoComplete="off" placeholder="Enter the VM-generated action token" /></label><label className="f-confirm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} /> I reviewed this payload and approve one Jira and NOC-Alerts write.</label></div> : <p className="f-integration-note">Draft mode is active. No Jira ticket or Chat message has been sent. The Jira URL currently points to project <b>OPS</b>; the supplied label <b>opspilot</b> must be validated before live mode.</p>}{error && <p className="f-jira-error">{error}</p>}</div>}</DialogContent><DialogActions><Button onClick={close}>{finished ? "Close" : "Cancel"}</Button>{!finished && draft?.mode === "live" && <Button appearance="primary" icon={<TicketDiagonal24Regular />} disabled={busy || !confirmed || !actionToken} onClick={() => void dispatch()}>Create Jira & notify NOC-Alerts</Button>}{!finished && draft?.mode !== "live" && <Button appearance="primary" icon={<TicketDiagonal24Regular />} disabled={busy} onClick={() => void prepare()}>{busy ? "Preparing…" : draft ? "Refresh draft" : "Prepare incident draft"}</Button>}</DialogActions></DialogBody></DialogSurface></Dialog>;
}

function CommandDialog({ command, close, explain }: { command: CommandSpec; close: () => void; explain: () => void }) {
  const [output, setOutput] = useState("Executing approved diagnostic against the selected node…");
  const [ready, setReady] = useState(false);
  useEffect(() => { const controller = new AbortController(); void executeApprovedCommand(command, controller.signal).then(result => { setOutput(`${result.output || result.message || "No output"}\n\n[exit ${result.exit_code ?? "blocked"} · ${result.duration_ms ?? 0} ms · ${result.generated_at || "now"}]`); setReady(true); }).catch(error => { if (error.name !== "AbortError") { setOutput(`OpsPilot could not collect command evidence: ${error.message}`); setReady(true); } }); return () => controller.abort(); }, [command]);
  return <div className="f-modal-layer" onMouseDown={close}><section className="f-command-dialog" onMouseDown={event => event.stopPropagation()}><header><span>&gt;_</span><div><b>Live command evidence</b><small>opspilot-node-01 · reviewed allowlist</small></div><Button appearance="subtle" onClick={close}>✕</Button></header><div className="f-command-meta"><span><small>COMMAND</small><code>{command.command}</code></span><span><small>POLICY</small><FluentStatus>read only</FluentStatus></span><span><small>TIMEOUT</small><b>8 seconds</b></span><span><small>AUDIT</small><b>enabled</b></span></div><pre><code><i>$ {command.command}</i>{"\n"}{output}</code></pre><footer><span>{ready ? "✓ Accurate host output captured" : "● Running as unprivileged OpsPilot collector"}</span><div><Button onClick={() => navigator.clipboard?.writeText(output)}>Copy output</Button><Button appearance="primary" disabled={!ready} icon={<Bot24Regular />} onClick={explain}>Explain with AI</Button></div></footer></section></div>;
}

function AIDock({ open, close, openJira, goAI, sample }: { open: boolean; close: () => void; openJira: () => void; goAI: () => void; sample: MetricSample }) {
  const storagePressure = sample.disk >= 80;
  return <aside className={`f-ai-dock ${open ? "open" : ""}`} aria-hidden={!open}><header><PolarBear size="large" /><div><b>OpsPilot AI</b><small>Ambient infrastructure intelligence</small></div><Button appearance="subtle" onClick={close}>✕</Button></header><section className="f-ai-primary"><small>AI SUGGESTS · LIVE EVIDENCE</small><h3>{storagePressure ? "Confirm root filesystem capacity and growth." : "No threshold breach requires immediate action."}</h3><p>{storagePressure ? <>Run <code>df -hT</code>, <code>df -ih</code>, and <code>du -xhd1 /var</code> before remediation.</> : "Continue observing correlated CPU, memory, disk, and load evidence."}</p><span>Evidence confidence <b>94%</b></span></section><section className="f-ai-actions"><button><i className={sample.disk >= 90 ? "bad" : sample.disk >= 80 ? "warn" : "good"} /><span><b>Storage pressure</b><small>{sample.disk}% used · live collector</small></span></button><button><i className={sample.memory >= 80 ? "warn" : "good"} /><span><b>Memory utilization</b><small>{sample.memory}% · live collector</small></span></button><button><i className="good" /><span><b>Compute signal</b><small>{sample.cpu}% CPU · load {sample.load.toFixed(2)}</small></span></button></section><div className="f-ai-dock-actions"><Button appearance="primary" onClick={goAI}>Open investigation</Button><Button icon={<TicketDiagonal24Regular />} onClick={openJira}>Create Jira</Button></div><footer><span><i />Watching live context</span><small>AI never runs a command without your click.</small></footer></aside>;
}

function OutageMode({ recover, openJira }: { recover: () => void; openJira: () => void }) {
  return <section className="f-outage" role="alert" aria-live="assertive"><div className="f-lightning"><i /><i /><i /><i /></div><div className="f-embers">{Array.from({ length: 20 }, (_, index) => <i key={index} />)}</div><div className="f-outage-card"><span className="f-outage-mark"><Alert24Regular /></span><small>SEV-1 · 3 FAILED HEARTBEATS</small><h1>OpsPilot Node<br /><em>is unreachable</em></h1><p>The last loaded evidence remains available while OpsPilot AI prepares reboot, network, and host-down investigation paths.</p><div><span><small>LAST SIGNAL</small><b>12 seconds ago</b></span><span><small>NODE</small><b>192.0.2.10</b></span><span><small>STATUS</small><b>Heartbeat lost</b></span></div><footer><Button appearance="primary" onClick={openJira}>Create SEV-1 Jira</Button><Button onClick={recover}>Restore demo signal</Button></footer></div></section>;
}

export default function FluentOpsPilot() {
  const [authenticated, setAuthenticated] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => typeof window !== "undefined" && window.localStorage.getItem("opspilot-fluent-theme") === "dark" ? "dark" : "light");
  const [view, setView] = useState<FluentView>("pulse");
  const [samples, setSamples] = useState(initialSamples);
  const [historyRange, setHistoryRange] = useState<HistoryRange>("30m");
  const [historySamples, setHistorySamples] = useState(() => buildDemoHistory("30m"));
  const [historyLoading, setHistoryLoading] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [aiOpen, setAiOpen] = useState(true);
  const [detail, setDetail] = useState<DetailMetric>(null);
  const [jiraMetric, setJiraMetric] = useState("");
  const [command, setCommand] = useState<CommandSpec | null>(null);
  const [nodeState, setNodeState] = useState<NodeState>("online");
  const [globalSearch, setGlobalSearch] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => { document.documentElement.dataset.fluentTheme = theme; }, [theme]);
  useEffect(() => { const controller = new AbortController(); let cancelled = false; const load = async () => { setHistoryLoading(true); try { if (window.location.hostname.endsWith("chatgpt.site")) { setHistorySamples(buildDemoHistory(historyRange)); return; } const response = await fetch(`api/v1/dashboard?range=${historyRange}`, { cache: "no-store", signal: controller.signal }); if (!response.ok) throw new Error(`history returned HTTP ${response.status}`); const data = await response.json(); const rows = Array.isArray(data.history?.samples) ? data.history.samples : []; const mapped = rows.map((item: Record<string, unknown>) => ({ cpu: Number(item.cpu) || 0, memory: Number(item.memory) || 0, disk: Number(item.disk) || 0, load: Number(item.load) || 0, rx: (Number(item.rx) || 0) / 1024, tx: (Number(item.tx) || 0) / 1024 })); if (!cancelled && mapped.length) setHistorySamples(mapped); } catch (error) { if (!cancelled && (error as Error).name !== "AbortError") setHistorySamples(current => current.length ? current : buildDemoHistory(historyRange)); } finally { if (!cancelled) setHistoryLoading(false); } }; void load(); const timer = window.setInterval(load, 5000); return () => { cancelled = true; controller.abort(); window.clearInterval(timer); }; }, [historyRange]);
  useEffect(() => {
    let consecutiveFailures = 0;
    let cancelled = false;
    const collect = async () => {
      try {
        const response = await fetch("api/v1/dashboard", { cache: "no-store" });
        if (!response.ok) throw new Error(`telemetry returned HTTP ${response.status}`);
        const data = await response.json();
        const next: MetricSample = {
          cpu: Math.round(Number(data.cpu?.percent) || 0),
          memory: Math.round(Number(data.memory?.percent) || 0),
          disk: Math.round(Number(data.disk?.percent) || 0),
          load: Number(data.cpu?.load_1m) || 0,
          rx: +((Number(data.network?.rx_bytes_per_second) || 0) / 1024).toFixed(1),
          tx: +((Number(data.network?.tx_bytes_per_second) || 0) / 1024).toFixed(1),
        };
        if (cancelled) return;
        consecutiveFailures = 0;
        setSamples(current => [...current.slice(1), next]);
        setNodeState(next.disk >= 80 || next.memory >= 85 || next.cpu >= 90 ? "warning" : "online");
      } catch {
        if (cancelled) return;
        consecutiveFailures += 1;
        if (consecutiveFailures >= 3) setNodeState("offline");
        else setNodeState("warning");
      }
    };
    void collect();
    const timer = window.setInterval(collect, 5000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, []);
  useEffect(() => { const run = (event: Event) => setCommand((event as CustomEvent<CommandSpec>).detail); window.addEventListener("opspilot-command", run); return () => window.removeEventListener("opspilot-command", run); }, []);
  useEffect(() => { const key = (event: KeyboardEvent) => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setSearchOpen(true); } if (event.key === "Escape") { setSearchOpen(false); setDetail(null); setCommand(null); } }; window.addEventListener("keydown", key); return () => window.removeEventListener("keydown", key); }, []);
  const toggleTheme = () => setTheme(current => { const next = current === "light" ? "dark" : "light"; document.documentElement.dataset.fluentTheme = next; window.localStorage.setItem("opspilot-fluent-theme", next); return next; });
  const navigate = (next: FluentView) => { setView(next); setMobileNav(false); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const searchResults = useMemo(() => { const q = globalSearch.toLowerCase(); return [...fluentNav.flatMap(group => group.items).filter(item => item.label.toLowerCase().includes(q)).map(item => ({ type: "view" as const, label: item.label, id: item.id, detail: "Open workspace" })), ...commands.filter(item => `${item.command} ${item.description}`.toLowerCase().includes(q)).slice(0,8).map(item => ({ type: "command" as const, label: item.command, id: item.id, detail: item.description }))].slice(0,12); }, [globalSearch]);
  const content = view === "pulse" ? <OverviewView samples={samples} historySamples={historySamples} historyRange={historyRange} setHistoryRange={setHistoryRange} historyLoading={historyLoading} setView={navigate} openDetail={setDetail} openJira={setJiraMetric} openAI={() => setAiOpen(true)} nodeState={nodeState} setNodeState={setNodeState} /> : view === "metrics" ? <MetricsWorkspace samples={samples} historySamples={historySamples} historyRange={historyRange} setHistoryRange={setHistoryRange} historyLoading={historyLoading} openDetail={setDetail} openJira={setJiraMetric} openAI={() => setAiOpen(true)} /> : view === "commands" ? <CommandWorkspace run={setCommand} /> : view === "ai" ? <AIWorkspace run={setCommand} samples={samples} /> : <DataWorkspace view={view as keyof typeof tableConfig} openJira={setJiraMetric} goCommands={() => navigate("commands")} />;

  if (!authenticated) return <FluentProvider theme={webDarkTheme}><LoginView onComplete={() => setAuthenticated(true)} /></FluentProvider>;
  return <FluentProvider theme={theme === "light" ? webLightTheme : webDarkTheme} className="f-provider"><main className={`f-shell ${theme} state-${nodeState}`}>
    <aside className={`f-sidebar ${mobileNav ? "open" : ""}`}><header><button className="f-brand" onClick={() => navigate("pulse")}><span className="f-mark"><i /><b>O</b></span><div><strong>OpsPilot</strong><small>FLUENT NOC INTELLIGENCE</small></div></button><Button className="f-mobile-close" appearance="subtle" onClick={() => setMobileNav(false)}>✕</Button></header><button className="f-host-card" onClick={() => navigate("pulse")}><span><Server24Regular /></span><div><small>CONNECTED NODE</small><b>opspilot-node-01</b><em>192.0.2.10 · Ubuntu 22.04</em></div><FluentStatus>live</FluentStatus></button><nav>{fluentNav.map(group => <section key={group.group}><small>{group.group}</small>{group.items.map(item => <button key={item.id} className={view === item.id ? "active" : ""} onClick={() => navigate(item.id)}><span><FluentIcon view={item.id} /></span><b>{item.label}</b>{item.badge && <em>{item.badge}</em>}</button>)}</section>)}</nav><div className="f-sidebar-ai"><PolarBear size="small" mood="watching" /><div><b>AI context live</b><small>14 signals connected</small></div><i /></div><footer><span>v0.9 ROUTING</span><b>DRAFT SAFE</b></footer></aside>
    {mobileNav && <button className="f-nav-scrim" onClick={() => setMobileNav(false)} />}
    <section className="f-workspace"><header className="f-topbar"><Button appearance="subtle" icon={<Navigation24Regular />} className="f-mobile-menu" onClick={() => setMobileNav(true)} /><div className="f-breadcrumb"><span>OpsPilot Node</span><i>/</i><b>{fluentNav.flatMap(group => group.items).find(item => item.id === view)?.label}</b></div><div className="f-top-actions"><span className="f-refresh"><i />Live · 5s</span><button className="f-global-search" onClick={() => setSearchOpen(true)}><Search24Regular /><span>Search metrics, logs, or commands</span><kbd>Ctrl K</kbd></button><Button appearance="subtle" icon={theme === "light" ? <WeatherMoon24Regular /> : <WeatherSunny24Regular />} onClick={toggleTheme} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} theme`} /><button className="f-ai-top" onClick={() => setAiOpen(value => !value)}><PolarBear size="small" mood="watching" /><span><small>ASK AI</small><b>{aiOpen ? "Watching context" : "1 suggestion"}</b></span></button><button className="f-avatar"><span>SV</span><div><b>On-call Engineer</b><small>Server engineer</small></div></button></div></header><div className="f-content">{content}<footer className="f-page-footer"><span><i />Hosted preview uses simulation · VM edition connects to live telemetry and draft incident routing</span><span>OpsPilot v0.9 · Fluent 2 · AI assisted</span></footer></div></section>
    {!aiOpen && <button className="f-floating-ai" onClick={() => setAiOpen(true)}><PolarBear size="large" /><span><small>ASK AI</small><b>Review 1 new suggestion</b></span></button>}
    <AIDock open={aiOpen} close={() => setAiOpen(false)} openJira={() => setJiraMetric("Root filesystem capacity review")} goAI={() => { setAiOpen(false); navigate("ai"); }} sample={samples.at(-1)!} />
    <MetricDrawer metric={detail} close={() => setDetail(null)} run={setCommand} sample={samples.at(-1)!} />
    <JiraDialog key={jiraMetric || "closed"} open={Boolean(jiraMetric)} metric={jiraMetric} close={() => setJiraMetric("")} />
    {command && <CommandDialog key={command.id} command={command} close={() => setCommand(null)} explain={() => { setCommand(null); navigate("ai"); }} />}
    {nodeState === "offline" && <OutageMode recover={() => setNodeState("online")} openJira={() => setJiraMetric("SEV-1 host heartbeat failure")} />}
    {searchOpen && <div className="f-modal-layer" onMouseDown={() => setSearchOpen(false)}><section className="f-search-dialog" onMouseDown={event => event.stopPropagation()}><header><Search24Regular /><input autoFocus value={globalSearch} onChange={event => setGlobalSearch(event.target.value)} placeholder="Search metrics, users, incidents, or a safe Linux command…" /><kbd>ESC</kbd></header><small>RESULTS</small>{searchResults.map(item => <button key={`${item.type}-${item.id}`} onClick={() => { if (item.type === "view") navigate(item.id as FluentView); else setCommand(commands.find(commandItem => commandItem.id === item.id)!); setSearchOpen(false); }}><span>{item.type === "view" ? <Apps24Regular /> : <Wrench24Regular />}</span><div><b>{item.label}</b><small>{item.detail}</small></div><em>{item.type === "view" ? "OPEN" : "RUN"} →</em></button>)}</section></div>}
  </main></FluentProvider>;
}
