import { useMemo, type CSSProperties } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export type ResourceHistoryRange = "15m" | "30m" | "1h" | "3h" | "6h" | "12h" | "24h" | "7d" | "15d";

export const RESOURCE_HISTORY_WINDOW_MS: Record<ResourceHistoryRange, number> = {
  "15m": 15 * 60_000,
  "30m": 30 * 60_000,
  "1h": 60 * 60_000,
  "3h": 3 * 60 * 60_000,
  "6h": 6 * 60 * 60_000,
  "12h": 12 * 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  "7d": 7 * 24 * 60 * 60_000,
  "15d": 15 * 24 * 60 * 60_000,
};

export type ResourceActivitySample = {
  timestamp?: number;
  cpu: number;
  memory: number;
  load: number;
};

type TelemetryMetric = "cpu" | "memory" | "load";

export type ResourceSpikeSelection = {
  metric: TelemetryMetric;
  title: string;
  timestamp: number;
  value: number;
};

const telemetryConfig: Record<TelemetryMetric, { title: string; shortLabel: string; color: string; unit: string; precision: number }> = {
  cpu: { title: "CPU Utilization", shortLabel: "CPU", color: "#0f6cbd", unit: "%", precision: 1 },
  memory: { title: "Memory Usage", shortLabel: "Memory", color: "#8764b8", unit: "%", precision: 1 },
  load: { title: "System Load", shortLabel: "Load", color: "#d83b01", unit: "", precision: 2 },
};

function formatAxisTimestamp(value: number, range: ResourceHistoryRange) {
  const longRange = range === "7d" || range === "15d";
  const dayRange = range === "24h";
  return new Intl.DateTimeFormat("en-US", longRange
    ? { month: "short", day: "numeric" }
    : dayRange
      ? { month: "short", day: "numeric", hour: "2-digit", hour12: false }
      : { hour: "2-digit", minute: "2-digit", hour12: false }
  ).format(new Date(value));
}

function formatTooltipTimestamp(value: number) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  }).format(new Date(value));
}

function TelemetryTooltip({ active, payload, metric }: { active?: boolean; payload?: Array<{ value?: number; payload?: ResourceActivitySample }>; metric: TelemetryMetric }) {
  if (!active || !payload?.length) return null;
  const config = telemetryConfig[metric];
  const value = Number(payload[0].value ?? 0);
  const timestamp = Number(payload[0].payload?.timestamp ?? Date.now());
  return <div className="f-telemetry-tooltip" style={{ "--telemetry-color": config.color } as CSSProperties}>
    <span><i />{config.title}</span>
    <strong>{value.toFixed(config.precision)}{config.unit}</strong>
    <time>{formatTooltipTimestamp(timestamp)}</time>
  </div>;
}

function TelemetryChartCard({ samples, range, metric, onSpikeSelect }: { samples: ResourceActivitySample[]; range: ResourceHistoryRange; metric: TelemetryMetric; onSpikeSelect?: (selection: ResourceSpikeSelection) => void }) {
  const config = telemetryConfig[metric];
  const values = samples.map(sample => sample[metric]);
  const latest = values.at(-1) ?? 0;
  const peak = Math.max(...values, 0);
  const average = values.length ? values.reduce((total, value) => total + value, 0) / values.length : 0;
  const maximum = metric === "load" ? Math.max(1, Math.ceil(peak * 1.25 * 10) / 10) : 100;
  const ticks = metric === "load" ? [0, maximum / 4, maximum / 2, maximum * .75, maximum] : [0, 25, 50, 75, 100];
  const gradientId = `telemetry-gradient-${metric}`;

  return <article className="f-telemetry-card" style={{ "--telemetry-color": config.color } as CSSProperties}>
    <header>
      <div><span><i />{config.title}</span><strong>{latest.toFixed(config.precision)}{config.unit}</strong></div>
      <dl><div><dt>AVG</dt><dd>{average.toFixed(config.precision)}{config.unit}</dd></div><div><dt>MAX</dt><dd>{peak.toFixed(config.precision)}{config.unit}</dd></div></dl>
    </header>
    <div className="f-telemetry-canvas">
      <ResponsiveContainer width="100%" height="100%" debounce={80}>
        <AreaChart data={samples} syncId="resource-activity" syncMethod="value" margin={{ top: 12, right: 12, bottom: 4, left: 0 }} accessibilityLayer onClick={(state: unknown) => {
          const chartState = state as { activePayload?: Array<{ payload?: ResourceActivitySample }> } | null;
          const sample = chartState?.activePayload?.[0]?.payload;
          if (!sample || !onSpikeSelect) return;
          onSpikeSelect({ metric, title: config.title, timestamp: Number(sample.timestamp ?? Date.now()), value: Number(sample[metric]) });
        }}>
          <defs><linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={config.color} stopOpacity={.38} /><stop offset="62%" stopColor={config.color} stopOpacity={.12} /><stop offset="100%" stopColor={config.color} stopOpacity={.015} /></linearGradient></defs>
          <CartesianGrid stroke="var(--f-line)" strokeDasharray="3 5" vertical={false} />
          <XAxis type="number" dataKey="timestamp" domain={["dataMin", "dataMax"]} scale="time" tickFormatter={value => formatAxisTimestamp(Number(value), range)} tick={{ fill: "var(--f-quiet)", fontSize: 10 }} axisLine={{ stroke: "var(--f-line-strong)" }} tickLine={false} minTickGap={range === "7d" || range === "15d" ? 48 : 36} />
          <YAxis domain={[0, maximum]} ticks={ticks} width={44} allowDecimals={metric === "load"} tickFormatter={value => metric === "load" ? Number(value).toFixed(maximum < 2 ? 2 : 1) : `${value}%`} tick={{ fill: "var(--f-quiet)", fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip content={<TelemetryTooltip metric={metric} />} cursor={{ stroke: config.color, strokeWidth: 1.5, strokeDasharray: "4 3" }} isAnimationActive={false} allowEscapeViewBox={{ x: false, y: true }} />
          <Area type="monotoneX" dataKey={metric} name={config.shortLabel} stroke={config.color} strokeWidth={2.4} fill={`url(#${gradientId})`} dot={false} activeDot={{ r: 4, fill: "var(--f-surface)", stroke: config.color, strokeWidth: 2.5 }} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  </article>;
}

export default function ResourceActivityCharts({ samples, range, loading = false, onSpikeSelect }: { samples: ResourceActivitySample[]; range: ResourceHistoryRange; loading?: boolean; onSpikeSelect?: (selection: ResourceSpikeSelection) => void }) {
  const timestampedSamples = useMemo(() => {
    const fallbackStart = Date.now() - RESOURCE_HISTORY_WINDOW_MS[range];
    return samples.map((sample, index) => ({
      ...sample,
      timestamp: sample.timestamp ?? fallbackStart + (index / Math.max(1, samples.length - 1)) * RESOURCE_HISTORY_WINDOW_MS[range],
    }));
  }, [samples, range]);

  return <div className="f-telemetry-suite">
    <header className="f-telemetry-toolbar"><span><i />Synchronized hover tracker</span><em>{loading ? "QUERYING HISTORY" : `${range} · ${timestampedSamples.length} samples`}</em></header>
    <section className="f-telemetry-grid">
      <TelemetryChartCard samples={timestampedSamples} range={range} metric="cpu" onSpikeSelect={onSpikeSelect} />
      <TelemetryChartCard samples={timestampedSamples} range={range} metric="memory" onSpikeSelect={onSpikeSelect} />
      <TelemetryChartCard samples={timestampedSamples} range={range} metric="load" onSpikeSelect={onSpikeSelect} />
    </section>
    {loading && <span className="history-loading">Loading historical samples…</span>}
  </div>;
}
