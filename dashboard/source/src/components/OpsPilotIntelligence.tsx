import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Button } from "@fluentui/react-components";
import {
  Bot24Regular,
  CheckmarkCircle24Regular,
  ChevronDown24Regular,
  Dismiss24Regular,
  Play24Regular,
  ShieldLock24Regular,
  Warning24Regular,
} from "@fluentui/react-icons";

export type SeverityLevel = "High" | "Medium" | "Low";

export type EvidenceItem = {
  source: string;
  excerpt: string;
};

export type ActionableStep = {
  order: number;
  command: string;
  purpose: string;
  risk: "read_only" | "state_change";
  requires_approval: boolean;
};

export type RemediationAction = {
  action_id: string;
  title: string;
  command: string;
  reason: string;
  risk: "none" | "low" | "medium" | "high";
  executable: boolean;
  execution_enabled: boolean;
  requires_privileged_broker: boolean;
};

export type RCAAnalysis = {
  status: "confirmed" | "likely" | "insufficient_evidence";
  probable_root_cause: string;
  root_cause_diagnosis: string;
  contributing_process: string;
  severity_level: SeverityLevel;
  confidence_percent: number;
  evidence: EvidenceItem[];
  resolution_theory: string;
  actionable_steps: ActionableStep[];
  recommended_action: RemediationAction;
  commands_executed: string[];
  raw_output: string;
  analysis_mode: "llm" | "deterministic_fallback";
  provider: string;
  model: string;
  generated_at: string;
};

export type PredictiveWarning = {
  metric: string;
  current_percent: number;
  growth_percent_per_hour: number;
  hours_to_exhaustion: number;
  confidence_percent: number;
  message: string;
};

export type AISignal = {
  status: "healthy" | "predictive_warning" | "investigating" | "warning" | "critical";
  headline: string;
  summary: string;
  triggered_by: Array<{ metric: string; value: number | string; unit: string; severity: string; service?: string }>;
  diagnosis: RCAAnalysis | null;
  predictive_warnings: PredictiveWarning[];
  generated_at: string;
  provider?: { configured?: boolean; model?: string; provider?: string; remediation_mode?: string };
};

type MetricSnapshot = {
  cpu: number;
  memory: number;
  disk: number;
  load: number;
  timestamp?: number;
};

type PreparedRemediation = {
  status: string;
  approval_id: string;
  action_id: string;
  title: string;
  exact_command: string;
  risk: string;
  expires_at: string;
  execution_enabled: boolean;
  requires_privileged_broker: boolean;
};

type ConversationItem = {
  id: string;
  role: "user" | "assistant";
  text?: string;
  analysis?: RCAAnalysis;
};

const demoAnalysis = (question: string): RCAAnalysis => ({
  status: "insufficient_evidence",
  probable_root_cause: "The hosted preview has no server command channel. Connect the VM backend to collect evidence before assigning a cause.",
  root_cause_diagnosis: `No live VM evidence is available to answer “${question}”.`,
  contributing_process: "Not identified in supplied evidence",
  severity_level: "Low",
  confidence_percent: 100,
  evidence: [],
  resolution_theory: "A metric value describes impact, while process and journal evidence are needed to prove the mechanism that produced it.",
  actionable_steps: [{ order: 1, command: "top -b -n 1", purpose: "Collect a live process snapshot from the VM edition.", risk: "read_only", requires_approval: false }],
  recommended_action: { action_id: "none", title: "No safe automatic fix", command: "", reason: "No live evidence is available.", risk: "none", executable: false, execution_enabled: false, requires_privileged_broker: false },
  commands_executed: [],
  raw_output: "Hosted preview: live command execution is unavailable.",
  analysis_mode: "deterministic_fallback",
  provider: "deterministic_fallback",
  model: "none",
  generated_at: new Date().toISOString(),
});

export function healthyAISignal(): AISignal {
  return {
    status: "healthy",
    headline: "No sustained resource pressure is visible.",
    summary: "CPU, memory, load, disk, and service state remain inside the current operating policy.",
    triggered_by: [],
    diagnosis: null,
    predictive_warnings: [],
    generated_at: new Date().toISOString(),
  };
}

async function responseJson<T>(response: Response): Promise<T> {
  const payload = await response.json().catch(() => ({ status: "error", message: `HTTP ${response.status}` }));
  if (!response.ok) throw new Error(String(payload.message || `OpsPilot returned HTTP ${response.status}`));
  return payload as T;
}

async function askOpsPilot(question: string, spikeTimestamp?: string): Promise<RCAAnalysis> {
  if (window.location.hostname.endsWith("chatgpt.site")) return demoAnalysis(question);
  const response = await fetch("api/v1/dashboard", {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "ai_query", question, ...(spikeTimestamp ? { spike_timestamp: spikeTimestamp } : {}) }),
  });
  return responseJson<RCAAnalysis>(response);
}

async function prepareRemediation(actionId: string): Promise<PreparedRemediation> {
  const response = await fetch("api/v1/dashboard", {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "prepare_remediation", action_id: actionId }),
  });
  return responseJson<PreparedRemediation>(response);
}

async function executeRemediation(prepared: PreparedRemediation) {
  const response = await fetch("api/v1/dashboard", {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/json", "X-OpsPilot-Action": "confirmed-remediation" },
    body: JSON.stringify({
      action: "execute_remediation",
      action_id: prepared.action_id,
      approval_id: prepared.approval_id,
      exact_command: prepared.exact_command,
      confirm: true,
    }),
  });
  return responseJson<{ status: string; command?: string; exit_code?: number; stdout?: string; stderr?: string; message?: string }>(response);
}

function SeverityBadge({ analysis }: { analysis: RCAAnalysis }) {
  const tone = analysis.severity_level === "High" ? "bad" : analysis.severity_level === "Medium" ? "warn" : "good";
  return <span className={`ai-severity ${tone}`}><i />{analysis.severity_level} · {analysis.status.replace("_", " ")} · {analysis.confidence_percent}% confidence</span>;
}

export function RCAResponseCard({ analysis, onRemediate }: { analysis: RCAAnalysis; onRemediate: (action: RemediationAction) => void }) {
  const action = analysis.recommended_action;
  return <section className="ai-rca-card">
    <header><span><Bot24Regular /></span><div><small>STRUCTURED RCA · {analysis.analysis_mode === "llm" ? analysis.model : "local evidence engine"}</small><SeverityBadge analysis={analysis} /></div></header>
    <section className="ai-rca-section diagnosis"><small>ROOT CAUSE DIAGNOSIS</small><h3>{analysis.root_cause_diagnosis}</h3><p>{analysis.probable_root_cause}</p>{analysis.contributing_process && <span>Contributing process / event: <b>{analysis.contributing_process}</b></span>}</section>
    <section className="ai-rca-section"><small>THE EVIDENCE</small>{analysis.evidence.length ? <div className="ai-evidence-blocks">{analysis.evidence.map((item, index) => <article key={`${item.source}-${index}`}><header><code>$ {item.source}</code><button onClick={() => navigator.clipboard?.writeText(item.excerpt)}>Copy</button></header><pre>{item.excerpt}</pre></article>)}</div> : <p className="ai-insufficient"><Warning24Regular /> No supplied log or process excerpt proves the initiating cause. More data is needed.</p>}</section>
    <section className="ai-rca-section"><small>RESOLUTION THEORY</small><p>{analysis.resolution_theory}</p></section>
    <section className="ai-rca-section"><small>ACTIONABLE STEPS</small><ol className="ai-steps">{analysis.actionable_steps.map(step => <li key={step.order}><span>{String(step.order).padStart(2, "0")}</span><div>{step.command && <code>{step.command}</code>}<p>{step.purpose}</p></div><em className={step.risk === "state_change" ? "state" : "read"}>{step.requires_approval ? "approval required" : "read only"}</em></li>)}</ol></section>
    <section className={`ai-remediation-card risk-${action.risk}`}><div><small>HUMAN-IN-THE-LOOP REMEDIATION</small><h4>{action.title}</h4><p>{action.reason}</p>{action.command && <code>{action.command}</code>}{action.requires_privileged_broker && <span><ShieldLock24Regular /> Requires the separately reviewed privileged remediation broker.</span>}</div>{action.action_id === "none" ? <Button disabled icon={<ShieldLock24Regular />}>No justified fix</Button> : <Button appearance="primary" icon={<Play24Regular />} onClick={() => onRemediate(action)}>Execute Recommended Fix</Button>}</section>
    <details className="ai-raw-output"><summary><ChevronDown24Regular /> View Raw Output <span>{analysis.commands_executed.length} diagnostics</span></summary><pre>{analysis.raw_output || "No command output was returned."}</pre></details>
  </section>;
}

export function AISignalContent({ signal, companion, onAsk, onRemediate }: { signal: AISignal; companion: ReactNode; onAsk: (question?: string) => void; onRemediate: (action: RemediationAction) => void }) {
  const tone = signal.status === "critical" ? "bad" : signal.status === "warning" || signal.status === "predictive_warning" ? "warn" : "good";
  return <div className="ai-signal-intelligent">
    {signal.predictive_warnings.map(warning => <div className="ai-predictive-banner" key={warning.metric}><Warning24Regular /><div><b>{warning.message}</b><small>{warning.growth_percent_per_hour}%/hour · regression confidence {warning.confidence_percent}%</small></div></div>)}
    <div className="ai-signal-summary">{companion}<div><span className={`ai-live-status ${tone}`}><i />{signal.status.replace("_", " ")}</span><h3>{signal.headline}</h3><p>{signal.summary}</p><div className="ai-signal-buttons"><button onClick={() => onAsk(signal.triggered_by.length ? `Explain the ${signal.triggered_by[0].metric} anomaly and prove its root cause.` : undefined)}>Ask OpsPilot AI</button>{signal.diagnosis?.recommended_action.action_id !== "none" && <button onClick={() => onRemediate(signal.diagnosis!.recommended_action)}>Review recommended fix</button>}</div></div></div>
    {signal.diagnosis && <div className="ai-signal-proof"><span>ROOT CAUSE</span><b>{signal.diagnosis.probable_root_cause}</b><em>{signal.diagnosis.contributing_process}</em></div>}
  </div>;
}

function RemediationDialog({ action, close }: { action: RemediationAction | null; close: () => void }) {
  const [prepared, setPrepared] = useState<PreparedRemediation | null>(null);
  const [approved, setApproved] = useState(false);
  const [phase, setPhase] = useState<"preparing" | "ready" | "executing" | "complete" | "error">("preparing");
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (!action) return;
    let cancelled = false;
    setPhase("preparing");
    void prepareRemediation(action.action_id).then(value => { if (!cancelled) { setPrepared(value); setPhase("ready"); } }).catch(error => { if (!cancelled) { setMessage(error.message); setPhase("error"); } });
    return () => { cancelled = true; };
  }, [action]);
  if (!action) return null;
  const run = async () => {
    if (!prepared || !approved) return;
    setPhase("executing");
    try {
      const result = await executeRemediation(prepared);
      setMessage(`${result.status}: exit ${result.exit_code ?? "—"}${result.stderr ? ` · ${result.stderr}` : ""}`);
      setPhase("complete");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
      setPhase("error");
    }
  };
  return <div className="ai-confirm-layer" role="presentation" onMouseDown={close}><section className="ai-confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="ai-confirm-title" onMouseDown={event => event.stopPropagation()}><header><span><ShieldLock24Regular /></span><div><small>HUMAN APPROVAL REQUIRED</small><h2 id="ai-confirm-title">Confirm exact remediation</h2></div><Button appearance="subtle" icon={<Dismiss24Regular />} onClick={close} /></header><div className="ai-confirm-risk"><Warning24Regular /><p>This operation changes server state. Review the exact fixed command; OpsPilot will not accept edited commands or reuse this approval.</p></div><label>EXACT COMMAND TO RUN<code>{prepared?.exact_command || action.command}</code></label>{prepared?.requires_privileged_broker && <p className="ai-confirm-locked"><ShieldLock24Regular /> This privileged action is intentionally blocked in the web sidecar. Install and approve a separate broker before execution.</p>}{prepared && !prepared.execution_enabled && !prepared.requires_privileged_broker && <p className="ai-confirm-locked"><ShieldLock24Regular /> Remediation mode is DRAFT. The command is reviewable, but execution remains locked.</p>}<label className="ai-confirm-check"><input type="checkbox" checked={approved} onChange={event => setApproved(event.target.checked)} /><span>I reviewed the exact command and approve this single execution.</span></label>{message && <p className={`ai-confirm-result ${phase}`}>{phase === "complete" ? <CheckmarkCircle24Regular /> : <Warning24Regular />}{message}</p>}<footer><Button onClick={close}>{phase === "complete" ? "Close" : "Cancel"}</Button><Button appearance="primary" icon={<Play24Regular />} disabled={!approved || !prepared?.execution_enabled || phase === "executing" || phase === "complete"} onClick={() => void run()}>{phase === "preparing" ? "Preparing…" : phase === "executing" ? "Executing…" : "Confirm and Execute"}</Button></footer></section></div>;
}

export function AskOpsPilotModal({ open, close, signal, sample, companion, initialQuestion, clearInitialQuestion }: { open: boolean; close: () => void; signal: AISignal; sample: MetricSnapshot; companion: ReactNode; initialQuestion?: string; clearInitialQuestion: () => void }) {
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<ConversationItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [remediation, setRemediation] = useState<RemediationAction | null>(null);
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if (open && initialQuestion) { setQuestion(initialQuestion); clearInitialQuestion(); } }, [open, initialQuestion, clearInitialQuestion]);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, loading]);
  const contextLine = useMemo(() => `CPU ${sample.cpu}% · Memory ${sample.memory}% · Disk ${sample.disk}% · Load ${sample.load.toFixed(2)}`, [sample]);
  if (!open) return null;
  const ask = async (preset?: string) => {
    const prompt = (preset ?? question).trim();
    if (!prompt || loading) return;
    setQuestion("");
    setError("");
    setLoading(true);
    setMessages(current => [...current, { id: crypto.randomUUID(), role: "user", text: prompt }]);
    try {
      const analysis = await askOpsPilot(prompt, sample.timestamp ? new Date(sample.timestamp).toISOString() : undefined);
      setMessages(current => [...current, { id: crypto.randomUUID(), role: "assistant", analysis }]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  };
  return <div className="ai-chat-layer" role="presentation" onMouseDown={close}><section className="ai-chat-modal" role="dialog" aria-modal="true" aria-label="Ask OpsPilot AI" onMouseDown={event => event.stopPropagation()}><header>{companion}<div><small>ASK AI · EVIDENCE-GROUNDED RCA</small><h2>OpsPilot Investigator</h2><span><i />{signal.provider?.configured ? `${signal.provider.model} connected` : "Local evidence mode · add provider key for LLM reasoning"}</span></div><Button appearance="subtle" icon={<Dismiss24Regular />} onClick={close} /></header><div className="ai-context-ribbon"><span>LIVE HOST</span><b>{contextLine}</b><em>172 approved diagnostics</em></div><main className="ai-chat-scroll"><article className="ai-chat-welcome">{companion}<div><h3>I’ll prove what the evidence supports—and say when it does not.</h3><p>Ask about a spike, degraded service, memory consumer, disk trend, network state, or current host health. I select only fixed read-only diagnostics.</p></div></article>{signal.diagnosis && messages.length === 0 && <RCAResponseCard analysis={signal.diagnosis} onRemediate={setRemediation} />}{messages.map(item => item.role === "user" ? <article className="ai-user-message" key={item.id}><span>SV</span><p>{item.text}</p></article> : item.analysis ? <RCAResponseCard key={item.id} analysis={item.analysis} onRemediate={setRemediation} /> : null)}{loading && <article className="ai-thinking">{companion}<div><b>Correlating live evidence…</b><span><i /><i /><i /></span><small>Running fixed diagnostics, redacting output, and validating structured JSON.</small></div></article>}{error && <p className="ai-chat-error"><Warning24Regular /> {error}</p>}<div ref={endRef} /></main><div className="ai-suggested-queries">{["Which services are currently degraded?", "What is using my memory?", "Check disk space trends"].map(item => <button key={item} onClick={() => void ask(item)}>{item}</button>)}</div><footer><textarea value={question} onChange={event => setQuestion(event.target.value)} onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void ask(); } }} placeholder="Ask OpsPilot to investigate a metric, spike, service, log, or resource trend…" maxLength={1000} /><div><span><ShieldLock24Regular /> No arbitrary shell · evidence redacted · state changes require confirmation</span><Button appearance="primary" icon={<Bot24Regular />} disabled={!question.trim() || loading} onClick={() => void ask()}>Investigate</Button></div></footer></section><RemediationDialog action={remediation} close={() => setRemediation(null)} /></div>;
}

export { RemediationDialog };
