import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ChangeEvent, FormEvent, ReactNode } from 'react';
import { Link, NavLink, Route, Routes, useLocation } from 'react-router-dom';
import {
  Activity, AlertOctagon, ArrowDownToLine, ArrowRight, Ban, Check, CheckCircle2,
  ChevronDown, Clock3, Command, Database, FileSearch, Fingerprint, GitBranch,
  GitCommitHorizontal, KeyRound, LayoutDashboard, LockKeyhole, Network, Plus,
  RefreshCw, Search, Settings2, Shield, ShieldAlert, ShieldCheck, ShieldX, Upload,
  Waypoints, X,
} from 'lucide-react';

type Json = Record<string, unknown>;
type ApiProblem = { detail?: string };
type Health = {
  service: string; version: string; status: string; security_core: string;
  components: Record<string, string>; audit_integrity: { valid: boolean; events_total: number; events_verified: number; first_invalid_sequence: number | null; head_hash?: string; tamper_evident_not_immutable: boolean };
  limitations: string[];
};
type Task = { task_id: string; envelope: Record<string, any>; signature: string; action_count: number; created_at: string };
type DecisionRow = { decision_id: string; task_id: string; outcome: string; reason: string; created_at: string; details: Record<string, any>; request_digest: string };
type Inspection = { inspection_id: string; artifact_id: string; sha256: string; filename: string; format: string; status: string; threat_classification: string; confidence: number; suspicious_indicators: { code: string; severity: string; description: string; evidence?: string }[]; limitations: string[]; discrepancies: string[]; representations: Record<string, string>; coverage: Record<string, any>; created_at: string };
type AuditEvent = { sequence: number; event_id: string; occurred_at: string; payload: Record<string, any>; previous_hash: string; event_hash: string };
type Overview = { status: string; counts: Record<string, any>; recent_decisions: DecisionRow[]; recent_inspections: Inspection[]; audit_integrity: Health['audit_integrity']; security_boundary: Record<string, string> };
type Graph = { nodes: { id: string; kind: string; label: string; outcome?: string }[]; edges: { source: string; target: string; label: string }[]; source: string; truncated: boolean };
type Policy = { version: string; mode: string; decision_outcomes: string[]; rules: { id: string; effect: string; description: string }[]; mutable_from_agent: boolean };
type LabReport = { mode: string; source: string; scenarios: Record<string, any>[]; metrics: Record<string, any>; limitations: string[] };

const navigation = [
  { path: '/', label: 'Security overview', icon: LayoutDashboard },
  { path: '/agents', label: 'Agent monitor', icon: Activity },
  { path: '/tasks', label: 'Task envelopes', icon: KeyRound },
  { path: '/actions', label: 'Action stream', icon: ArrowDownToLine },
  { path: '/graph', label: 'Action graph', icon: Waypoints },
  { path: '/vision', label: 'ICE-VISION', icon: FileSearch },
  { path: '/flow', label: 'Data flow', icon: Network },
  { path: '/policy', label: 'Policy studio', icon: ShieldCheck },
  { path: '/registry', label: 'Agent registry', icon: Fingerprint },
  { path: '/lab', label: 'Threat lab', icon: ShieldAlert },
  { path: '/incidents', label: 'Incident center', icon: AlertOctagon },
  { path: '/audit', label: 'Audit ledger', icon: GitCommitHorizontal },
  { path: '/settings', label: 'System health', icon: Settings2 },
];

function prettyDate(value?: string) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}
function short(value?: string, size = 10) { return value ? `${value.slice(0, size)}…` : '—'; }
function outcomeClass(value?: string) { return `status-pill status-${(value || 'unknown').toLowerCase()}`; }
function relativeAge(value?: string) {
  if (!value) return 'No recent activity';
  const ms = Date.now() - new Date(value).valueOf();
  if (!Number.isFinite(ms)) return value;
  const mins = Math.max(0, Math.floor(ms / 60_000));
  return mins < 1 ? 'Just now' : mins < 60 ? `${mins}m ago` : `${Math.floor(mins / 60)}h ago`;
}

async function requestJson<T>(token: string, path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('Accept', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init?.body) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...init, headers });
  const body = await response.json().catch(() => ({} as ApiProblem));
  if (!response.ok) throw new Error((body as ApiProblem).detail || `Request failed with HTTP ${response.status}`);
  return body as T;
}

function useEndpoint<T>(token: string, path: string | null, refreshKey = 0) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let alive = true;
    if (!path || !token) {
      setData(null); setError(''); setLoading(false);
      return () => { alive = false; };
    }
    setLoading(true); setError('');
    requestJson<T>(token, path).then((value) => { if (alive) setData(value); })
      .catch((reason: Error) => { if (alive) { setData(null); setError(reason.message); } })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [token, path, refreshKey]);
  return { data, loading, error };
}

function useHealth() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState('');
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    requestJson<Health>('', '/api/health').then((value) => { if (alive) setHealth(value); })
      .catch((reason: Error) => { if (alive) setError(reason.message); });
    return () => { alive = false; };
  }, [tick]);
  return { health, error, refresh: () => setTick((value) => value + 1) };
}

function EmptyState({ icon: Icon = Database, title, detail }: { icon?: typeof Database; title: string; detail: string }) {
  return <div className="empty-state"><span className="empty-icon"><Icon size={18} /></span><strong>{title}</strong><p>{detail}</p></div>;
}
function SectionTitle({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: ReactNode }) {
  return <div className="section-title"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{detail}</p></div>{action}</div>;
}
function Notice({ tone = 'info', children }: { tone?: 'info' | 'danger' | 'success' | 'warning'; children: ReactNode }) {
  return <div className={`notice notice-${tone}`} role="status"><span className="notice-mark">{tone === 'danger' ? <ShieldX size={16} /> : tone === 'success' ? <CheckCircle2 size={16} /> : tone === 'warning' ? <ShieldAlert size={16} /> : <Shield size={16} />}</span><div>{children}</div></div>;
}
function LoadingLine() { return <div className="loading-line"><span /> Loading verified service data…</div>; }
function ErrorNotice({ error }: { error: string }) { return error ? <Notice tone="danger">{error}</Notice> : null; }
function DataLock() { return <div className="lock-panel"><LockKeyhole size={20} /><div><strong>Operator authorization required</strong><p>Enter the operator bearer token in the left rail. It is kept in this page’s memory and is not written to browser storage.</p></div></div>; }
function DataTable({ headers, children, empty }: { headers: string[]; children: ReactNode; empty?: string }) {
  const items = Array.isArray(children) ? children.filter(Boolean) : children;
  const emptyCollection = Array.isArray(items) && items.length === 0;
  return <div className="table-wrap"><table><thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead><tbody>{emptyCollection ? <tr><td colSpan={headers.length} className="table-empty">{empty || 'No events recorded.'}</td></tr> : items}</tbody></table></div>;
}
function StatusPill({ value }: { value: string }) { return <span className={outcomeClass(value)}><i />{value}</span>; }

function OverviewPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<Overview>(token, token ? '/api/overview' : null);
  return <>
    <SectionTitle eyebrow="CONTROL PLANE / LIVE STATE" title="Security overview" detail="Observed enforcement state from BLACK ICE’s local control plane." action={<span className="source-tag"><span className="pulse-dot" /> API-backed</span>} />
    {!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}
    {data && <>
      {data.status !== 'ready' && <Notice tone="warning">Control plane is in <strong>restricted</strong> mode. Check signing-key, operator-token and audit-integrity status in System Health; protected actions remain fail-closed.</Notice>}
      <div className="metric-grid">
        <Metric label="Active task envelopes" value={data.counts.tasks_active ?? 0} sub={`${data.counts.tasks_total ?? 0} total issued`} icon={KeyRound} />
        <Metric label="Recent decisions" value={data.counts.decisions_recent ?? 0} sub="latest 100 stored decisions" icon={Shield} />
        <Metric label="Artifact inspections" value={data.counts.inspections_total ?? 0} sub="originals retained by content hash" icon={FileSearch} />
        <Metric label="Audit chain" value={data.audit_integrity.valid ? 'VERIFIED' : 'FAILED'} sub={`${data.audit_integrity.events_verified} / ${data.audit_integrity.events_total} links verified`} icon={GitBranch} tone={data.audit_integrity.valid ? 'good' : 'bad'} />
      </div>
      <div className="dashboard-grid">
        <div className="panel panel-wide"><PanelHeading title="Recent action decisions" meta="REAL API EVENTS" /><DataTable headers={['Decision', 'Task', 'Operation', 'Resource', 'Outcome', 'When']} empty="No action decisions have been recorded yet.">{data.recent_decisions.map((row) => <tr key={row.decision_id}><td className="mono">{short(row.decision_id)}</td><td className="mono">{short(row.task_id, 8)}</td><td>{row.details.operation || '—'}</td><td className="mono">{row.details.resource || '—'}</td><td><StatusPill value={row.outcome} /></td><td className="muted">{relativeAge(row.created_at)}</td></tr>)}</DataTable></div>
        <div className="panel"><PanelHeading title="Enforcement boundary" meta="CURRENT LIMITS" /><div className="boundary-list">{Object.entries(data.security_boundary).map(([key, value]) => <div className="boundary-row" key={key}><span>{key.replaceAll('_', ' ')}</span><span>{value}</span></div>)}</div><div className="panel-note">A request can execute only when routed through the registered gateway adapter.</div></div>
        <div className="panel"><PanelHeading title="Decision distribution" meta="RECENT 100" /><div className="distribution-list">{Object.entries(data.counts.decision_outcomes || {}).map(([name, value]) => <div key={name} className="distribution-row"><span className="dist-label"><i className={`dot-${name.toLowerCase()}`} />{name}</span><strong>{value as number}</strong></div>)}</div></div>
      </div>
    </>}
  </>;
}
function Metric({ label, value, sub, icon: Icon, tone = 'normal' }: { label: string; value: ReactNode; sub: string; icon: typeof Shield; tone?: string }) {
  return <div className={`metric-card metric-${tone}`}><div className="metric-top"><span>{label}</span><Icon size={17} /></div><strong className="metric-value">{value}</strong><div className="metric-sub">{sub}</div></div>;
}
function PanelHeading({ title, meta, action }: { title: string; meta?: string; action?: ReactNode }) {
  return <div className="panel-heading"><div><h2>{title}</h2>{meta && <span>{meta}</span>}</div>{action}</div>;
}

function TasksPage({ token, onRequest }: { token: string; onRequest: (path: string, method: string, body?: Json) => Promise<any> }) {
  const [refresh, setRefresh] = useState(0);
  const { data, loading, error } = useEndpoint<Task[]>(token, token ? '/api/tasks' : null, refresh);
  const [agent, setAgent] = useState('research-agent');
  const [allowWrite, setAllowWrite] = useState(false);
  const [approval, setApproval] = useState(false);
  const [issued, setIssued] = useState<any>(null);
  const [actionError, setActionError] = useState('');
  const [busy, setBusy] = useState(false);
  const createTask = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setActionError(''); setIssued(null);
    try {
      const response = await onRequest('/api/tasks', 'POST', {
        agent_id: agent.trim(), task_owner: 'operator',
        permitted_filesystem_operations: ['list', 'read', ...(allowWrite ? ['write'] : [])],
        permitted_tools: ['filesystem'], approval_requirements: approval ? ['filesystem.write'] : [],
      });
      setIssued(response); setRefresh((value) => value + 1);
    } catch (reason) { setActionError(reason instanceof Error ? reason.message : 'Task creation failed'); }
    finally { setBusy(false); }
  };
  const revoke = async (taskId: string) => {
    if (!window.confirm('Revoke this task immediately? Existing workspace files will be preserved.')) return;
    try { await onRequest(`/api/tasks/${taskId}/revoke`, 'POST', {}); setRefresh((value) => value + 1); }
    catch (reason) { setActionError(reason instanceof Error ? reason.message : 'Revocation failed'); }
  };
  return <>
    <SectionTitle eyebrow="ICE-POLICY / SIGNED AUTHORITY" title="Task Security Envelopes" detail="Issue narrow, expiring task capabilities; agent identity and operation scope are checked again at every gateway call." />
    {!token && <DataLock />}{error && <ErrorNotice error={error} />}{actionError && <ErrorNotice error={actionError} />}
    {token && <div className="panel task-issuer"><PanelHeading title="Issue a protected task" meta="OPERATOR AUTHORIZED" /><form className="issue-form" onSubmit={createTask}>
      <label>Agent identity<input value={agent} onChange={(event) => setAgent(event.target.value)} maxLength={128} required /></label>
      <label className="check-row"><input type="checkbox" checked={allowWrite} onChange={(event) => setAllowWrite(event.target.checked)} />Permit workspace writes</label>
      <label className="check-row"><input type="checkbox" checked={approval} onChange={(event) => setApproval(event.target.checked)} disabled={!allowWrite} />Require operator review for writes</label>
      <button className="button button-primary" disabled={busy || !agent.trim()}><Plus size={15} />{busy ? 'Issuing…' : 'Issue signed envelope'}</button>
    </form>
    {issued && <div className="issued-box"><div className="issued-title"><CheckCircle2 size={17} />Task issued · token shown once</div><div className="issued-grid"><span>Task ID</span><code>{issued.envelope.task_id}</code><span>Agent</span><code>{issued.envelope.agent_id}</code><span>Expires</span><code>{prettyDate(issued.envelope.expires_at)}</code><span>Agent token</span><code className="token-once">{issued.agent_token}</code></div><Notice tone="warning">Copy this token to the agent through a secure channel. It cannot be retrieved later and must not be stored in source code.</Notice></div>}
    </div>}
    <div className="panel"><PanelHeading title="Issued envelopes" meta={data ? `${data.length} RECORDS` : 'API DATA'} action={<button className="icon-button" onClick={() => setRefresh((value) => value + 1)} aria-label="Refresh tasks"><RefreshCw size={15} /></button>} />
      {loading && <LoadingLine />}
      {data && <DataTable headers={['Task / agent', 'Capabilities', 'Lifetime', 'Actions', 'State']} empty="No task envelopes issued yet.">{data.map((task) => <tr key={task.task_id}><td><div className="primary-cell mono">{short(task.task_id, 12)}</div><div className="muted">{task.envelope.agent_id}</div></td><td className="capability-cell">{task.envelope.permitted_tools?.join(', ') || 'none'}<div className="muted">{task.envelope.permitted_filesystem_operations?.join(' · ') || 'no filesystem operations'}</div></td><td>{prettyDate(task.envelope.expires_at)}</td><td>{task.action_count} / {task.envelope.resource_limits?.max_actions ?? '—'}</td><td className="state-actions"><StatusPill value={task.envelope.task_state} />{task.envelope.task_state === 'ACTIVE' && <button className="text-button danger-text" onClick={() => void revoke(task.task_id)}>Revoke</button>}</td></tr>)}</DataTable>}
    </div>
  </>;
}

function AgentsPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<Task[]>(token, token ? '/api/tasks' : null);
  const agents = useMemo(() => {
    const byId = new Map<string, Task[]>();
    for (const task of data || []) byId.set(task.envelope.agent_id, [...(byId.get(task.envelope.agent_id) || []), task]);
    return [...byId.entries()].map(([agent, tasks]) => ({ agent, tasks, active: tasks.filter((task) => task.envelope.task_state === 'ACTIVE').length, last: tasks[0]?.created_at }));
  }, [data]);
  return <><SectionTitle eyebrow="IDENTITY / OBSERVABILITY" title="Agent monitor" detail="Agents are observed through issued task envelopes and gateway requests; BLACK ICE does not claim to observe unmediated processes." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{data && <div className="agent-grid">{agents.length ? agents.map((agent) => <div className="panel agent-card" key={agent.agent}><div className="agent-glyph"><Fingerprint size={20} /></div><div className="agent-name">{agent.agent}</div><div className="agent-id">{agent.tasks.length} envelope{agent.tasks.length === 1 ? '' : 's'} · observed {relativeAge(agent.last)}</div><div className="agent-stats"><span><strong>{agent.active}</strong> active task{agent.active === 1 ? '' : 's'}</span><span><strong>{agent.tasks.length}</strong> total</span></div><Link to="/tasks" className="inline-link">View envelopes <ArrowRight size={14} /></Link></div>) : <EmptyState icon={Fingerprint} title="No registered agent activity" detail="An identity is derived from operator-issued task envelopes; no synthetic agent telemetry is shown." />}</div>}</>;
}

function ActionStreamPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<DecisionRow[]>(token, token ? '/api/decisions?limit=200' : null);
  const [query, setQuery] = useState('');
  const filtered = (data || []).filter((item) => `${item.task_id} ${item.outcome} ${item.details.operation} ${item.details.resource} ${item.reason}`.toLowerCase().includes(query.toLowerCase()));
  return <><SectionTitle eyebrow="ICE-GATE / DECISION TRACE" title="Action stream" detail="Structured authorization decisions and adapter execution summaries. Parameters and file contents are not written to this ledger." action={<label className="search-box"><Search size={15} /><input aria-label="Search action stream" placeholder="Filter events" value={query} onChange={(event) => setQuery(event.target.value)} /></label>} />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{data && <div className="panel"><PanelHeading title="Gateway decisions" meta={`${filtered.length} OF ${data.length} EVENTS`} /><DataTable headers={['Time', 'Outcome', 'Agent', 'Tool / operation', 'Resource', 'Policy reason']} empty="No gateway actions have been requested.">{filtered.map((item) => <tr key={item.decision_id}><td className="muted">{prettyDate(item.created_at)}</td><td><StatusPill value={item.outcome} /></td><td className="mono">{short(item.details.agent_id, 12)}</td><td>{item.details.tool_id}.{item.details.operation}</td><td className="mono">{item.details.resource}</td><td className="reason-cell">{item.reason}</td></tr>)}</DataTable></div>}</>;
}

function GraphPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<Graph>(token, token ? '/api/graph' : null);
  return <><SectionTitle eyebrow="ICE-TRACE / RELATIONSHIPS" title="Action graph" detail="Graph nodes and links are derived from stored SQLite audit events; this view is limited to retained event history." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{data && <div className="panel graph-panel"><PanelHeading title="Task → decision → artifact" meta={`${data.nodes.length} NODES · ${data.edges.length} EDGES`} /><div className="graph-legend"><span><i className="legend-task" />Task</span><span><i className="legend-decision" />Decision</span><span><i className="legend-artifact" />Artifact</span></div>{data.nodes.length === 0 ? <EmptyState icon={Waypoints} title="No action relationships" detail="Task and artifact nodes appear after actual gateway operations or inspections." /> : <GraphView data={data} />}{data.truncated && <div className="panel-note">Graph uses the latest 200 retained audit events; earlier relationships may be omitted.</div>}<div className="source-note">Source: {data.source}</div></div>}</>;
}
function GraphView({ data }: { data: Graph }) {
  const width = 960; const height = Math.max(300, Math.ceil(data.nodes.length / 4) * 76 + 70);
  const positions = new Map<string, { x: number; y: number }>();
  data.nodes.forEach((node, index) => positions.set(node.id, { x: 80 + (index % 4) * 270, y: 60 + Math.floor(index / 4) * 76 }));
  return <div className="graph-canvas"><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Action graph of tasks, decisions, and inspected artifacts"><defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#486171" /></marker></defs>{data.edges.map((edge, index) => { const a = positions.get(edge.source); const b = positions.get(edge.target); if (!a || !b) return null; return <g key={`${edge.source}-${edge.target}-${index}`}><line x1={a.x + 82} y1={a.y + 16} x2={b.x - 9} y2={b.y + 16} stroke="#385060" strokeWidth="1.5" markerEnd="url(#arrow)" /><text x={(a.x + b.x) / 2 + 24} y={(a.y + b.y) / 2 + 10} className="edge-label">{edge.label}</text></g>; })}{data.nodes.map((node) => { const pos = positions.get(node.id)!; return <g key={node.id} transform={`translate(${pos.x},${pos.y})`} className={`graph-node graph-${node.kind}`}><rect width="164" height="34" rx="6" /><text x="12" y="14" className="node-kind">{node.kind.toUpperCase()}</text><text x="12" y="27" className="node-label">{node.label.slice(0, 20)}</text></g>; })}</svg></div>;
}

function VisionPage({ token, onRequest }: { token: string; onRequest: (path: string, method: string, body?: Json) => Promise<any> }) {
  const [report, setReport] = useState<Inspection | null>(null);
  const [inspections, setInspections] = useState<Inspection[] | null>(null);
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  useEffect(() => { if (!token) { setInspections(null); return; } let alive = true; requestJson<Inspection[]>(token, '/api/artifacts/inspections').then((items) => { if (alive) setInspections(items); }).catch(() => { if (alive) setInspections([]); }); return () => { alive = false; }; }, [token]);
  const inspectFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]; if (!file) return;
    if (file.size > 10 * 1024 * 1024) { setError('File exceeds the 10 MiB artifact limit.'); return; }
    setBusy(true); setError(''); setReport(null);
    try {
      const base64 = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader(); reader.onload = () => resolve(String(reader.result).split(',')[1] || ''); reader.onerror = () => reject(new Error('File could not be read'));
        reader.readAsDataURL(file);
      });
      const result = await onRequest('/api/artifacts/inspect', 'POST', { filename: file.name, content_base64: base64, source: 'security-console-upload', provenance: { channel: 'operator-upload' } });
      setReport(result); setInspections((current) => [result, ...(current || []).filter((item) => item.inspection_id !== result.inspection_id)]);
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Inspection failed'); }
    finally { setBusy(false); event.target.value = ''; }
  };
  return <><SectionTitle eyebrow="ICE-VISION / MULTI-REPRESENTATION" title="Artifact inspection" detail="Upload an artifact for bounded, non-executing parsing. Original bytes are retained by SHA-256; parser gaps remain explicit." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{token && <div className="upload-panel"><div className="upload-icon"><Upload size={19} /></div><div><strong>Inspect an artifact</strong><p>HTML, Markdown, text, PDF, Office Open XML, SVG, PNG/JPEG, ZIP, source code, JSON, XML · 10 MiB maximum.</p></div><label className="button button-primary upload-button"><Upload size={14} />{busy ? 'Inspecting…' : 'Choose file'}<input type="file" onChange={(event) => void inspectFile(event)} disabled={busy} /></label></div>}
    {report && <div className="panel inspection-report"><PanelHeading title={report.filename} meta={`${report.format.toUpperCase()} · ${report.status.toUpperCase()}`} /><div className="report-summary"><StatusPill value={report.threat_classification} /><span>SHA-256 <code>{report.sha256}</code></span><span>Confidence <strong>{Math.round(report.confidence * 100)}%</strong></span></div>{report.suspicious_indicators.length > 0 ? <div className="finding-list">{report.suspicious_indicators.map((finding, index) => <div key={`${finding.code}-${index}`} className={`finding finding-${finding.severity}`}><ShieldAlert size={16} /><div><strong>{finding.code}</strong><p>{finding.description}</p>{finding.evidence && <code>{finding.evidence}</code>}</div><span>{finding.severity}</span></div>)}</div> : <Notice tone="info">No deterministic indicator was found. This is not proof that the artifact is safe.</Notice>}<div className="coverage-block"><h3>Coverage & limitations</h3><div className="coverage-chips">{Object.keys(report.representations).map((key) => <span key={key}>{key}</span>)}</div><ul>{[...report.limitations, ...report.discrepancies].map((item) => <li key={item}>{item}</li>)}</ul></div><details className="representations"><summary>Extracted representations</summary>{Object.entries(report.representations).map(([name, value]) => <div key={name} className="representation"><h4>{name}</h4><pre>{value || '(no text extracted)'}</pre></div>)}</details></div>}
    {inspections && <div className="panel"><PanelHeading title="Inspection history" meta={`${inspections.length} STORED REPORTS`} /><DataTable headers={['Artifact', 'Format', 'Status', 'Classification', 'SHA-256', 'Inspected']} empty="No artifacts have been inspected.">{inspections.map((item) => <tr key={item.inspection_id}><td>{item.filename}</td><td>{item.format}</td><td><StatusPill value={item.status} /></td><td>{item.threat_classification}</td><td className="mono">{short(item.sha256, 14)}</td><td>{prettyDate(item.created_at)}</td></tr>)}</DataTable></div>}
  </>;
}

function FlowPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<{ observed_operations: Record<string, any>[]; coverage: string; limitations: string[] }>(token, token ? '/api/flow/summary' : null);
  return <><SectionTitle eyebrow="ICE-FLOW / OBSERVED DATA MOVEMENT" title="Data flow monitor" detail="A bounded view of data classifications and operations observed at the gateway; no dynamic taint tracking is claimed." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{data && <><Notice tone="warning">{data.coverage}</Notice><div className="panel"><PanelHeading title="Observed file and tool operations" meta={`${data.observed_operations.length} RECORDS`} /><DataTable headers={['Time', 'Task', 'Operation', 'Resource', 'Classification', 'Execution', 'Decision']} empty="No gateway-mediated data movement observed.">{data.observed_operations.map((item) => <tr key={item.decision_id}><td>{prettyDate(item.created_at)}</td><td className="mono">{short(item.task_id, 8)}</td><td>{item.tool_id}.{item.operation}</td><td className="mono">{item.resource}</td><td>{item.data_classification || 'unclassified'}</td><td>{item.execution_status || 'not-executed'}</td><td><StatusPill value={item.outcome} /></td></tr>)}</DataTable></div><div className="panel-note-box"><strong>Known gaps</strong>{data.limitations.map((item) => <span key={item}>{item}</span>)}</div></>}</>;
}

function PolicyPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<Policy>(token, token ? '/api/policy' : null);
  return <><SectionTitle eyebrow="ICE-POLICY / VERSIONED RULES" title="Policy studio" detail="Transparent, deterministic baseline rules. This build exposes policy for inspection; in-console policy mutation is not implemented." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{data && <><div className="policy-banner"><div className="policy-mark"><ShieldCheck size={22} /></div><div><span>ACTIVE POLICY · {data.version}</span><h2>{data.mode}</h2><p>External content and agent messages are not policy authority.</p></div><span className="read-only-chip">READ ONLY</span></div><div className="panel"><PanelHeading title="Decision rules" meta={`${data.rules.length} RULES · AGENT MUTATION ${data.mutable_from_agent ? 'ALLOWED' : 'DENIED'}`} /><div className="policy-rules">{data.rules.map((rule, index) => <div className="policy-rule" key={rule.id}><span className="rule-number">{String(index + 1).padStart(2, '0')}</span><code>{rule.id}</code><span className={`effect effect-${rule.effect}`}>{rule.effect}</span><p>{rule.description}</p></div>)}</div></div><div className="panel-note-box"><strong>Change control</strong><span>Policy is currently defined by source-controlled deterministic rules. The protected agent cannot change it.</span><span>Operator policy authoring, version promotion and independent two-person approval are not implemented in this build.</span></div></>}</>;
}

function RegistryPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<Task[]>(token, token ? '/api/tasks' : null);
  const agents = useMemo(() => {
    const map = new Map<string, Task[]>();
    for (const item of data || []) map.set(item.envelope.agent_id, [...(map.get(item.envelope.agent_id) || []), item]);
    return [...map.entries()].map(([id, tasks]) => ({ id, tasks }));
  }, [data]);
  return <><SectionTitle eyebrow="IDENTITY / SCOPED AUTHORITY" title="Agent identity registry" detail="Registry entries are derived from operator-issued signed envelopes; there is no self-service identity creation or identity-provider integration." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{data && <div className="panel"><PanelHeading title="Observed agent identities" meta={`${agents.length} IDENTITIES`} /><DataTable headers={['Agent ID', 'Envelopes', 'Active', 'Latest issue', 'Boundary']} empty="No agent identities have been issued.">{agents.map(({ id, tasks }) => <tr key={id}><td className="mono">{id}</td><td>{tasks.length}</td><td>{tasks.filter((task) => task.envelope.task_state === 'ACTIVE').length}</td><td>{prettyDate(tasks[0]?.created_at)}</td><td>task-scoped bearer + signed TSE</td></tr>)}</DataTable></div>}</>;
}

function ThreatLabPage({ token, onRequest }: { token: string; onRequest: (path: string, method: string, body?: Json) => Promise<any> }) {
  const [report, setReport] = useState<LabReport | null>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  const run = async () => { setBusy(true); setError(''); try { setReport(await onRequest('/api/lab/run', 'POST', {})); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Lab run failed'); } finally { setBusy(false); } };
  return <><SectionTitle eyebrow="ICE-LAB / SYNTHETIC VALIDATION" title="Threat lab" detail="Run synthetic cases through the current gateway and parser implementations. This is a demonstration, not real-world attack validation." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{token && <div className="lab-launch"><div className="lab-emblem"><ShieldAlert size={22} /></div><div><strong>Run the bounded synthetic suite</strong><p>Exercises allowed reads, traversal denial, unregistered command denial, data redaction, attempted egress, approval review, hidden HTML inspection and revocation.</p></div><button className="button button-primary" disabled={busy} onClick={() => void run()}><Activity size={15} />{busy ? 'Running scenarios…' : 'Run ICE-LAB'}</button></div>}
    {report && <><Notice tone="warning">Run mode: {report.mode}. Results represent only these synthetic cases; no third-party systems were contacted.</Notice><div className="metric-grid lab-metrics"><Metric label="Cases passed" value={`${report.metrics.passed_count}/${report.metrics.scenario_count}`} sub="actual gate/vision outcomes" icon={CheckCircle2} tone={report.metrics.failed_count ? 'bad' : 'good'} /><Metric label="Denied prohibited actions" value={`${Math.round((report.metrics.unauthorized_action_prevention_rate || 0) * 100)}%`} sub="listed attempts only" icon={Ban} /><Metric label="Mean scenario latency" value={`${report.metrics.mean_scenario_latency_ms ?? '—'} ms`} sub="single run, non-benchmark" icon={Clock3} /><Metric label="Hidden instruction" value={report.metrics.hidden_instruction_indicator_detected ? 'FOUND' : 'MISSED'} sub="synthetic HTML only" icon={FileSearch} tone={report.metrics.hidden_instruction_indicator_detected ? 'good' : 'bad'} /></div><div className="panel"><PanelHeading title="Scenario results" meta="MEASURED RUN OUTPUT" /><DataTable headers={['Scenario', 'Actual result', 'Expected', 'Status', 'Latency']} empty="No scenarios.">{report.scenarios.map((item) => <tr key={item.scenario}><td><strong>{item.scenario}</strong><div className="muted">{item.description}</div></td><td>{item.actual}</td><td>{item.expected}</td><td><StatusPill value={item.passed ? 'PASS' : 'FAIL'} /></td><td>{item.latency_ms} ms</td></tr>)}</DataTable></div><div className="panel-note-box"><strong>Metric caveats</strong>{report.limitations.map((item) => <span key={item}>{item}</span>)}</div></>}
  </>;
}

function IncidentsPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<Record<string, any>[]>(token, token ? '/api/incidents' : null);
  return <><SectionTitle eyebrow="ICE-RESPONSE / REVIEW QUEUE" title="Incident center" detail="Derived from recorded denial/review decisions and task revocations. No automatic destructive response is performed." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{data && <div className="panel"><PanelHeading title="Security events needing attention" meta={`${data.length} EVENTS`} /><DataTable headers={['Time / sequence', 'Event', 'Task', 'Reason / evidence', 'State']} empty="No recorded denial, review, or revocation events.">{data.map((item) => <tr key={item.event_id}><td>#{item.sequence}<div className="muted">{prettyDate(item.occurred_at)}</div></td><td>{item.decision || item.event}</td><td className="mono">{short(item.task_id, 8)}</td><td className="reason-cell">{item.reason || item.evidence || 'Administrative response event'}</td><td><StatusPill value={item.decision || item.event} /></td></tr>)}</DataTable></div>}</>;
}

function AuditPage({ token }: { token: string }) {
  const [verify, setVerify] = useState<Health['audit_integrity'] | null>(null);
  const { data, loading, error } = useEndpoint<AuditEvent[]>(token, token ? '/api/audit/events?limit=200' : null);
  useEffect(() => { if (!token) { setVerify(null); return; } let alive = true; requestJson<Health['audit_integrity']>(token, '/api/audit/verify').then((result) => { if (alive) setVerify(result); }).catch(() => { if (alive) setVerify(null); }); return () => { alive = false; }; }, [token]);
  return <><SectionTitle eyebrow="ICE-AUDIT / INTEGRITY CHAIN" title="Audit ledger" detail="SQLite events are linked with SHA-256. The chain detects many row edits; local storage is not immutable against a privileged host operator." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{verify && <div className="audit-verification"><div className={`verify-symbol ${verify.valid ? 'valid' : 'invalid'}`}>{verify.valid ? <Check size={18} /> : <X size={18} />}</div><div><strong>{verify.valid ? 'Integrity chain verified' : 'Integrity verification failed'}</strong><span>{verify.events_verified} of {verify.events_total} events checked · first invalid sequence {verify.first_invalid_sequence ?? 'none'}</span></div><span className="mono hash-head">HEAD {short(verify.head_hash, 16)}</span></div>}{data && <div className="panel"><PanelHeading title="Hash-linked events" meta={`${data.length} LATEST`} /><div className="audit-list">{data.map((event) => <div className="audit-event" key={event.event_id}><div className="audit-seq">{String(event.sequence).padStart(4, '0')}</div><div className="audit-event-body"><div className="audit-event-title"><strong>{event.payload.event || event.payload.category}</strong><span>{prettyDate(event.occurred_at)}</span></div><div className="audit-event-desc">{event.payload.reason || event.payload.operation || event.payload.event || 'Control-plane record'}</div><div className="audit-hashes"><span>PREV <code>{short(event.previous_hash, 18)}</code></span><span>HASH <code>{short(event.event_hash, 18)}</code></span></div></div></div>)}</div></div>}</>;
}

function SettingsPage({ token }: { token: string }) {
  const { data, loading, error } = useEndpoint<Record<string, any>>(token, token ? '/api/system' : null);
  return <><SectionTitle eyebrow="CONTROL PLANE / CONFIGURATION" title="System health" detail="Runtime capabilities and declared limitations. Secret values are never returned by this endpoint." />{!token && <DataLock />}{error && <ErrorNotice error={error} />}{loading && <LoadingLine />}{data && <><div className="health-grid"><HealthCard icon={Shield} title="Control plane" value={data.control_plane} /><HealthCard icon={Database} title="Persistence" value={data.database} /><HealthCard icon={KeyRound} title="TSE signing" value={data.signing_key_configured ? 'configured' : 'not configured'} /><HealthCard icon={GitBranch} title="Audit integrity" value={data.audit.valid ? 'verified' : 'failed'} /></div><div className="panel"><PanelHeading title="Runtime boundaries" meta={`POLICY ${data.policy_version}`} /><div className="boundary-list"><div className="boundary-row"><span>Artifact byte limit</span><code>{Number(data.artifact_limit_bytes).toLocaleString()} bytes</code></div><div className="boundary-row"><span>Action byte limit</span><code>{Number(data.action_limit_bytes).toLocaleString()} bytes</code></div>{(data.not_implemented as string[]).map((item) => <div className="boundary-row" key={item}><span>{item}</span><StatusPill value="not implemented" /></div>)}</div></div><Notice tone="warning">Single-process SQLite mode. Task locking is process-local; production horizontal scaling requires shared atomic revocation/locking and durable audit storage.</Notice></>}</>;
}
function HealthCard({ icon: Icon, title, value }: { icon: typeof Shield; title: string; value: string }) { return <div className="health-card"><Icon size={17} /><span>{title}</span><strong>{value}</strong></div>; }

function App() {
  const [token, setToken] = useState('');
  const [tokenInput, setTokenInput] = useState('');
  const location = useLocation();
  const { health, error: healthError, refresh: refreshHealth } = useHealth();
  const active = navigation.find((item) => item.path === location.pathname) || navigation[0];
  const onRequest = useCallback(async (path: string, method: string, body?: Json) => {
    return requestJson<any>(token, path, { method, body: body === undefined ? undefined : JSON.stringify(body) });
  }, [token]);
  const unlock = (event: FormEvent) => { event.preventDefault(); setToken(tokenInput.trim()); setTokenInput(''); };
  const clearToken = () => { setToken(''); setTokenInput(''); };
  return <div className="app-shell">
    <aside className="sidebar">
      <Link to="/" className="brand"><span className="brand-mark"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 29 9.5v13L16 30 3 22.5v-13L16 2Z" fill="none" stroke="currentColor" strokeWidth="1.5"/><path d="m10 21 6-10 6 10M12.2 17.5h7.6" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="square"/></svg></span><span><strong>BLACK ICE</strong><small>CONTROL PLANE</small></span></Link>
      <div className="sidebar-section-label">OPERATIONS</div>
      <nav className="side-nav" aria-label="Primary navigation">{navigation.map(({ path, label, icon: Icon }) => <NavLink to={path} aria-label={label} end={path === '/'} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} key={path}><Icon size={16} strokeWidth={1.8} /><span>{label}</span>{path === '/incidents' && <span className="nav-count">{health?.audit_integrity?.valid === false ? '!' : ''}</span>}</NavLink>)}</nav>
      <div className="side-spacer" />
      <div className="operator-box">
        <div className="operator-heading"><KeyRound size={14} /><span>OPERATOR ACCESS</span><span className={`credential-dot ${token ? 'connected' : ''}`} /></div>
        {token ? <><div className="token-state"><CheckCircle2 size={14} /><span>Token held in memory</span></div><button className="text-button clear-token" onClick={clearToken}>Clear authorization</button></> : <form onSubmit={unlock}><label className="sr-only" htmlFor="operator-token">Operator bearer token</label><input id="operator-token" type="password" placeholder="Paste operator token" value={tokenInput} onChange={(event) => setTokenInput(event.target.value)} autoComplete="off" /><button className="button button-unlock" type="submit" disabled={!tokenInput.trim()}>Unlock console <ArrowRight size={13} /></button><p>Required for API data. Never stored in browser storage.</p></form>}
      </div>
      <div className="sidebar-footer"><span className={`connection-dot ${health?.status === 'ready' ? 'healthy' : ''}`} /><span>{healthError ? 'API unavailable' : health ? `CORE ${health.status.toUpperCase()}` : 'CONNECTING'}</span><span className="version-mark">v0.1.0</span></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="breadcrumb"><span>BLACK ICE</span><ChevronDown size={13} /><strong>{active.label}</strong></div><div className="topbar-right"><div className={`service-state ${health?.status === 'ready' ? 'state-ready' : 'state-restricted'}`}><span className="pulse-dot" />{health?.status === 'ready' ? 'ENFORCEMENT READY' : 'RESTRICTED MODE'}</div><button className="icon-button" aria-label="Refresh service state" onClick={refreshHealth}><RefreshCw size={15} /></button></div></header>
      <div className="content-area"><Routes>
        <Route path="/" element={<OverviewPage token={token} />} />
        <Route path="/agents" element={<AgentsPage token={token} />} />
        <Route path="/tasks" element={<TasksPage token={token} onRequest={onRequest} />} />
        <Route path="/actions" element={<ActionStreamPage token={token} />} />
        <Route path="/graph" element={<GraphPage token={token} />} />
        <Route path="/vision" element={<VisionPage token={token} onRequest={onRequest} />} />
        <Route path="/flow" element={<FlowPage token={token} />} />
        <Route path="/policy" element={<PolicyPage token={token} />} />
        <Route path="/registry" element={<RegistryPage token={token} />} />
        <Route path="/lab" element={<ThreatLabPage token={token} onRequest={onRequest} />} />
        <Route path="/incidents" element={<IncidentsPage token={token} />} />
        <Route path="/audit" element={<AuditPage token={token} />} />
        <Route path="/settings" element={<SettingsPage token={token} />} />
        <Route path="*" element={<div className="panel"><EmptyState icon={Command} title="Route not found" detail="Choose a control-plane section from the navigation." /></div>} />
      </Routes></div>
      <footer className="page-footer"><span>BLACK ICE · INDEPENDENT ACTION CONTROL</span><span>DETECT ≠ PREVENT · NO UNMEDIATED TOOL GUARANTEE</span></footer>
    </main>
  </div>;
}

export default App;
