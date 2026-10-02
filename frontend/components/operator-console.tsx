"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, Boxes, ChevronRight, CircleStop, Command, Crosshair,
  Database, Download, FileSearch, Gauge, GitFork, LogOut, OctagonX, Play, Radar, RefreshCw, Search,
  Settings2, ShieldAlert, ShieldCheck, Sparkles, TerminalSquare, Trash2, WandSparkles, X,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import remarkGfm from "remark-gfm";

import { api, formatDate, pct } from "@/lib/api";
import type {
  CytoscapePayload, Evidence, Finding, GraphAnalysis, GraphAsset, Json, Overview,
  Page, PriorityPayload, RemediationAction, RetestAttempt, Scan, ScanEvent,
  ScanResults, ValidatedFinding,
} from "@/lib/types";
import { AttackGraph } from "./attack-graph";
import { exportInteractiveGraph, type GraphExportMetrics } from "@/lib/graph-export";
import { IntelView } from "./intel-view";
import { AIProviderConfig, defaultAIProvider, type AIProviderSettings } from "./ai-provider-config";

type View = "overview" | "new-scan" | "scans" | "findings" | "graph" | "assets" | "remediation" | "intel" | "system";

const views: Array<{ id: View; label: string; icon: typeof Gauge }> = [
  { id: "overview", label: "Command Center", icon: Gauge },
  { id: "new-scan", label: "New Scan", icon: Crosshair },
  { id: "scans", label: "Scans", icon: Radar },
  { id: "findings", label: "Findings", icon: FileSearch },
  { id: "graph", label: "Attack Graph", icon: GitFork },
  { id: "assets", label: "Assets", icon: Boxes },
  { id: "remediation", label: "Remediation", icon: WandSparkles },
  { id: "intel", label: "Intelligence", icon: ShieldAlert },
  { id: "system", label: "System", icon: Settings2 },
];

const activeStates = new Set(["queued", "claimed", "running"]);

function useOverview() {
  return useQuery({
    queryKey: ["overview"], queryFn: () => api<Overview>("api/v1/console/overview"),
    refetchInterval: 5_000,
  });
}

function Loading({ label = "Loading live data" }: { label?: string }) {
  return <div className="state-box"><span className="spinner" /> {label}</div>;
}

function Failure({ error }: { error: Error }) {
  return <div className="error-box"><AlertTriangle size={15} /> {error.message}</div>;
}

function Status({ value }: { value: string }) {
  return <span className={`status status-${value.toLowerCase().replaceAll("_", "-")}`}>{value.replaceAll("_", " ")}</span>;
}

function SafeMarkdown({ children }: { children: string }) {
  return <div className="markdown-body"><ReactMarkdown
    remarkPlugins={[remarkGfm]}
    skipHtml
    components={{
      a: ({ children: label, ...props }) => <a {...props} target="_blank" rel="noreferrer noopener">{label}</a>,
      img: ({ alt }) => <span className="muted">[Image omitted{alt ? `: ${alt}` : ""}]</span>,
    }}
  >{children}</ReactMarkdown></div>;
}

function Severity({ value }: { value: string | null }) {
  const severity = (value ?? "info").toLowerCase();
  return <span className={`severity severity-${severity}`}>{severity}</span>;
}

function Metric({ label, value, detail }: { label: string; value: number | string; detail?: string }) {
  return <article className="metric"><p>{label}</p><strong>{value}</strong>{detail && <span>{detail}</span>}</article>;
}

export function OperatorConsole() {
  const [view, setView] = useState<View>("overview");
  const [palette, setPalette] = useState(false);
  const [globalSearch, setGlobalSearch] = useState("");
  const [remediationFinding, setRemediationFinding] = useState("");
  const [remediationScan, setRemediationScan] = useState("");
  const [scanRunId, setScanRunId] = useState("");
  const [scopeInitialized, setScopeInitialized] = useState(false);
  const queryClient = useQueryClient();
  const overview = useOverview();
  // The scan is the unit of analysis: this global selector scopes Findings, the
  // Attack Graph, the Command Center and Reports to one scan. Default to the most
  // recent scan; "" is the explicit all-scans union.
  const scopeScans = useQuery({ queryKey: ["scope-scans"], queryFn: () => api<Page<Scan>>("api/v1/console/scans?limit=100"), refetchInterval: 15_000 });
  useEffect(() => {
    if (scopeInitialized) return;
    const latest = (scopeScans.data?.items ?? []).find((s) => s.scan_run_id);
    if (latest?.scan_run_id) { setScanRunId(latest.scan_run_id); setScopeInitialized(true); }
  }, [scopeScans.data, scopeInitialized]);

  useEffect(() => {
    const listener = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault(); setPalette((value) => !value);
      }
      if (event.key === "Escape") setPalette(false);
    };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, []);

  async function logout() {
    await fetch("/api/session", { method: "DELETE" });
    queryClient.clear();
    location.reload();
  }

  const connected = overview.isSuccess;
  const active = overview.data?.counts.active_scans ?? 0;
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="wordmark">SENTINAL <b>X</b></div>
        <div className="nav-label">OPERATIONS</div>
        <nav>{views.map(({ id, label, icon: Icon }) => (
          <button key={id} className={view === id ? "active" : ""} onClick={() => setView(id)}>
            <Icon size={16} strokeWidth={1.7} /><span>{label}</span>
            {id === "scans" && active > 0 && <em>{active}</em>}
          </button>
        ))}</nav>
        <div className="sidebar-foot">
          <div><span className={`connection-dot ${connected ? "online" : ""}`} />{connected ? "Backend connected" : "Backend unavailable"}</div>
          <button onClick={logout}><LogOut size={15} /> Sign out</button>
        </div>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <button className="command-search" onClick={() => setPalette(true)}>
            <Search size={15} /><span>Search or run a command</span><kbd>⌘ K</kbd>
          </button>
          <label className="scan-scope" title="Scope every view to one scan">
            <Radar size={14} />
            <select value={scanRunId} onChange={(event) => setScanRunId(event.target.value)} aria-label="Scan scope">
              <option value="">All scans (unified)</option>
              {(scopeScans.data?.items ?? []).filter((s) => s.scan_run_id).map((s) => <option key={s.scan_run_id!} value={s.scan_run_id!}>{s.target} · {formatDate(s.completed_at ?? s.created_at)} · {s.finding_count} findings</option>)}
            </select>
          </label>
          <div className={`connection ${connected ? "connected" : ""}`}><Activity size={14} />{connected ? "CONNECTED" : "OFFLINE"}</div>
          {active > 0 && <button className="scan-pill" onClick={() => setView("scans")}><Radar size={14} />{active} ACTIVE</button>}
          <button className="button primary compact" onClick={() => setView("new-scan")}><Play size={14} /> New scan</button>
        </header>
        <div className="page">
          {view === "overview" && <OverviewView navigate={setView} scanRunId={scanRunId} />}
          {view === "new-scan" && <NewScanView onCreated={() => setView("scans")} />}
          {view === "scans" && <ScansView search={globalSearch} onRemediate={(id) => { setRemediationFinding(""); setRemediationScan(id); setView("remediation"); }} />}
          {view === "findings" && <FindingsView search={globalSearch} scanRunId={scanRunId} onRemediate={(id) => { setRemediationScan(""); setRemediationFinding(id); setView("remediation"); }} />}
          {view === "graph" && <GraphView scanRunId={scanRunId} />}
          {view === "assets" && <AssetsView />}
          {view === "remediation" && <RemediationView initialFinding={remediationFinding} initialScan={remediationScan} scanRunId={scanRunId} />}
          {view === "intel" && <IntelView />}
          {view === "system" && <SystemView />}
        </div>
      </main>
      {palette && <CommandPalette search={globalSearch} setSearch={setGlobalSearch} navigate={(next) => { setView(next); setPalette(false); }} close={() => setPalette(false)} />}
    </div>
  );
}

function PageTitle({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: React.ReactNode }) {
  return <div className="page-title"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><span>{detail}</span></div>{action}</div>;
}

function OverviewView({ navigate, scanRunId }: { navigate: (view: View) => void; scanRunId: string }) {
  const overview = useOverview();
  const scans = useQuery({ queryKey: ["scans", "recent"], queryFn: () => api<Page<Scan>>("api/v1/console/scans?limit=6"), refetchInterval: 5_000 });
  // When a scan is selected, the triage/severity reflect that scan only; totals
  // (assets, all scans) stay global. Fetch a larger scoped page to derive counts.
  const scopedFindings = useQuery({ queryKey: ["overview-findings", scanRunId], queryFn: () => api<Page<Finding>>(`api/v1/console/findings?limit=500&scan_run_id=${encodeURIComponent(scanRunId)}`), refetchInterval: 5_000 });
  if (overview.isPending) return <Loading />;
  if (overview.error) return <Failure error={overview.error} />;
  const c = overview.data.counts;
  const items = scopedFindings.data?.items ?? [];
  const sev = (name: string) => items.filter((f) => (f.severity ?? "info").toLowerCase() === name).length;
  const scoped = Boolean(scanRunId);
  const findingsCount = scoped ? items.length : c.findings;
  const validatedCount = scoped ? items.filter((f) => f.status === "validated").length : c.validated;
  const criticalCount = scoped ? sev("critical") : c.critical;
  const highCount = scoped ? sev("high") : c.high;
  const severity = [
    { name: "Critical", value: criticalCount, fill: "#E5484D" },
    { name: "High", value: highCount, fill: "#F5820B" },
    { name: "Other", value: Math.max(findingsCount - criticalCount - highCount, 0), fill: "#71717A" },
  ];
  const latestGraph = overview.data.latest_graph;
  const triage = scoped ? items.slice(0, 6) : undefined;
  return <>
    <PageTitle eyebrow="OPERATIONS / LIVE" title="Command Center" detail={scoped ? "Scoped to the selected scan · Discovery → Validation → Attack Graph" : "All scans · Discovery → Validation → Attack Graph state"} action={<button className="button" onClick={() => navigate("graph")}><GitFork size={15} /> Open graph</button>} />
    <section className="metrics-grid">
      <Metric label="ACTIVE SCANS" value={c.active_scans} detail={`${c.scans} total`} />
      <Metric label={scoped ? "SCAN FINDINGS" : "FINDINGS"} value={findingsCount} detail={`${validatedCount} validated`} />
      <Metric label="CRITICAL / HIGH" value={`${criticalCount} / ${highCount}`} detail="raw scanner severity" />
      <Metric label="ASSETS" value={c.assets} detail={`${c.evidence} evidence artifacts`} />
    </section>
    <section className="overview-grid">
      <article className="panel radar-panel">
        <div className="radar-motif"><i /><i /><i /><span /></div>
        <div className="panel-head"><div><p className="eyebrow">ATTACK SURFACE</p><h2>Graph assurance</h2></div><Status value={latestGraph?.diagnosis ?? "not analyzed"} /></div>
        <div className="assurance-number">{latestGraph?.answerable ? "VERIFIED" : "PENDING"}</div>
        <dl className="compact-dl"><div><dt>Snapshot</dt><dd>{latestGraph?.id.slice(0, 12) ?? "—"}</dd></div><div><dt>Seed</dt><dd>{latestGraph?.seed ?? "—"}</dd></div><div><dt>Invariants</dt><dd>{latestGraph?.invariants_passed ? "PASS" : "—"}</dd></div></dl>
      </article>
      <article className="panel"><div className="panel-head"><div><p className="eyebrow">FINDINGS</p><h2>Severity inventory</h2></div></div>
        <div className="chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={severity} layout="vertical" margin={{ left: 2, right: 12 }}><XAxis type="number" hide /><YAxis type="category" dataKey="name" width={64} tick={{ fill: "#A1A1AA", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip cursor={{ fill: "#1E1E22" }} contentStyle={{ background: "#17171A", border: "1px solid #34343A" }} /><Bar dataKey="value" radius={[0, 3, 3, 0]} isAnimationActive={false}>{severity.map((entry) => <Cell key={entry.name} fill={entry.fill} />)}</Bar></BarChart></ResponsiveContainer></div>
      </article>
    </section>
    <section className="two-col">
      <article className="panel table-panel"><div className="panel-head"><div><p className="eyebrow">RECENT ACTIVITY</p><h2>Scans</h2></div><button className="link" onClick={() => navigate("scans")}>View all <ChevronRight size={14} /></button></div>
        {scans.isPending ? <Loading /> : scans.error ? <Failure error={scans.error} /> : scans.data.items.length === 0 ? <Empty text="No scans have been submitted." /> : <ScanTable items={scans.data.items} />}
      </article>
      <article className="panel table-panel"><div className="panel-head"><div><p className="eyebrow">TRIAGE QUEUE</p><h2>Findings</h2></div><button className="link" onClick={() => navigate("findings")}>View all <ChevronRight size={14} /></button></div>
        {scopedFindings.isPending ? <Loading /> : scopedFindings.error ? <Failure error={scopedFindings.error} /> : (triage ?? scopedFindings.data.items).slice(0, 6).length === 0 ? <Empty text={scoped ? "No findings for this scan." : "No findings are stored."} /> : <FindingTable items={(triage ?? scopedFindings.data.items).slice(0, 6)} />}
      </article>
    </section>
  </>;
}

type AuthMode = "none" | "form" | "json" | "cookie";

function parseJsonObject(raw: string, label: string): Record<string, string> {
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error(`${label} must be valid JSON.`); }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed) || !Object.keys(parsed).length) {
    throw new Error(`${label} must be a non-empty JSON object.`);
  }
  return parsed as Record<string, string>;
}

function NewScanView({ onCreated }: { onCreated: () => void }) {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("fast");
  const [authMode, setAuthMode] = useState<AuthMode>("none");
  // Manual headers / cookie.
  const [auth, setAuth] = useState("");
  // Generic login (form + json) config.
  const [loginUrl, setLoginUrl] = useState("");
  const [formFields, setFormFields] = useState('{"username": "", "password": ""}');
  const [jsonBody, setJsonBody] = useState('{"email": "", "password": ""}');
  const [tokenSource, setTokenSource] = useState<"json_path" | "header">("json_path");
  const [tokenLocator, setTokenLocator] = useState("token");
  const [injectHeader, setInjectHeader] = useState("Authorization");
  const [injectTemplate, setInjectTemplate] = useState("Bearer {token}");
  const [checkUrl, setCheckUrl] = useState("");
  const [successContains, setSuccessContains] = useState("");
  const queryClient = useQueryClient();
  const create = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { target, profile };
      const check: Record<string, string> = {};
      if (checkUrl.trim()) check.check_url = checkUrl.trim();
      if (successContains.trim()) check.success_contains = successContains.trim();
      const hasCheck = Object.keys(check).length > 0;
      if (authMode === "form") {
        const auth_: Record<string, unknown> = {
          method: "form",
          form: { login_url: loginUrl.trim(), fields: parseJsonObject(formFields, "Form fields") },
        };
        if (hasCheck) auth_.check = check;
        body.auth = auth_;
      } else if (authMode === "json") {
        const jsonLogin: Record<string, unknown> = {
          login_url: loginUrl.trim(),
          json_body: parseJsonObject(jsonBody, "JSON body"),
          inject_header: injectHeader.trim() || "Authorization",
          inject_template: injectTemplate.trim() || "Bearer {token}",
        };
        if (!tokenLocator.trim()) throw new Error("A token location is required for JSON login.");
        if (tokenSource === "json_path") jsonLogin.token_json_path = tokenLocator.trim();
        else jsonLogin.token_response_header = tokenLocator.trim();
        const auth_: Record<string, unknown> = { method: "json", json_login: jsonLogin };
        if (hasCheck) auth_.check = check;
        body.auth = auth_;
      } else if (authMode === "cookie") {
        const raw = auth.trim();
        if (raw) {
          const headers = raw.startsWith("{") ? parseJsonObject(raw, "Auth headers") : { Cookie: raw };
          body.custom_headers = headers;
        }
      }
      return api<{ job_id: string; status: string }>("api/v1/discovery/scans", { method: "POST", body: JSON.stringify(body) });
    },
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["scans"] }); await queryClient.invalidateQueries({ queryKey: ["overview"] }); onCreated(); },
  });
  const generic = authMode === "form" || authMode === "json";
  return <>
    <PageTitle eyebrow="DISCOVERY / AUTHORISED TARGET" title="New Scan" detail="The backend scope allow-list is enforced before work is queued." />
    <section className="panel form-panel">
      <form onSubmit={(event) => { event.preventDefault(); create.mutate(); }}>
        <label htmlFor="target">Target URL or host</label>
        <input id="target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://authorized.example" required maxLength={2048} />
        <fieldset><legend>Scan profile</legend><div className="profile-grid">
          {[["fast", "Focused coverage · lower runtime"], ["deep", "Extended enumeration · higher runtime"]].map(([id, detail]) => <label className={profile === id ? "selected" : ""} key={id}><input type="radio" name="profile" value={id} checked={profile === id} onChange={() => setProfile(id)} /><strong>{id.toUpperCase()}</strong><span>{detail}</span></label>)}
        </div></fieldset>
        <label htmlFor="authmode">Authentication <span className="muted">— for login-gated targets</span></label>
        <select id="authmode" value={authMode} onChange={(event) => setAuthMode(event.target.value as AuthMode)}>
          <option value="none">None — unauthenticated crawl</option>
          <option value="form">Form login — the scanner logs in (cookie session)</option>
          <option value="json">API / JSON login — the scanner logs in (token)</option>
          <option value="cookie">Manual cookie / headers…</option>
        </select>
        {generic && <div className="auth-config">
          <label htmlFor="loginurl">Login URL</label>
          <input id="loginurl" value={loginUrl} onChange={(event) => setLoginUrl(event.target.value)} placeholder="https://authorized.example/login" required maxLength={2048} />
          {authMode === "form" && <>
            <label htmlFor="formfields">Form fields <span className="muted">— JSON; hidden CSRF tokens are added automatically</span></label>
            <textarea id="formfields" value={formFields} onChange={(event) => setFormFields(event.target.value)} rows={3} placeholder={'{"username": "user", "password": "secret"}'} />
          </>}
          {authMode === "json" && <>
            <label htmlFor="jsonbody">JSON body</label>
            <textarea id="jsonbody" value={jsonBody} onChange={(event) => setJsonBody(event.target.value)} rows={3} placeholder={'{"email": "user@example.com", "password": "secret"}'} />
            <label htmlFor="tokensrc">Token location</label>
            <div className="inline-fields">
              <select id="tokensrc" value={tokenSource} onChange={(event) => setTokenSource(event.target.value as "json_path" | "header")}>
                <option value="json_path">Response JSON path</option>
                <option value="header">Response header</option>
              </select>
              <input value={tokenLocator} onChange={(event) => setTokenLocator(event.target.value)} placeholder={tokenSource === "json_path" ? "data.token" : "X-Auth-Token"} maxLength={256} />
            </div>
            <div className="inline-fields">
              <input value={injectHeader} onChange={(event) => setInjectHeader(event.target.value)} placeholder="Authorization" maxLength={128} aria-label="Inject header name" />
              <input value={injectTemplate} onChange={(event) => setInjectTemplate(event.target.value)} placeholder="Bearer {token}" maxLength={256} aria-label="Inject header template" />
            </div>
          </>}
          <label htmlFor="checkurl">Session check URL <span className="muted">— optional; defaults to the target</span></label>
          <input id="checkurl" value={checkUrl} onChange={(event) => setCheckUrl(event.target.value)} placeholder="https://authorized.example/account" maxLength={2048} />
          <label htmlFor="successmark">Logged-in marker <span className="muted">— optional text proving the session works</span></label>
          <input id="successmark" value={successContains} onChange={(event) => setSuccessContains(event.target.value)} placeholder="Sign out" maxLength={512} />
        </div>}
        {authMode === "cookie" && <textarea id="auth" value={auth} onChange={(event) => setAuth(event.target.value)} rows={2} maxLength={8192} placeholder={'Session cookie, e.g. session=abc123 — or a JSON headers object {"Cookie":"…","X-Api-Key":"…"}'} />}
        <div className="scope-note"><ShieldCheck size={17} /><div><strong>Scope enforcement active</strong><span>Out-of-scope targets are rejected, and the login flow itself is scope-checked on every hop. Scans remain non-destructive and honor the global kill switch. Credentials are used only to log in; the derived session is encrypted at rest and expires automatically.</span></div></div>
        {create.error && <Failure error={create.error} />}
        <button className="button primary" disabled={create.isPending}><Play size={15} />{create.isPending ? "Submitting…" : "Start scan"}</button>
      </form>
    </section>
  </>;
}

function ScansView({ search, onRemediate }: { search: string; onRemediate: (id: string) => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const scans = useQuery({
    queryKey: ["scans", search], queryFn: () => api<Page<Scan>>(`api/v1/console/scans?limit=100&search=${encodeURIComponent(search)}`),
    refetchInterval: (query) => query.state.data?.items.some((item) => activeStates.has(item.status)) ? 3_000 : 10_000,
  });
  return <>
    <PageTitle eyebrow="DISCOVERY / JOB LEDGER" title="Scans" detail="Durable scan jobs and their real event streams." />
    <section className="panel table-panel">
      {scans.isPending ? <Loading /> : scans.error ? <Failure error={scans.error} /> : scans.data.items.length === 0 ? <Empty text="No scans match the current search." /> : <ScanTable items={scans.data.items} select={setSelected} />}
    </section>
    {selected && <ScanDrawer id={selected} close={() => setSelected(null)} onRemediate={onRemediate} />}
  </>;
}

function ScanTable({ items, select }: { items: Scan[]; select?: (id: string) => void }) {
  return <div className="table-scroll"><table><thead><tr><th>Target</th><th>Profile</th><th>Status</th><th>Findings</th><th>Events</th><th>Created</th></tr></thead><tbody>{items.map((scan) => <tr key={scan.id} tabIndex={select ? 0 : undefined} onClick={() => select?.(scan.id)} onKeyDown={(event) => { if (event.key === "Enter") select?.(scan.id); }}><td><strong className="mono">{scan.target}</strong><small>{scan.id.slice(0, 12)}</small></td><td className="mono">{scan.profile}</td><td><Status value={scan.status} /></td><td className="mono">{scan.finding_count}</td><td className="mono">{scan.event_count}</td><td>{formatDate(scan.created_at)}</td></tr>)}</tbody></table></div>;
}

function ScanDrawer({ id, close, onRemediate }: { id: string; close: () => void; onRemediate: (id: string) => void }) {
  const queryClient = useQueryClient();
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const status = useQuery({ queryKey: ["scan", id], queryFn: () => api<Scan>(`api/v1/discovery/scans/${id}`), refetchInterval: (query) => activeStates.has(query.state.data?.status ?? "") ? 2_500 : false });
  const results = useQuery({ queryKey: ["scan-results", id], queryFn: () => api<ScanResults>(`api/v1/discovery/scans/${id}/results`), refetchInterval: 5_000 });
  const cancel = useMutation({ mutationFn: () => api<{ cancel_requested: boolean }>(`api/v1/discovery/scans/${id}/cancel`, { method: "PATCH" }), onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan", id] }) });
  useEffect(() => {
    const source = new EventSource(`/api/events/scan/${id}`);
    source.onmessage = (message) => {
      const next = JSON.parse(message.data) as ScanEvent;
      setEvents((current) => current.some((item) => item.seq === next.seq) ? current : [...current, next].sort((a, b) => a.seq - b.seq));
    };
    return () => source.close();
  }, [id]);
  const phases = useMemo(() => {
    const map = new Map<string, string>();
    for (const event of events) {
      const stage = typeof event.data.stage === "string" ? event.data.stage : null;
      if (stage) map.set(stage, event.event.includes("complete") ? "complete" : event.event.includes("start") ? "running" : (map.get(stage) ?? "pending"));
    }
    return [...map.entries()];
  }, [events]);
  return <Drawer title="Scan detail" subtitle={id} close={close}>
    {status.isPending ? <Loading /> : status.error ? <Failure error={status.error} /> : <>
      <div className="drawer-summary"><div><span>TARGET</span><strong>{status.data.target}</strong></div><div><span>STATUS</span><Status value={status.data.status} /></div><div><span>ATTEMPT</span><strong>{status.data.attempt_count}</strong></div></div>
      {activeStates.has(status.data.status) && <button className="button danger" disabled={cancel.isPending} onClick={() => cancel.mutate()}><CircleStop size={15} /> Cancel scan</button>}
      {status.data.status === "completed" && <button className="button primary" onClick={() => { close(); onRemediate(id); }}><WandSparkles size={15} /> Generate remediation report</button>}
    </>}
    <h3>Phase progress</h3>
    {phases.length === 0 ? <Empty text="No phase events received yet." /> : <div className="phase-rail">{phases.map(([phase, state], index) => <div key={phase} className={state}><b>{index + 1}</b><span>{phase}</span><i /></div>)}</div>}
    <h3>Coverage</h3><JsonBlock value={results.data?.coverage ?? null} />
    <h3>Durable event ledger</h3><div className="event-log">{events.length === 0 ? <span>Waiting for events…</span> : events.slice().reverse().map((event) => <div key={event.seq}><time>{event.seq.toString().padStart(3, "0")}</time><strong>{event.event}</strong><code>{JSON.stringify(event.data)}</code></div>)}</div>
  </Drawer>;
}

function FindingsView({ search, scanRunId, onRemediate }: { search: string; scanRunId: string; onRemediate: (id: string) => void }) {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const findings = useQuery({
    queryKey: ["findings", search, status, severity, scanRunId],
    queryFn: () => api<Page<Finding>>(`api/v1/console/findings?limit=500&search=${encodeURIComponent(search)}&status=${encodeURIComponent(status)}&severity=${encodeURIComponent(severity)}&scan_run_id=${encodeURIComponent(scanRunId)}`),
    refetchInterval: 5_000,
  });
  return <>
    <PageTitle eyebrow="VALIDATION / TRIAGE" title="Findings" detail={scanRunId ? "Findings for the selected scan only." : "Deduplicated findings across all scans."} />
    <div className="filters"><select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by status"><option value="">All verdicts</option><option value="unvalidated">Unvalidated</option><option value="validated">Validated</option><option value="false_positive">False positive</option><option value="inconclusive">Inconclusive</option><option value="unverifiable_safely">Unverifiable safely</option></select><select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter by severity"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></div>
    <section className="panel table-panel">{findings.isPending ? <Loading /> : findings.error ? <Failure error={findings.error} /> : findings.data.items.length === 0 ? <Empty text="No findings match these filters." /> : <FindingTable items={findings.data.items} select={setSelected} />}</section>
    {selected && <FindingDrawer finding={selected} close={() => setSelected(null)} onRemediate={onRemediate} />}
  </>;
}

function FindingTable({ items, select }: { items: Finding[]; select?: (finding: Finding) => void }) {
  return <div className="table-scroll"><table><thead><tr><th>Finding</th><th>Severity</th><th>Verdict</th><th>Confidence</th><th>Asset</th><th>Evidence</th></tr></thead><tbody>{items.map((finding) => <tr key={finding.id} tabIndex={select ? 0 : undefined} onClick={() => select?.(finding)} onKeyDown={(event) => { if (event.key === "Enter") select?.(finding); }}><td><strong>{finding.vuln_class ?? finding.vuln_class_candidate}</strong><small className="mono">{finding.endpoint ?? finding.id}</small></td><td><Severity value={finding.severity} /></td><td><Status value={finding.status} /></td><td className="mono">{pct(finding.confidence ?? finding.discovery_confidence)}</td><td><span>{finding.hostname}</span><small>{finding.asset_id.slice(0, 10)}</small></td><td className="mono">{finding.evidence_id ? finding.evidence_id.slice(0, 8) : "—"}</td></tr>)}</tbody></table></div>;
}

function FindingDrawer({ finding, close, onRemediate }: { finding: Finding; close: () => void; onRemediate: (id: string) => void }) {
  const queryClient = useQueryClient();
  const detail = useQuery({ queryKey: ["finding", finding.id], queryFn: () => api<ValidatedFinding>(`api/v1/validation/findings/${finding.id}`), refetchInterval: 5_000 });
  const evidence = useQuery({ queryKey: ["evidence", finding.evidence_id], queryFn: () => api<Evidence>(`api/v1/console/evidence/${finding.evidence_id}`), enabled: Boolean(finding.evidence_id) });
  const validate = useMutation({ mutationFn: () => api<{ job_id: string }>(`api/v1/validation/findings/${finding.id}`, { method: "POST" }), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["finding", finding.id] }); await queryClient.invalidateQueries({ queryKey: ["findings"] }); } });
  return <Drawer title={finding.vuln_class ?? finding.vuln_class_candidate} subtitle={finding.id} close={close}>
    <div className="drawer-summary"><div><span>SEVERITY</span><Severity value={finding.severity} /></div><div><span>VERDICT</span><Status value={detail.data?.status ?? finding.status} /></div><div><span>CONFIDENCE</span><strong>{pct(detail.data?.confidence ?? finding.confidence)}</strong></div></div>
    <dl className="detail-list"><div><dt>Asset</dt><dd>{finding.hostname}</dd></div><div><dt>Endpoint</dt><dd>{finding.endpoint ?? "—"}</dd></div><div><dt>Parameter</dt><dd>{finding.param ?? "—"}</dd></div><div><dt>CVSS</dt><dd>{finding.cvss_vector ?? "—"}</dd></div><div><dt>EPSS</dt><dd>{pct(finding.epss)}</dd></div><div><dt>Source</dt><dd>{finding.source_tool} · {finding.generated_by}</dd></div></dl>
    {finding.mapping_status === "mapped" && finding.status === "unvalidated" && <button className="button primary" onClick={() => validate.mutate()} disabled={validate.isPending}><ShieldCheck size={15} />{validate.isPending ? "Queueing…" : "Validate safely"}</button>}
    {(detail.data?.status ?? finding.status) === "validated" && <button className="button primary" onClick={() => { close(); onRemediate(finding.id); }}><WandSparkles size={15} /> Generate AI remediation</button>}
    {validate.error && <Failure error={validate.error} />}
    <h3>Observed capability transition</h3><div className="capability-row"><code>{detail.data?.observed_requires.join(" + ") || "network_reach"}</code><ChevronRight size={16} /><code>{detail.data?.observed_grants.join(" + ") || "not proven"}</code></div>
    <h3>Evidence and explainability</h3>
    {!finding.evidence_id ? <Empty text="No validation evidence is attached yet." /> : evidence.isPending ? <Loading /> : evidence.error ? <Failure error={evidence.error} /> : <EvidenceView evidence={evidence.data} />}
  </Drawer>;
}

function EvidenceView({ evidence }: { evidence: Evidence }) {
  return <div className="evidence"><div className="evidence-meta"><span><b>ORACLE</b>{evidence.oracle ?? "—"}</span><span><b>VERDICT</b>{evidence.expected_status ?? "—"}</span><span><b>CONFIDENCE</b>{pct(evidence.confidence)}</span><span><b>SEED</b>{evidence.seed} · reproducible</span><span><b>PROVENANCE</b>{evidence.generated_by}</span></div>{evidence.redacted_request_excerpt && <pre>{evidence.redacted_request_excerpt}</pre>}<JsonBlock value={evidence.manifest} /></div>;
}

// Safe object access over the loosely-typed summary payload.
function obj(value: unknown): Record<string, Json> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, Json>) : {};
}
function arr(value: unknown): Record<string, Json>[] {
  return Array.isArray(value) ? (value as Record<string, Json>[]) : [];
}
function pctText(v: unknown, digits = 1): string {
  return typeof v === "number" ? `${(v * 100).toFixed(digits)}%` : "—";
}
function chokeLabel(raw: unknown): string {
  const s = String(raw ?? "");
  const m = s.match(/^(\w[\w-]*)\s+(?:GET|POST|PUT|PATCH|DELETE)\s+https?:\/\/[^/]+(\/[^?\s]*)/i);
  return m ? `${m[1]} · ${m[2]}` : s;
}
// Best-effort target label for the graph export header, read from the graph itself.
function graphTarget(nodes: Array<{ data?: Record<string, unknown> }>): string {
  for (const n of nodes) { const h = n.data?.hostname; if (typeof h === "string" && h) return h; }
  for (const n of nodes) { const id = String(n.data?.id ?? ""); const m = id.match(/^([a-z0-9.-]+):/i); if (m) return m[1]; }
  return "target";
}

function GraphView({ scanRunId }: { scanRunId: string }) {
  const [overlays, setOverlays] = useState({ probability: true, cut: false, dominators: false, modal: true, provenance: false });
  const [evidenceId, setEvidenceId] = useState<string | null>(null);
  const [selectedPatches, setSelectedPatches] = useState<string[]>([]);
  const [budgetHours, setBudgetHours] = useState(8);
  const scope = scanRunId ? `scan_run_id=${encodeURIComponent(scanRunId)}` : "";
  const graph = useQuery({ queryKey: ["graph", "cytoscape", scanRunId], queryFn: () => api<CytoscapePayload>(`api/v1/graph/cytoscape?${scope}`), refetchInterval: 20_000 });
  const analysis = useQuery({ queryKey: ["graph", "analysis", budgetHours, scanRunId], queryFn: () => api<GraphAnalysis>(`api/v1/graph/analyze?trials=6400&seed=1337&budget_hours=${budgetHours}&${scope}`), refetchInterval: 20_000 });
  const priority = useQuery({ queryKey: ["graph", "priority", scanRunId], queryFn: () => api<PriorityPayload>(`api/v1/graph/priority?top=20&${scope}`), refetchInterval: 20_000 });
  const evidence = useQuery({ queryKey: ["evidence", evidenceId], queryFn: () => api<Evidence>(`api/v1/console/evidence/${evidenceId}`), enabled: Boolean(evidenceId) });
  const recompute = useMutation({ mutationFn: () => api<Record<string, Json>>(`api/v1/graph/recompute?${scope}`, { method: "POST", body: JSON.stringify({ patched: selectedPatches, trials: 6400, seed: 1337 }) }) });
  const [graphReport, setGraphReport] = useState("");
  const reportMut = useMutation({ mutationFn: () => api<{ report_markdown: string }>(`api/v1/console/remediation/graph-report?scan_run_id=${encodeURIComponent(scanRunId)}`, { method: "POST" }), onSuccess: (d) => setGraphReport(d.report_markdown) });
  const [exporting, setExporting] = useState(false);
  const queryClient = useQueryClient();
  const assets = useQuery({ queryKey: ["graph-assets"], queryFn: () => api<{ items: GraphAsset[] }>("api/v1/graph/assets"), refetchInterval: 30_000 });
  const patchAsset = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<GraphAsset> }) => api<GraphAsset>(`api/v1/graph/assets/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["graph"] }); await queryClient.invalidateQueries({ queryKey: ["graph-assets"] }); },
  });
  // A simulated patch set belongs to one scan's graph; clear it when scope changes.
  useEffect(() => { setSelectedPatches([]); recompute.reset(); }, [scanRunId]); // eslint-disable-line react-hooks/exhaustive-deps
  const toggle = (key: keyof typeof overlays) => setOverlays((current) => ({ ...current, [key]: !current[key] }));
  const togglePatch = (id: string) => setSelectedPatches((c) => c.includes(id) ? c.filter((x) => x !== id) : [...c, id]);

  const summary = analysis.data?.summary ?? {};
  const diag = obj(summary.diagnosis);
  const answerable = diag.answerable === true;
  const diagnosis = String(diag.status ?? "analyzing");
  const jewelProb = Object.values(obj(summary.jewel_probability)).map(obj);
  const worstJewel = jewelProb.reduce((a, b) => (Number(b.p ?? 0) > Number(a.p ?? -1) ? b : a), {} as Record<string, Json>);
  const jewelPct = typeof worstJewel.p === "number" ? worstJewel.p : null;
  const prov = obj(summary.provenance);
  const derived = typeof prov.derived_fraction === "number" ? prov.derived_fraction : null;
  const assumed = typeof prov.assumed_fraction === "number" ? prov.assumed_fraction : (derived !== null ? 1 - derived : null);
  const chokes = arr(summary.top_chokepoints);
  const cut = obj(summary.cut);
  const budgetPlan = obj(summary.budget_plan);
  const picks = arr(budgetPlan.picks);
  const cutVulns = Array.isArray(cut.vulns) ? (cut.vulns as string[]) : [];
  const retest = recompute.data;
  const jewelDelta = retest ? Object.values(obj(retest.jewel_delta)).map(obj)[0] : undefined;

  const doExport = async () => {
    if (!graph.data) return;
    setExporting(true);
    try {
      const nodes = graph.data.elements.nodes;
      const edges = graph.data.elements.edges;
      const metrics: GraphExportMetrics = {
        target: graphTarget(nodes as Array<{ data?: Record<string, unknown> }>),
        scope: scanRunId ? "this scan" : "all scans",
        jewelPct: jewelPct !== null ? pctText(jewelPct) : "—",
        jewelCi: pctText(worstJewel.ci ?? 0),
        derivedPct: derived !== null ? pctText(derived, 0) : "—",
        assumedPct: assumed !== null ? pctText(assumed, 0) : "—",
        totalEdges: String(prov.total_edges ?? "—"),
        cutSize: String(cut.size ?? cutVulns.length ?? "—"),
        cutCost: String(cut.cost ?? "—"),
        mcTrials: typeof summary.mc_trials === "number" ? String(summary.mc_trials) : "—",
        seed: String(typeof analysis.data?.seed === "number" ? analysis.data.seed : 1337),
        chokepoints: chokes.slice(0, 5).map((c) => ({
          label: chokeLabel(c.label),
          detail: `gates ${Array.isArray(c.dominated_jewels) ? (c.dominated_jewels as unknown[]).length : 0} jewel(s) · ${String(c.patch_hours ?? "—")}h`,
        })),
      };
      await exportInteractiveGraph([...nodes, ...edges], overlays, metrics);
    } finally {
      setExporting(false);
    }
  };

  return <>
    <PageTitle eyebrow="CORRELATION / REPRODUCIBLE" title="Attack Graph" detail={`${scanRunId ? "This scan only" : "All scans (unified)"} · evidence-backed reachability${typeof summary.mc_trials === "number" ? ` · ${summary.mc_trials} Monte-Carlo trials · seed ${typeof analysis.data?.seed === "number" ? analysis.data.seed : 1337}` : ""}`} action={<div className="row-actions">
      <button className="button" disabled={!graph.data || exporting} title="Download a standalone interactive HTML of this graph (offline, zoomable)" onClick={doExport}><Download size={14} /> {exporting ? "Exporting…" : "Export HTML"}</button>
      <button className="button" disabled={!scanRunId || reportMut.isPending} title={scanRunId ? "Standalone report on this scan's graph" : "Select a scan to report on"} onClick={() => reportMut.mutate()}><FileSearch size={14} /> {reportMut.isPending ? "Building…" : "Graph report"}</button>
      <button className="button" onClick={() => { void graph.refetch(); void analysis.refetch(); void priority.refetch(); }}><RefreshCw size={14} /> Recompute graph</button>
    </div>} />
    <div className="graph-layout"><section className="panel graph-panel">
      <div className="overlay-bar">{(["probability", "modal", "cut", "dominators", "provenance"] as const).map((key) => <button key={key} className={overlays[key] ? "on" : ""} onClick={() => toggle(key)}>{key === "probability" ? "heatmap" : key === "cut" ? "min-cut" : key.replaceAll("_", " ")}</button>)}</div>
      {graph.isPending ? <Loading label="Building attack graph" /> : graph.error ? <Failure error={graph.error} /> : <AttackGraph graph={graph.data} {...overlays} onEvidence={setEvidenceId} />}
      <div className="graph-status"><span>SNAPSHOT <b>{graph.data?.snapshot_id.slice(0, 12) ?? "—"}</b></span><span>{graph.data?.cached ? "CACHED" : "FRESH"}</span><span>HOVER → SCORECARD</span><span>CLICK → EVIDENCE</span></div>
    </section><aside className="graph-side">
      <section className="panel">
        <p className="eyebrow">CROWN JEWEL COMPROMISE PROBABILITY</p>
        {answerable ? <div className="jewel-metric">
          <div className={`big ${jewelDelta ? "safe" : ""}`}>{jewelDelta ? pctText(jewelDelta.after) : pctText(jewelPct)}</div>
          <small>{jewelDelta ? `after ${selectedPatches.length} simulated patch${selectedPatches.length === 1 ? "" : "es"} · ±${pctText(jewelDelta.after_ci)}` : `bounded risk · ±${pctText(worstJewel.ci ?? 0)} · ${jewelProb.length} jewel${jewelProb.length === 1 ? "" : "s"}`}</small>
          {jewelDelta && <div className="retest"><span className="from">{pctText(jewelDelta.before)}</span><span className="arrow">→</span><span className="to">{pctText(jewelDelta.after)}</span><span className="arrow">·</span><span>{String(retest?.paths_eliminated ?? 0)} paths cut</span></div>}
        </div> : <><h2 style={{ marginTop: 6 }}>{diagnosis.replaceAll("_", " ")}</h2><Empty text={String((arr(diag.problems)[0] ?? {}).fix ?? "Mark a business-critical asset as a crown jewel to compute risk.")} /></>}
      </section>

      <section className="panel">
        <p className="eyebrow">ASSET CRITICALITY</p>
        <div className="crit-slider">{(assets.data?.items ?? []).length === 0 ? <Empty text="No assets in the graph yet." /> : (assets.data?.items ?? []).map((a) => (
          <div className="row" key={a.id}>
            <label style={{ display: "flex", gap: 7, alignItems: "center", minWidth: 0, cursor: "pointer" }}>
              <input type="checkbox" checked={a.is_crown_jewel} onChange={() => patchAsset.mutate({ id: a.id, body: { is_crown_jewel: !a.is_crown_jewel } })} />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.hostname}{a.is_crown_jewel && <span className="tag ok" style={{ marginLeft: 6 }}>JEWEL</span>}</span>
            </label>
            <input type="range" min={1} max={5} value={a.criticality} title={`criticality ${a.criticality}`} style={{ width: 84, accentColor: "#eab308" }} onChange={(e) => patchAsset.mutate({ id: a.id, body: { criticality: Number(e.target.value) } })} />
          </div>
        ))}</div>
      </section>

      <section className="panel">
        <p className="eyebrow">DATA PROVENANCE · VERIFIED GRAPH ACCURACY</p>
        <h2>{derived !== null ? pctText(derived, 0) : "—"}</h2>
        {derived !== null && <><div className="prov-bar"><i className="derived" style={{ width: `${derived * 100}%` }} /><i className="assumed" style={{ width: `${(assumed ?? 0) * 100}%` }} /></div>
        <dl className="compact-dl"><div><dt>Evidence / observed</dt><dd>{pctText(derived, 0)}</dd></div><div><dt>Assumed (blind spots)</dt><dd style={{ color: "#eab308" }}>{pctText(assumed ?? 0, 0)}</dd></div><div><dt>Total edges</dt><dd>{String(prov.total_edges ?? "—")}</dd></div></dl></>}
      </section>

      {answerable && <section className="panel">
        <p className="eyebrow">UNBYPASSABLE CHOKEPOINTS</p>
        <div className="choke-list">{chokes.length === 0 ? <Empty text="No single-point gate to the crown jewels." /> : chokes.slice(0, 3).map((c, i) => <div key={String(c.vuln_id ?? i)} className="choke"><span className="rank">#{i + 1}</span><span><strong>{chokeLabel(c.label)}</strong><small>gates {Array.isArray(c.dominated_jewels) ? (c.dominated_jewels as unknown[]).length : 0} jewel(s) · {String(c.patch_hours ?? "—")}h · impact {String(c.weighted_impact ?? "—")}</small></span></div>)}</div>
      </section>}

      {answerable && <section className="panel">
        <div className="panel-head"><div><p className="eyebrow">TIME-CONSTRAINED FIX LIST</p><h2>{budgetHours}h maintenance window</h2></div></div>
        <div className="budget-slider"><input type="range" min={1} max={40} value={budgetHours} onChange={(e) => setBudgetHours(Number(e.target.value))} /><div className="row"><span>1h</span><span>highest-ROI patches that fit</span><span>40h</span></div></div>
        {picks.length === 0 ? <Empty text="No patch fits this window." /> : <div className="choke-list">{picks.map((p, i) => <div key={String(p.vuln_id ?? i)} className="choke"><span className="rank">{String(p.patch_hours ?? "—")}h</span><span><strong>{chokeLabel(p.label)}</strong><small>{String(p.paths_killed ?? 0)} paths killed · {String(p.paths_killed_per_hour ?? "—")}/h</small></span></div>)}</div>}
      </section>}

      <section className="panel priorities">
        <div className="panel-head"><div><p className="eyebrow">BREAK THE CHAIN</p><h2>Patch &amp; simulate</h2></div>{cutVulns.length > 0 && <button className="button" onClick={() => setSelectedPatches(cutVulns)}>Lockdown ({cutVulns.length} · {String(cut.cost ?? "—")}h)</button>}</div>
        {priority.isPending ? <Loading /> : priority.error ? <Failure error={priority.error} /> : priority.data.items.length === 0 ? <Empty text="No reachable patchable path exists." /> : priority.data.items.slice(0, 12).map((item) => <label key={item.vuln_id}><input type="checkbox" checked={selectedPatches.includes(item.vuln_id)} onChange={() => togglePatch(item.vuln_id)} /><span><strong>{chokeLabel(item.label ?? item.vuln_id)}</strong><small>{item.in_min_cut ? <span className="tag cut">MIN-CUT</span> : ""} {item.patch_hours ?? "—"}h</small></span></label>)}
        <button className="button primary full" disabled={selectedPatches.length === 0 || recompute.isPending} onClick={() => recompute.mutate()} style={{ marginTop: 12 }}>{recompute.isPending ? "Simulating…" : `Simulate ${selectedPatches.length} patch${selectedPatches.length === 1 ? "" : "es"}`}</button>
        {selectedPatches.length > 0 && <button className="button full" onClick={() => { setSelectedPatches([]); recompute.reset(); }} style={{ marginTop: 6 }}>Clear</button>}
        {recompute.error && <Failure error={recompute.error} />}
        {retest && <div className="retest" style={{ marginTop: 12 }}><span>Risk</span><span className="from">{pctText(jewelDelta?.before)}</span><span className="arrow">→</span><span className="to">{pctText(jewelDelta?.after)}</span></div>}
      </section>
    </aside></div>
    {evidenceId && <Drawer title="Edge evidence" subtitle={evidenceId} close={() => setEvidenceId(null)}>{evidence.isPending ? <Loading /> : evidence.error ? <Failure error={evidence.error} /> : <EvidenceView evidence={evidence.data} />}</Drawer>}
    {reportMut.error && <Failure error={reportMut.error} />}
    {graphReport && <div className="zoom-backdrop"><ReportView report={graphReport} zoomed onClose={() => setGraphReport("")} /></div>}
  </>;
}

function AssetsView() {
  const queryClient = useQueryClient();
  const assets = useQuery({ queryKey: ["graph-assets"], queryFn: () => api<{ items: GraphAsset[] }>("api/v1/graph/assets"), refetchInterval: 10_000 });
  const update = useMutation({ mutationFn: ({ id, body }: { id: string; body: Partial<GraphAsset> }) => api<GraphAsset>(`api/v1/graph/assets/${id}`, { method: "PATCH", body: JSON.stringify(body) }), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["graph-assets"] }); await queryClient.invalidateQueries({ queryKey: ["graph"] }); } });
  return <><PageTitle eyebrow="TOPOLOGY / CLASSIFICATION" title="Assets" detail="Classify entry points, trust zones, criticality, and crown jewels." /><section className="panel table-panel">{assets.isPending ? <Loading /> : assets.error ? <Failure error={assets.error} /> : assets.data.items.length === 0 ? <Empty text="Discovery has not persisted any assets." /> : <div className="table-scroll"><table><thead><tr><th>Asset</th><th>Zone</th><th>Criticality</th><th>Entry point</th><th>Crown jewel</th></tr></thead><tbody>{assets.data.items.map((asset) => <tr key={asset.id}><td><strong>{asset.hostname}</strong><small className="mono">{asset.id.slice(0, 14)}</small></td><td><input className="cell-input" defaultValue={asset.zone} onBlur={(event) => { if (event.target.value !== asset.zone) update.mutate({ id: asset.id, body: { zone: event.target.value } }); }} /></td><td><select value={asset.criticality} onChange={(event) => update.mutate({ id: asset.id, body: { criticality: Number(event.target.value) } })}>{[1,2,3,4,5].map((value) => <option key={value}>{value}</option>)}</select></td><td><input type="checkbox" checked={asset.is_entry_point} onChange={() => update.mutate({ id: asset.id, body: { is_entry_point: !asset.is_entry_point } })} /></td><td><input type="checkbox" checked={asset.is_crown_jewel} onChange={() => update.mutate({ id: asset.id, body: { is_crown_jewel: !asset.is_crown_jewel } })} /></td></tr>)}</tbody></table></div>}</section>{update.error && <Failure error={update.error} />}</>;
}

type RemedMode = "scan" | "finding";

function ReportView({ report, onClose, onZoom, zoomed }: { report: string; onClose?: () => void; onZoom?: () => void; zoomed?: boolean }) {
  return <div className={zoomed ? "report-zoom" : "panel report-panel"}>
    <div className="panel-head"><div><p className="eyebrow">GENERATED REPORT</p><h2>Evidence-linked remediation & attack-graph report</h2></div>
      <div className="row-actions">
        <button className="button compact" onClick={() => navigator.clipboard.writeText(report)}>Copy</button>
        {onZoom && <button className="button compact" onClick={onZoom}>{zoomed ? "Exit" : "Zoom"}</button>}
        {onClose && <button className="button compact" onClick={onClose}><X size={14} /></button>}
      </div>
    </div>
    <div className="report-block"><SafeMarkdown>{report}</SafeMarkdown></div>
  </div>;
}

const AI_PROVIDER_STORAGE_KEY = "sentinalx.ai-provider";

function RemediationView({ initialFinding, initialScan, scanRunId }: { initialFinding: string; initialScan: string; scanRunId: string }) {
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState<AIProviderSettings>(defaultAIProvider);
  const [providerLoaded, setProviderLoaded] = useState(false);
  // Remember the last AI configuration so it never has to be retyped.
  // localStorage persists across reloads, tab close and browser restart (unlike
  // sessionStorage, which a tab close clears). Loading in an effect (not during
  // render) avoids any SSR/hydration mismatch.
  useEffect(() => {
    try { const raw = localStorage.getItem(AI_PROVIDER_STORAGE_KEY); if (raw) setProvider({ ...defaultAIProvider, ...JSON.parse(raw) }); } catch { /* ignore unavailable storage */ }
    setProviderLoaded(true);
  }, []);
  useEffect(() => {
    if (!providerLoaded) return;
    try { localStorage.setItem(AI_PROVIDER_STORAGE_KEY, JSON.stringify(provider)); } catch { /* ignore unavailable storage */ }
  }, [provider, providerLoaded]);
  const [mode, setMode] = useState<RemedMode>(initialFinding ? "finding" : "scan");
  const [findingId, setFindingId] = useState("");
  const [scanId, setScanId] = useState("");
  const [report, setReport] = useState("");
  const [zoom, setZoom] = useState(false);
  useEffect(() => { if (initialFinding) { setFindingId(initialFinding); setMode("finding"); } }, [initialFinding]);
  useEffect(() => { if (initialScan) { setScanId(initialScan); setMode("scan"); } }, [initialScan]);
  const findings = useQuery({ queryKey: ["remediation-findings", scanRunId], queryFn: () => api<Page<Finding>>(`api/v1/console/findings?status=validated&limit=500&scan_run_id=${encodeURIComponent(scanRunId)}`) });
  const scans = useQuery({ queryKey: ["remediation-scans"], queryFn: () => api<Page<Scan>>("api/v1/console/scans?status=completed&limit=100") });
  const actions = useQuery({ queryKey: ["remediation-actions"], queryFn: () => api<{ items: RemediationAction[] }>("api/v1/console/remediation/actions?limit=200"), refetchInterval: 10_000 });
  // Default the whole-scan report selector to the globally-scoped scan.
  useEffect(() => { if (!scanId && scanRunId) { const match = (scans.data?.items ?? []).find((s) => s.scan_run_id === scanRunId); if (match) setScanId(match.id); } }, [scans.data, scanRunId, scanId]);
  const generate = useMutation({
    mutationFn: () => api<RemediationAction>(`api/v1/console/remediation/findings/${findingId}/generate`, { method: "POST", body: JSON.stringify(provider) }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["remediation-actions"] }); },
  });
  const generateReport = useMutation({
    mutationFn: () => api<{ actions: RemediationAction[]; generation_errors: Array<{ group_key: string; finding_id: string; error: string }>; report_markdown: string }>(`api/v1/console/remediation/scans/${scanId}/generate`, { method: "POST", body: JSON.stringify(provider) }),
    onSuccess: async (data) => { setReport(data.report_markdown); await queryClient.invalidateQueries({ queryKey: ["remediation-actions"] }); },
  });
  const requestBusy = generate.isPending || generateReport.isPending;
  return <>
    <PageTitle eyebrow="REMEDIATE / VERIFY" title="AI Remediation & Retest" detail="Ground fixes in validated evidence, record operator application, then safely replay the original oracle." />
    <div className="remediation-layout">
      <div className="remediation-main">
        <section className="panel">
          <div className="mode-toggle" role="tablist">
            <button role="tab" aria-selected={mode === "scan"} className={mode === "scan" ? "on" : ""} onClick={() => setMode("scan")}><FileSearch size={15} /> Whole-scan report</button>
            <button role="tab" aria-selected={mode === "finding"} className={mode === "finding" ? "on" : ""} onClick={() => setMode("finding")}><WandSparkles size={15} /> Single vulnerability</button>
          </div>
          {mode === "scan" ? <div className="task-row">
            <select value={scanId} onChange={(event) => setScanId(event.target.value)}>
              <option value="">Select a completed scan…</option>
              {(scans.data?.items ?? []).map((scan) => <option key={scan.id} value={scan.id}>{scan.target} · {formatDate(scan.completed_at)}</option>)}
            </select>
            <button className="button primary" disabled={!scanId || requestBusy} onClick={() => generateReport.mutate()}><FileSearch size={15} />{generateReport.isPending ? "Building report…" : "Generate full report"}</button>
          </div> : <div className="task-row">
            <select value={findingId} onChange={(event) => setFindingId(event.target.value)}>
              <option value="">Select a validated finding…</option>
              {(findings.data?.items ?? []).map((finding) => <option key={finding.id} value={finding.id}>{finding.vuln_class ?? finding.vuln_class_candidate} · {finding.hostname} · {finding.param ?? "endpoint"}</option>)}
            </select>
            <button className="button primary" disabled={!findingId || requestBusy} onClick={() => generate.mutate()}><Sparkles size={15} />{generate.isPending ? "Consulting provider…" : "Generate remediation"}</button>
          </div>}
          <p className="muted" style={{ marginTop: 10 }}>{mode === "scan" ? "A full report covers every validated vulnerability in the scan plus a dedicated attack-graph section." : "Generates one evidence-grounded fix for the selected finding and adds it to the ledger below."}</p>
          {generate.error && <Failure error={generate.error} />}
          {generateReport.error && <Failure error={generateReport.error} />}
        </section>

        {report && !zoom && <ReportView report={report} onClose={() => setReport("")} onZoom={() => setZoom(true)} />}

        <section className="panel"><div className="panel-head"><div><p className="eyebrow">ACTION LEDGER</p><h2>Remediation lifecycle</h2></div><span className="tag">{actions.data?.items.length ?? 0} ACTIONS</span></div>
          {actions.isPending ? <Loading /> : actions.error ? <Failure error={actions.error} /> : actions.data.items.length === 0 ? <Empty text="Generate remediation for a validated finding to begin." /> : <div className="action-stack">{actions.data.items.map((action) => <RemediationCard key={action.id} action={action} />)}</div>}
        </section>
      </div>

      <aside className="remediation-aside">
        <section className="panel"><AIProviderConfig value={provider} onChange={setProvider} /></section>
      </aside>
    </div>
    {zoom && report && <div className="zoom-backdrop"><ReportView report={report} zoomed onZoom={() => setZoom(false)} onClose={() => { setZoom(false); }} /></div>}
  </>;
}

function RemediationCard({ action }: { action: RemediationAction }) {
  const queryClient = useQueryClient();
  const attempts = useQuery({ queryKey: ["retests", action.id], queryFn: () => api<{ items: RetestAttempt[] }>(`api/v1/console/remediation/actions/${action.id}/retests`) });
  const apply = useMutation({
    mutationFn: (applied: boolean) => api<RemediationAction>(`api/v1/console/remediation/actions/${action.id}/applied`, { method: "PATCH", body: JSON.stringify({ applied }) }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["remediation-actions"] }); },
  });
  const retest = useMutation({
    mutationFn: () => api<{ results: RetestAttempt[]; graph_snapshot_id: string }>(`api/v1/console/remediation/actions/${action.id}/retest`, { method: "POST" }),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["remediation-actions"] }),
        queryClient.invalidateQueries({ queryKey: ["retests", action.id] }),
        queryClient.invalidateQueries({ queryKey: ["findings"] }),
        queryClient.invalidateQueries({ queryKey: ["graph"] }),
        queryClient.invalidateQueries({ queryKey: ["overview"] }),
      ]);
    },
  });
  const httpStatus = action.generation_metadata?.http_status;
  return <article className="remediation-card">
    <header><div><span className="tag">{action.action_kind.replaceAll("_", " ")}</span><span className="tag ok">{action.generated_by.toUpperCase()}</span></div><Status value={action.status} /></header>
    <h3>{action.group_key}</h3><p className="root-cause">{action.root_cause}</p>
    <details><summary>Recommended remediation</summary><div className="recommendation"><SafeMarkdown>{action.recommendation}</SafeMarkdown></div>{action.code_diff && <pre className="json-block">{action.code_diff}</pre>}</details>
    <dl className="compact-dl"><div><dt>Findings covered</dt><dd>{action.finding_ids.length}<small>database-linked</small></dd></div><div><dt>Confidence</dt><dd>{pct(action.confidence)}<small>{action.generated_by === "ai" ? "evidence-bound" : "recorded"}</small></dd></div><div><dt>Provider request</dt><dd>{httpStatus ? `HTTP ${String(httpStatus)}` : action.generated_by}</dd></div></dl>
    <label className="applied-check"><input type="checkbox" checked={action.applied} disabled={action.status === "retested" || apply.isPending} onChange={(event) => apply.mutate(event.target.checked)} /><span>I applied this remediation to the target</span></label>
    <button className="button primary full" disabled={!action.applied || action.status !== "applied" || retest.isPending} onClick={() => retest.mutate()}><RefreshCw size={14} />{retest.isPending ? "Replaying safe oracle…" : "Retest vulnerability"}</button>
    {(apply.error || retest.error) && <Failure error={(apply.error ?? retest.error) as Error} />}
    {(attempts.data?.items ?? []).map((attempt) => <div className={`retest-result verdict-${attempt.verdict}`} key={attempt.id}><Status value={attempt.verdict} /><span>{attempt.before_status} → {attempt.after_status}</span><code>evidence {attempt.evidence_id.slice(0, 12)}</code></div>)}
  </article>;
}

interface Inventory {
  scans: number; active_scans: number; findings: number; validated: number;
  evidence: number; assets: number; remediation_actions: number; retests: number;
  graph_snapshots: number; scope_allowlist: string[];
  credential_encryption_enabled: boolean; offline_mode: boolean;
}

function SystemView() {
  const overview = useOverview();
  const queryClient = useQueryClient();
  const [confirmWipe, setConfirmWipe] = useState("");
  const inventory = useQuery({ queryKey: ["inventory"], queryFn: () => api<Inventory>("api/v1/console/inventory"), refetchInterval: 8_000 });
  const scans = useQuery({ queryKey: ["system-scans"], queryFn: () => api<Page<Scan>>("api/v1/console/scans?limit=100"), refetchInterval: 8_000 });
  const invalidateAll = () => queryClient.invalidateQueries();
  const engage = useMutation({ mutationFn: () => api<{ killswitch_engaged: boolean }>("api/v1/discovery/killswitch?reason=operator-console", { method: "POST" }), onSuccess: () => queryClient.invalidateQueries({ queryKey: ["overview"] }) });
  const resetKill = useMutation({ mutationFn: () => api<{ killswitch_engaged: boolean }>("api/v1/discovery/killswitch/reset", { method: "POST" }), onSuccess: () => queryClient.invalidateQueries({ queryKey: ["overview"] }) });
  const deleteScan = useMutation({ mutationFn: (runId: string) => api<Json>(`api/v1/console/scans/${runId}`, { method: "DELETE" }), onSuccess: invalidateAll });
  const clearReports = useMutation({ mutationFn: () => api<Json>("api/v1/console/remediation/actions", { method: "DELETE" }), onSuccess: invalidateAll });
  const wipe = useMutation({ mutationFn: () => api<Json>("api/v1/console/reset", { method: "POST" }), onSuccess: () => { setConfirmWipe(""); return invalidateAll(); } });
  const inv = inventory.data;
  const scanRows = (scans.data?.items ?? []).filter((s) => s.scan_run_id);
  return <>
    <PageTitle eyebrow="CONTROL PLANE" title="System" detail="Data inventory, reset controls, scope, and fail-closed runtime state." />

    <section className="panel"><div className="panel-head"><div><p className="eyebrow">DATA INVENTORY</p><h2>Stored across the shared pipeline</h2></div>{inventory.isFetching && <span className="tag">live</span>}</div>
      {inventory.isPending ? <Loading /> : inventory.error ? <Failure error={inventory.error} /> : inv && <div className="metrics-grid">
        <Metric label="SCANS" value={inv.scans} detail={`${inv.active_scans} active`} />
        <Metric label="FINDINGS" value={inv.findings} detail={`${inv.validated} validated`} />
        <Metric label="EVIDENCE" value={inv.evidence} detail="replayable artifacts" />
        <Metric label="ASSETS" value={inv.assets} detail="graph nodes" />
        <Metric label="REMEDIATIONS" value={inv.remediation_actions} detail={`${inv.retests} retests`} />
        <Metric label="GRAPH SNAPSHOTS" value={inv.graph_snapshots} detail="cached analyses" />
      </div>}
    </section>

    <section className="two-col">
      <article className="panel"><p className="eyebrow">SCOPE ALLOW-LIST</p><h2>Authorised targets</h2>
        <p className="muted">The only mandatory guardrail: active scanning is refused for anything not on this fail-closed list.</p>
        <div className="scope-chips">{(inv?.scope_allowlist ?? []).length === 0 ? <Empty text="Scope is empty — nothing is in scope." /> : (inv?.scope_allowlist ?? []).map((entry) => <code key={entry} className="scope-chip">{entry}</code>)}</div>
        <dl className="compact-dl"><div><dt>Credential encryption</dt><dd>{inv?.credential_encryption_enabled ? "enabled" : "disabled"}</dd></div><div><dt>Offline mode</dt><dd>{inv?.offline_mode ? "on" : "off"}</dd></div></dl>
      </article>
      <article className={`panel kill-panel ${overview.data?.killswitch.engaged ? "engaged" : ""}`}><OctagonX size={22} /><div><p className="eyebrow">GLOBAL KILL SWITCH</p><h2>{overview.data?.killswitch.engaged ? "ENGAGED" : "DISENGAGED"}</h2><span>{overview.data?.killswitch.reason ?? "Workers may execute authorised, non-destructive scans."}</span></div>{overview.data?.killswitch.engaged ? <button className="button" onClick={() => resetKill.mutate()} disabled={resetKill.isPending}>Admin reset</button> : <button className="button danger" onClick={() => engage.mutate()} disabled={engage.isPending}>Engage now</button>}</article>
    </section>

    <section className="panel"><div className="panel-head"><div><p className="eyebrow">DATA MANAGEMENT</p><h2>Delete a scan or reset everything</h2></div></div>
      <p className="muted">Deletes are permanent. Removing a scan clears its findings, evidence and graph contribution; findings still observed by another scan are kept.</p>
      <div className="table-scroll"><table><thead><tr><th>Target</th><th>Completed</th><th>Findings</th><th></th></tr></thead><tbody>
        {scanRows.length === 0 ? <tr><td colSpan={4}><Empty text="No scans stored." /></td></tr> : scanRows.map((s) => <tr key={s.id}>
          <td><strong className="mono">{s.target}</strong><small>{s.scan_run_id!.slice(0, 12)}</small></td>
          <td>{formatDate(s.completed_at ?? s.created_at)}</td>
          <td className="mono">{s.finding_count}</td>
          <td style={{ textAlign: "right" }}><button className="button danger compact" disabled={deleteScan.isPending} onClick={() => deleteScan.mutate(s.scan_run_id!)}><Trash2 size={13} /> Delete</button></td>
        </tr>)}
      </tbody></table></div>
      <div className="danger-zone">
        <div className="row"><div><strong>Clear remediation reports</strong><span className="muted">Remove all generated remediation actions and retests.</span></div><button className="button" disabled={clearReports.isPending} onClick={() => clearReports.mutate()}><Trash2 size={14} /> Clear reports</button></div>
        <div className="row"><div><strong>Wipe ALL scan data</strong><span className="muted">Delete every scan, finding, evidence, graph and report. Keeps the kill switch. Type <code>RESET</code> to confirm.</span></div><div style={{ display: "flex", gap: 8 }}><input value={confirmWipe} onChange={(e) => setConfirmWipe(e.target.value)} placeholder="RESET" style={{ width: 100 }} /><button className="button danger" disabled={confirmWipe !== "RESET" || wipe.isPending}  onClick={() => wipe.mutate()}><Database size={14} /> {wipe.isPending ? "Wiping…" : "Wipe all"}</button></div></div>
      </div>
      {(deleteScan.error || clearReports.error || wipe.error) && <Failure error={(deleteScan.error ?? clearReports.error ?? wipe.error) as Error} />}
    </section>

    <RuntimeSettingsPanel />

    <section className="panel"><p className="eyebrow">RUNTIME</p><h2>Shared pipeline</h2><div className="pipeline"><span>DISCOVER</span><i /><span>VALIDATE</span><i /><span>GRAPH</span></div><p className="muted">One PostgreSQL state boundary. Workers communicate through durable jobs and evidence records.</p></section>
    {(engage.error || resetKill.error) && <Failure error={(engage.error ?? resetKill.error) as Error} />}
  </>;
}

type SettingRow = {
  key: string; section: string; label: string; help: string; kind: string;
  minimum: number | null; maximum: number | null; advanced: boolean; warning: string;
  default: string | number; value: string | number; overridden: boolean;
};

function RuntimeSettingsPanel() {
  const queryClient = useQueryClient();
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [showAdvanced, setShowAdvanced] = useState(false);
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: () => api<{ settings: SettingRow[] }>("api/v1/console/settings") });
  const save = useMutation({
    mutationFn: (overrides: Record<string, string>) => api<{ settings: SettingRow[] }>("api/v1/console/settings", { method: "PATCH", body: JSON.stringify({ overrides }) }),
    onSuccess: () => { setEdits({}); return queryClient.invalidateQueries({ queryKey: ["settings"] }); },
  });
  const resetAll = useMutation({
    mutationFn: () => api<{ settings: SettingRow[] }>("api/v1/console/settings/reset", { method: "POST" }),
    onSuccess: () => { setEdits({}); return queryClient.invalidateQueries({ queryKey: ["settings"] }); },
  });
  const rows = settingsQuery.data?.settings ?? [];
  const sections = Array.from(new Set(rows.filter((r) => !r.advanced).map((r) => r.section)));
  const advancedRows = rows.filter((r) => r.advanced);
  const dirty = Object.entries(edits).filter(([key, v]) => {
    const row = rows.find((r) => r.key === key);
    return row && v !== String(row.value);
  });
  const onEdit = (key: string, v: string) => setEdits((prev) => ({ ...prev, [key]: v }));

  const field = (row: SettingRow) => {
    const current = edits[row.key] ?? String(row.value);
    return <div className="setting-row" key={row.key}>
      <div className="setting-label"><strong>{row.label}</strong><code>{row.key}</code>{row.help && <span className="muted">{row.help}</span>}{row.overridden && <span className="tag">overridden · default {String(row.default)}</span>}</div>
      <input value={current} onChange={(e) => onEdit(row.key, e.target.value)}
        inputMode={row.kind === "csv" ? "text" : "decimal"}
        placeholder={row.kind === "csv" ? "comma,separated,tags" : `${row.minimum ?? ""}–${row.maximum ?? ""}`} />
    </div>;
  };

  return <section className="panel"><div className="panel-head"><div><p className="eyebrow">CONTROL PLANE</p><h2>Runtime settings</h2></div>{settingsQuery.isFetching && <span className="tag">live</span>}</div>
    <p className="muted">Operator-tunable behaviour (ADR-0007). Changes apply to the next job with no restart. Effective value = override → environment → code default. Writes require the admin key.</p>
    {settingsQuery.isPending ? <Loading /> : settingsQuery.error ? <Failure error={settingsQuery.error} /> : <>
      {sections.map((section) => <div className="setting-group" key={section}>
        <h3>{section}</h3>
        {rows.filter((r) => r.section === section && !r.advanced).map(field)}
      </div>)}
      {advancedRows.length > 0 && <div className="setting-group advanced">
        <button type="button" className="link" onClick={() => setShowAdvanced((v) => !v)}><AlertTriangle size={14} /> Advanced / safety settings {showAdvanced ? "▲" : "▼"}</button>
        {showAdvanced && advancedRows.map((row) => <div key={row.key}>
          {row.warning && <div className="scope-note warn"><AlertTriangle size={16} /><span>{row.warning}</span></div>}
          {field(row)}
        </div>)}
      </div>}
      <div className="danger-zone"><div className="row">
        <div><strong>{dirty.length} change{dirty.length === 1 ? "" : "s"} pending</strong><span className="muted">Save writes overrides; reset returns every setting to its default.</span></div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="button" disabled={resetAll.isPending} onClick={() => resetAll.mutate()}><RefreshCw size={14} /> Reset all</button>
          <button className="button primary" disabled={save.isPending || dirty.length === 0} onClick={() => save.mutate(Object.fromEntries(dirty))}>{save.isPending ? "Saving…" : "Save changes"}</button>
        </div>
      </div></div>
      {(save.error || resetAll.error) && <Failure error={(save.error ?? resetAll.error) as Error} />}
    </>}
  </section>;
}

function Drawer({ title, subtitle, close, children }: { title: string; subtitle: string; close: () => void; children: React.ReactNode }) {
  return <div className="drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) close(); }}><aside className="drawer" role="dialog" aria-modal="true" aria-label={title}><header><div><p className="eyebrow">DETAIL</p><h2>{title}</h2><code>{subtitle}</code></div><button onClick={close} aria-label="Close"><X size={18} /></button></header><div className="drawer-body">{children}</div></aside></div>;
}

function JsonBlock({ value }: { value: Json | Record<string, Json> | null }) {
  return <pre className="json-block">{value == null ? "No structured data." : JSON.stringify(value, null, 2)}</pre>;
}

function Empty({ text }: { text: string }) {
  return <div className="empty"><TerminalSquare size={18} /><span>{text}</span></div>;
}

function CommandPalette({ search, setSearch, navigate, close }: { search: string; setSearch: (value: string) => void; navigate: (view: View) => void; close: () => void }) {
  const [query, setQuery] = useState(search);
  const filtered = views.filter((view) => view.label.toLowerCase().includes(query.toLowerCase()));
  return <div className="palette-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) close(); }}><section className="palette" role="dialog" aria-modal="true" aria-label="Command palette"><div className="palette-input"><Command size={17} /><input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Navigate or filter records…" /></div><div className="palette-results">{filtered.map(({ id, label, icon: Icon }) => <button key={id} onClick={() => { setSearch(query); navigate(id); }}><Icon size={16} /><span>{label}</span><kbd>↵</kbd></button>)}</div></section></div>;
}
