"use client";

import { useMutation } from "@tanstack/react-query";
import { Globe, Mail, Server, ShieldAlert, Network, Search } from "lucide-react";
import { useState } from "react";

import { api } from "@/lib/api";
import type { Json } from "@/lib/types";

type IntelResult = Record<string, Json>;

type TabId = "url" | "email" | "domain" | "ip" | "exposure";

const TABS: Array<{ id: TabId; label: string; icon: typeof Globe }> = [
  { id: "url", label: "URL / Phishing", icon: Globe },
  { id: "email", label: "Email", icon: Mail },
  { id: "domain", label: "Domain", icon: Server },
  { id: "ip", label: "IP Address", icon: Network },
  { id: "exposure", label: "Email Exposure", icon: ShieldAlert },
];

const PLACEHOLDER: Record<TabId, string> = {
  url: "http://secure-login.verify-account.example/",
  email: "Paste raw email source (headers + body)…",
  domain: "example.com",
  ip: "8.8.8.8",
  exposure: "someone@example.com",
};

function num(v: Json | undefined): number | null {
  return typeof v === "number" ? v : null;
}
function riskOf(d: IntelResult): { score: number | null; level: string } {
  const score = num(d.risk_score) ?? num(d.email_risk_score) ?? num(d.domain_risk_score) ?? num(d.ip_risk_score);
  const level = String(d.risk_level ?? d.email_risk_level ?? d.domain_risk_level ?? d.ip_risk_level ?? (d.error ? "ERROR" : "—"));
  return { score, level };
}
function levelClass(level: string): string {
  const l = level.toLowerCase();
  if (l === "critical") return "crit";
  if (l === "high") return "high";
  if (l === "medium") return "med";
  if (l === "low") return "low";
  return "na";
}

interface Signal { name?: string; description?: string; points?: number; triggered?: boolean }

function SignalList({ signals }: { signals: Json | undefined }) {
  const rows = Array.isArray(signals) ? (signals as Signal[]) : [];
  if (rows.length === 0) return null;
  const fired = rows.filter((s) => s.triggered);
  const rest = rows.filter((s) => !s.triggered);
  return (
    <div className="intel-signals">
      <p className="eyebrow">EXPLAINABLE SIGNALS · {fired.length}/{rows.length} triggered</p>
      {[...fired, ...rest].map((s, i) => (
        <div key={`${s.name}-${i}`} className={`sig ${s.triggered ? "on" : ""}`}>
          <span className="dot" />
          <span className="body"><strong>{s.name}</strong><small>{s.description}</small></span>
          <span className="pts">{s.triggered ? `+${s.points ?? 0}` : "0"}</span>
        </div>
      ))}
    </div>
  );
}

function Facts({ rows }: { rows: Array<[string, Json | undefined]> }) {
  const shown = rows.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0));
  if (shown.length === 0) return null;
  return <dl className="compact-dl intel-facts">{shown.map(([k, v]) => (
    <div key={k}><dt>{k}</dt><dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd></div>
  ))}</dl>;
}

function Details({ tab, data }: { tab: TabId; data: IntelResult }) {
  if (tab === "exposure") {
    const breaches = Array.isArray(data.breaches) ? (data.breaches as IntelResult[]) : [];
    return <>
      <Facts rows={[["Address", data.email], ["Source", data.source], ["Breaches", data.breach_count], ["Pastes", data.paste_count], ["Exposed data", data.exposed_categories]]} />
      {breaches.length > 0 && <div className="intel-breaches">{breaches.map((b, i) => (
        <div key={`${b.name}-${i}`} className="breach"><div className="bh"><strong>{String(b.name)}</strong><small>{String(b.year ?? "")} · {String(b.records ?? "?")} records{b.verified ? " · verified" : ""}</small></div>
          <div className="cats">{(Array.isArray(b.exposed_data) ? (b.exposed_data as string[]) : []).map((c) => <span key={c} className={`cat ${/password|financial|credit|bank/i.test(c) ? "hot" : ""}`}>{c}</span>)}</div></div>
      ))}</div>}
    </>;
  }
  const c = (data.components ?? {}) as IntelResult;
  const dns = (data.dns_info ?? data.intelligence ?? {}) as IntelResult;
  const tls = (data.tls_info ?? {}) as IntelResult;
  const rep = (data.reputation ?? {}) as IntelResult;
  const ch = (data.characteristics ?? {}) as IntelResult;
  const content = (data.content ?? {}) as IntelResult;
  if (tab === "url") return <Facts rows={[["Domain", c.registered_domain ?? c.domain], ["Scheme", c.scheme], ["IP(s)", dns.a_records ?? dns.ip_addresses], ["TLS", tls.valid === undefined ? undefined : (tls.valid ? "valid" : "invalid")], ["Reputation", rep.verdict ?? rep.classification], ["Redirects", (data.redirect_chain as IntelResult)?.hops]]} />;
  if (tab === "domain") return <Facts rows={[["Registrable", ch.registrable_domain ?? data.domain], ["Length", ch.length], ["Risky TLD", ch.has_risky_tld], ["A records", dns.a_records], ["TLS valid", tls.valid], ["Reputation", rep.verdict ?? rep.classification]]} />;
  if (tab === "ip") return <Facts rows={[["Target", data.target], ["Class", data.classification], ["Version", data.ip_version], ["Reverse DNS", data.reverse_dns], ["Reputation", rep.verdict ?? rep.classification]]} />;
  if (tab === "email") return <Facts rows={[["From", content.from_address ?? content.from_], ["Subject", content.subject], ["Reply-To", content.reply_to], ["Links", Array.isArray(content.links) ? (content.links as unknown[]).length : content.link_count]]} />;
  return null;
}

export function IntelView() {
  const [tab, setTab] = useState<TabId>("url");
  const [input, setInput] = useState("");
  const run = useMutation<IntelResult, Error, { tab: TabId; value: string }>({
    mutationFn: ({ tab, value }) => {
      const body = tab === "email" ? { raw_email: value } : tab === "exposure" ? { email: value.trim() } : tab === "domain" ? { domain: value.trim() } : tab === "ip" ? { ip: value.trim() } : { url: value.trim() };
      return api<IntelResult>(`api/v1/intel/${tab}`, { method: "POST", body: JSON.stringify(body) });
    },
  });
  const data = run.data;
  const risk = data ? riskOf(data) : null;

  return <>
    <div className="page-title"><div><p className="eyebrow">THREAT INTELLIGENCE</p><h1>URL, Email &amp; Exposure Intelligence</h1><span>Explainable, evidence-based risk scoring for suspicious indicators. Passive/authorized signals only.</span></div></div>
    <div className="intel-tabs">{TABS.map(({ id, label, icon: Icon }) => (
      <button key={id} className={tab === id ? "on" : ""} onClick={() => { setTab(id); setInput(""); run.reset(); }}><Icon size={15} /> {label}</button>
    ))}</div>

    <section className="panel intel-input">
      {tab === "email"
        ? <textarea rows={6} value={input} placeholder={PLACEHOLDER[tab]} onChange={(e) => setInput(e.target.value)} />
        : <input value={input} placeholder={PLACEHOLDER[tab]} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && input.trim()) run.mutate({ tab, value: input }); }} />}
      <button className="button primary" disabled={!input.trim() || run.isPending} onClick={() => run.mutate({ tab, value: input })}><Search size={15} /> {run.isPending ? "Analyzing…" : "Analyze"}</button>
      {tab === "exposure" && <p className="muted intel-note">Privacy-preserving: the address is masked and only breach metadata (site, date, data categories) is shown — never passwords or leaked values. Source: XposedOrNot.</p>}
    </section>

    {run.isPending && <div className="state-box"><span className="spinner" /> Querying intelligence sources…</div>}
    {run.error && <div className="error-box">{run.error.message}</div>}
    {data && risk && <div className="intel-result">
      <section className={`panel intel-score sev-${levelClass(risk.level)}`}>
        <p className="eyebrow">RISK SCORE</p>
        <div className="score-big">{risk.score ?? "—"}<span>/100</span></div>
        <div className={`level ${levelClass(risk.level)}`}>{risk.level}</div>
        {typeof data.error === "string" && <p className="muted">{data.error}</p>}
        <Details tab={tab} data={data} />
      </section>
      <section className="panel"><SignalList signals={data.signals} />
        <details className="intel-raw"><summary>Raw analyzer output</summary><pre>{JSON.stringify(data, null, 2)}</pre></details>
      </section>
    </div>}
  </>;
}
