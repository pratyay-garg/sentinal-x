"use client";

import { useState } from "react";

import { api } from "@/lib/api";

export interface AIProviderSettings {
  provider: "openai_compatible" | "vertex_express";
  base_url: string;
  api_key: string;
  model: string;
}

export const defaultAIProvider: AIProviderSettings = {
  provider: "openai_compatible",
  base_url: "https://api.openai.com/v1",
  api_key: "",
  model: "gpt-5-mini",
};

export function AIProviderConfig({ value, onChange }: {
  value: AIProviderSettings;
  onChange: (value: AIProviderSettings) => void;
}) {
  const [models, setModels] = useState<string[]>([]);
  const [checking, setChecking] = useState(false);
  const [connection, setConnection] = useState<{ ok: boolean; message: string } | null>(null);
  const update = (key: keyof AIProviderSettings, next: string) => onChange({ ...value, [key]: next });
  const selectProvider = (provider: AIProviderSettings["provider"]) => {
    setModels([]); setConnection(null);
    onChange(provider === "vertex_express"
      ? { provider, base_url: "https://aiplatform.googleapis.com", api_key: value.api_key, model: "gemini-2.5-flash" }
      : { provider, base_url: "https://api.openai.com/v1", api_key: value.api_key, model: "gpt-5-mini" });
  };
  async function checkProvider() {
    setChecking(true); setConnection(null);
    try {
      const result = await api<{ connected: boolean; models: string[] }>("api/v1/console/remediation/provider/models", { method: "POST", body: JSON.stringify(value) });
      setModels(result.models);
      setConnection({ ok: true, message: `Connected · ${result.models.length} model${result.models.length === 1 ? "" : "s"} available` });
      if (result.models.length === 1) update("model", result.models[0]);
    } catch (error) {
      setConnection({ ok: false, message: error instanceof Error ? error.message : "Provider check failed" });
    } finally { setChecking(false); }
  }
  return <section className="provider-config">
    <div className="panel-head"><div><p className="eyebrow">AI PROVIDER</p><h2>AI connection</h2></div><span className="tag ok">REMEMBERED</span></div>
    <div className="provider-grid">
      <label>Provider<select value={value.provider} onChange={(event) => selectProvider(event.target.value as AIProviderSettings["provider"])}><option value="openai_compatible">OpenAI compatible</option><option value="vertex_express">Google Vertex Express</option></select></label>
      {value.provider === "openai_compatible" && <label>Base URL<input value={value.base_url} onChange={(event) => update("base_url", event.target.value)} placeholder="https://api.openai.com/v1" /></label>}
      <label>Model<input list="sentinalx-provider-models" value={value.model} onChange={(event) => update("model", event.target.value)} placeholder="gpt-5-mini" /><datalist id="sentinalx-provider-models">{models.map((model) => <option value={model} key={model} />)}</datalist></label>
      <label>API key<input type="password" autoComplete="off" value={value.api_key} onChange={(event) => update("api_key", event.target.value)} placeholder="sk-… (optional for local providers)" /></label>
    </div>
    <div className="provider-status"><button className="button" type="button" disabled={checking || !value.base_url || !value.model || (value.provider === "vertex_express" && !value.api_key)} onClick={checkProvider}>{checking ? "Checking…" : value.provider === "vertex_express" ? "Test Vertex connection" : "Test connection & load models"}</button>{connection && <span className={connection.ok ? "ok" : "bad"}>{connection.message}</span>}</div>
    <p className="muted">Remembered in this browser (localStorage) so you don&apos;t retype it, sent only when you click Generate, and never stored on the SENTINAL X server.</p>
  </section>;
}
