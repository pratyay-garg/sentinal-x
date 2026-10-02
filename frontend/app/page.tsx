"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useState } from "react";

import { OperatorConsole } from "@/components/operator-console";

export default function Home() {
  const queryClient = useQueryClient();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const session = useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      const response = await fetch("/api/session", { cache: "no-store" });
      return response.json() as Promise<{ configured: boolean; authenticated: boolean }>;
    },
    retry: false,
  });

  async function login(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError("");
    const response = await fetch("/api/session", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    setPending(false);
    if (!response.ok) {
      setError("Authentication failed");
      return;
    }
    setPassword("");
    await queryClient.invalidateQueries({ queryKey: ["session"] });
  }

  if (session.isPending) return <div className="boot"><span className="spinner" /> Establishing console session</div>;
  if (!session.data?.configured) {
    return <main className="login-shell"><section className="login-panel"><div className="wordmark">SENTINAL <b>X</b></div><p className="eyebrow">CONFIGURATION REQUIRED</p><h1>Console authentication is disabled</h1><div className="error-box">Set CONSOLE_PASSWORD and CONSOLE_SESSION_SECRET in Slice_4/.env, then restart the frontend.</div></section></main>;
  }
  if (!session.data.authenticated) {
    return (
      <main className="login-shell">
        <section className="login-panel">
          <div className="wordmark">SENTINAL <b>X</b></div>
          <p className="eyebrow">SECURITY OPERATIONS CONSOLE</p>
          <h1>Operator authentication</h1>
          <form onSubmit={login}>
            <label htmlFor="password">Console password</label>
            <input id="password" type="password" autoFocus autoComplete="current-password"
              value={password} onChange={(event) => setPassword(event.target.value)} required />
            {error && <div className="error-box">{error}</div>}
            <button className="button primary" disabled={pending}>{pending ? "Verifying…" : "Enter console"}</button>
          </form>
          <code>&gt; session protected · backend keys server-side</code>
        </section>
      </main>
    );
  }
  return <OperatorConsole />;
}
