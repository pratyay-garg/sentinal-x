"use client";

import cytoscape, { Core, EventObject } from "cytoscape";
import { Maximize2, Minimize2, Minus, Plus, RotateCcw, Scan } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { CyElement, CytoscapePayload } from "@/lib/types";
import { GRAPH_LAYOUT, GRAPH_STYLE, PROV_COLOR, shortLabel } from "@/lib/graph-style";

interface Props {
  graph: CytoscapePayload;
  probability: boolean;
  cut: boolean;
  dominators: boolean;
  modal: boolean;
  provenance: boolean;
  onEvidence: (id: string) => void;
}

function elements(payload: CytoscapePayload): CyElement[] {
  return [...payload.elements.nodes, ...payload.elements.edges];
}

function scorecard(rows: unknown): string {
  if (!Array.isArray(rows) || rows.length === 0) return "";
  const lines = rows
    .map((r) => {
      const row = r as { signal?: string; contribution?: number };
      if (typeof row.contribution !== "number") return null;
      const v = row.contribution;
      const sign = v >= 0 ? "+" : "−";
      return `<tr><td>${row.signal ?? "?"}</td><td class="${v >= 0 ? "pos" : "neg"}">${sign}${Math.abs(v).toFixed(2)}</td></tr>`;
    })
    .filter(Boolean);
  if (lines.length === 0) return "";
  return `<div class="tt-sub">Log-odds scorecard</div><table class="tt-score">${lines.join("")}</table>`;
}

function pct(v: unknown): string {
  return typeof v === "number" ? `${(v * 100).toFixed(1)}%` : "—";
}

export function AttackGraph({ graph, probability, cut, dominators, modal, provenance, onEvidence }: Props) {
  const root = useRef<HTMLDivElement>(null);
  const tip = useRef<HTMLDivElement>(null);
  const instance = useRef<Core | null>(null);
  const [fs, setFs] = useState(false);

  const zoomBy = (factor: number) => {
    const cy = instance.current;
    if (cy) cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };
  const fitGraph = () => instance.current?.fit(undefined, 44);
  const resetView = () => { const cy = instance.current; if (cy) { cy.zoom(1); cy.center(); } };

  // Resize + refit when entering/leaving fullscreen; Escape exits.
  useEffect(() => {
    const cy = instance.current;
    const t = setTimeout(() => { cy?.resize(); cy?.fit(undefined, 44); }, 80);
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setFs(false); };
    if (fs) window.addEventListener("keydown", onKey);
    return () => { clearTimeout(t); window.removeEventListener("keydown", onKey); };
  }, [fs]);

  useEffect(() => {
    if (!root.current) return;
    instance.current?.destroy();

    const cy = cytoscape({
      container: root.current,
      elements: elements(graph),
      wheelSensitivity: 0.2,
      minZoom: 0.12,
      maxZoom: 5,
      layout: GRAPH_LAYOUT,
      style: GRAPH_STYLE,
    });

    // Precompute display labels + evidence class.
    cy.nodes().forEach((n) => { n.data("display", shortLabel(String(n.data("label") ?? n.id()))); });
    cy.edges().forEach((e) => { if (e.data("evidence_id")) e.addClass("has-evidence"); });

    // Hover tooltip: scorecard + provenance + probability.
    const showTip = (evt: EventObject) => {
      const el = evt.target;
      const d = el.data();
      const box = tip.current;
      if (!box) return;
      const isEdge = el.isEdge();
      const title = isEdge
        ? `${d.provenance ?? "derived"} edge`
        : shortLabel(String(d.label ?? el.id()));
      const rows: string[] = [];
      if (isEdge) {
        rows.push(`<div><span>probability</span><b>${pct(d.p)}</b></div>`);
        rows.push(`<div><span>pressure (witness)</span><b>${pct(d.witness)}</b></div>`);
        rows.push(`<div><span>provenance</span><b class="prov" style="color:${PROV_COLOR[d.provenance] ?? "#94a3b8"}">${d.provenance ?? "—"}</b></div>`);
        if (d.evidence_id) rows.push(`<div><span>evidence</span><b class="clk">click to prove ↗</b></div>`);
      } else {
        if (d.type === "vuln") rows.push(`<div><span>status</span><b>${d.status ?? "—"}</b></div>`);
        if (d.compromise_prob !== undefined) rows.push(`<div><span>compromise</span><b>${pct(d.compromise_prob)} ±${pct(d.prob_ci)}</b></div>`);
        if (Number(d.dominated_assets) > 0) rows.push(`<div><span>gates assets</span><b class="warn">${d.dominated_assets}</b></div>`);
        if (d.in_min_cut) rows.push(`<div><span>min-cut</span><b class="warn">yes</b></div>`);
        if (Array.isArray(d.mitre) && d.mitre.length) rows.push(`<div><span>ATT&CK</span><b>${d.mitre.join(", ")}</b></div>`);
        if (d.evidence_id) rows.push(`<div><span>evidence</span><b class="clk">click to prove ↗</b></div>`);
      }
      const card = scorecard(isEdge ? d.contributions : d.score_contributions);
      box.innerHTML = `<div class="tt-title">${title}</div><div class="tt-rows">${rows.join("")}</div>${card}`;
      box.style.display = "block";
    };
    const moveTip = (evt: EventObject) => {
      const box = tip.current;
      const rect = root.current?.getBoundingClientRect();
      if (!box || !rect) return;
      const x = evt.renderedPosition?.x ?? 0;
      const y = evt.renderedPosition?.y ?? 0;
      box.style.left = `${Math.min(x + 16, rect.width - 260)}px`;
      box.style.top = `${Math.min(y + 12, rect.height - 40)}px`;
    };
    const hideTip = () => { if (tip.current) tip.current.style.display = "none"; };

    cy.on("mouseover", "node, edge", showTip);
    cy.on("mousemove", "node, edge", moveTip);
    cy.on("mouseout", "node, edge", hideTip);

    // Focus the neighbourhood on hover so a dense graph stays readable.
    cy.on("mouseover", "node", (evt) => {
      const nb = evt.target.closedNeighborhood();
      cy.elements().addClass("dim");
      nb.removeClass("dim").addClass("hl");
    });
    cy.on("mouseout", "node", () => cy.elements().removeClass("dim hl"));

    const openEvidence = (evt: EventObject) => {
      const id = evt.target.data("evidence_id") as unknown;
      if (typeof id === "string" && id) onEvidence(id);
    };
    cy.on("tap", "edge, node", openEvidence);

    instance.current = cy;
    return () => { cy.destroy(); instance.current = null; hideTip(); };
  }, [graph, onEvidence]);

  // Overlay toggles — applied without rebuilding the graph.
  useEffect(() => {
    const cy = instance.current;
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().forEach((node) => {
        node.toggleClass("cut", cut && Boolean(node.data("in_min_cut")));
        node.toggleClass("dominator", dominators && Number(node.data("dominated_assets") ?? 0) > 0);
        node.toggleClass("risk", probability && Number(node.data("compromise_prob") ?? 0) >= 0.5);
        node.style("label", provenance
          ? `${shortLabel(String(node.data("label") ?? node.id()))}  ·  ${String(node.data("provenance") ?? "derived")}`
          : String(node.data("display") ?? node.id()));
      });
      cy.edges().forEach((edge) => {
        edge.toggleClass("heat", probability && Number(edge.data("witness") ?? 0) > 0.02);
        edge.toggleClass("modal", modal && Boolean(edge.data("on_modal_path")));
        edge.toggleClass("evidence", Boolean(edge.data("evidence_id")) && !provenance);
      });
    });
  }, [probability, cut, dominators, modal, provenance]);

  return (
    <div className={`graph-stage${fs ? " fullscreen" : ""}`}>
      <div ref={root} className="graph-canvas" aria-label="Interactive attack graph" />
      <div ref={tip} className="graph-tip" aria-hidden />
      <div className="graph-controls">
        <button onClick={() => zoomBy(1.25)} title="Zoom in" aria-label="Zoom in"><Plus size={15} /></button>
        <button onClick={() => zoomBy(0.8)} title="Zoom out" aria-label="Zoom out"><Minus size={15} /></button>
        <button onClick={fitGraph} title="Fit to view" aria-label="Fit to view"><Scan size={15} /></button>
        <button onClick={resetView} title="Reset zoom" aria-label="Reset zoom"><RotateCcw size={15} /></button>
        <button onClick={() => setFs((v) => !v)} title={fs ? "Exit fullscreen (Esc)" : "Fullscreen"} aria-label="Toggle fullscreen">{fs ? <Minimize2 size={15} /> : <Maximize2 size={15} />}</button>
      </div>
      <div className="graph-legend" aria-hidden>
        <span><i className="lg-star" /> crown jewel</span>
        <span><i className="lg-vuln" /> vulnerability</span>
        <span><i className="lg-state" /> privilege</span>
        <span><i className="lg-ev" /> verified</span>
        <span><i className="lg-cvss" /> CVSS prior</span>
        <span><i className="lg-assumed" /> assumed</span>
      </div>
    </div>
  );
}
