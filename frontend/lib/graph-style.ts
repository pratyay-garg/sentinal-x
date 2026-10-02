// Single source of truth for the attack-graph visual style, shared by the live
// Cytoscape canvas (attack-graph.tsx) and the standalone interactive HTML export
// (graph-export.ts) so both render identically.
import type cytoscape from "cytoscape";

export const MONO = "'JetBrains Mono','IBM Plex Mono',Consolas,monospace";

// Provenance → colour. Verified evidence is blue, published priors (CVSS/class)
// are grey, and assumed edges are bright yellow so blind spots are obvious.
export const PROV_COLOR: Record<string, string> = {
  evidence: "#3b82f6", observed: "#3b82f6", verified: "#3b82f6",
  cvss_vector: "#64748b", class_table: "#64748b", assumed: "#eab308",
};

export function shortLabel(raw: string): string {
  const m = raw.match(/^(\w[\w-]*)\s+(?:GET|POST|PUT|PATCH|DELETE)\s+https?:\/\/[^/]+(\/[^?\s]*)/i);
  if (m) return `${m[1]} · ${m[2].length > 26 ? m[2].slice(0, 25) + "…" : m[2]}`;
  return raw.length > 34 ? raw.slice(0, 33) + "…" : raw;
}

export const GRAPH_LAYOUT: cytoscape.CytoscapeOptions["layout"] = {
  name: "breadthfirst", directed: true, padding: 44, spacingFactor: 1.55,
  avoidOverlap: true, nodeDimensionsIncludeLabels: true, grid: false,
};

export const GRAPH_STYLE: cytoscape.CytoscapeOptions["style"] = [
  {
    selector: "node",
    style: {
      label: "data(display)", "font-size": "10px", "font-family": MONO,
      color: "#cbd5e1", "text-valign": "bottom", "text-halign": "center",
      "text-margin-y": 6, "text-wrap": "wrap", "text-max-width": "132px",
      "text-background-color": "#0a0a0b", "text-background-opacity": 0.82,
      "text-background-padding": "3px", "text-background-shape": "roundrectangle",
      width: 38, height: 38, "background-color": "#1e293b",
      "border-width": 2, "border-color": "#334155", "transition-property": "border-color, background-color",
    },
  },
  {
    selector: "node[type = 'state']",
    style: {
      shape: "ellipse",
      "background-color": "mapData(compromise_prob, 0, 1, #14532d, #b91c1c)",
      "border-color": "#22c55e",
    },
  },
  {
    selector: "node[type = 'vuln']",
    style: { shape: "diamond", width: 40, height: 40, "background-color": "#7c2d12", "border-color": "#f59e0b" },
  },
  { selector: "node[type = 'meta']", style: { shape: "round-rectangle", "background-color": "#334155", "border-color": "#64748b", width: 30, height: 24, "font-size": "9px" } },
  {
    selector: "node[?jewel]",
    style: {
      shape: "star", width: 52, height: 52, "background-color": "#a16207",
      "border-color": "#fde047", "border-width": 3, color: "#fde047",
    },
  },
  {
    selector: "edge",
    style: {
      "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 0.9,
      width: "mapData(witness, 0, 1, 1.4, 9)",
      "line-color": "#475569", "target-arrow-color": "#475569", opacity: 0.9,
    },
  },
  { selector: "edge[provenance = 'assumed']", style: { "line-color": "#eab308", "target-arrow-color": "#eab308", "line-style": "dashed" } },
  { selector: "edge[provenance = 'cvss_vector']", style: { "line-color": "#64748b", "target-arrow-color": "#64748b" } },
  { selector: "edge[provenance = 'class_table']", style: { "line-color": "#64748b", "target-arrow-color": "#64748b" } },
  { selector: "edge[provenance = 'evidence']", style: { "line-color": "#3b82f6", "target-arrow-color": "#3b82f6" } },
  { selector: "edge[provenance = 'observed']", style: { "line-color": "#3b82f6", "target-arrow-color": "#3b82f6" } },
  { selector: "edge[kind = 'implies']", style: { "line-style": "dotted", opacity: 0.5, width: 1.4 } },
  { selector: "edge.heat", style: { "line-color": "mapData(witness, 0, 1, #f59e0b, #ef4444)", "target-arrow-color": "#ef4444", "z-index": 20 } },
  { selector: "edge.modal", style: { "line-color": "#fde047", "target-arrow-color": "#fde047", width: 5.5, "line-style": "solid", opacity: 1, "z-index": 40 } },
  { selector: "edge.evidence", style: { "line-color": "#ef4444", "target-arrow-color": "#ef4444" } },
  { selector: "node.cut", style: { "border-color": "#ef4444", "border-width": 4 } },
  { selector: "node.dominator", style: { "border-color": "#a855f7", "border-width": 4 } },
  { selector: "node.risk", style: { "border-color": "#ef4444" } },
  { selector: ".dim", style: { opacity: 0.12 } },
  { selector: ".hl", style: { opacity: 1, "z-index": 60 } },
  { selector: ":selected", style: { "overlay-color": "#fde047", "overlay-opacity": 0.2, "overlay-padding": 8 } },
];
