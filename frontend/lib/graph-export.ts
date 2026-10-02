// Standalone interactive attack-graph export. Produces a single self-contained
// .html file: the Cytoscape library is inlined (fetched once at export time),
// so the file opens offline in any browser with full click / hover / zoom /
// fullscreen and toggleable overlays — ideal for a presentation without the
// backend running. It reuses the exact GRAPH_STYLE/GRAPH_LAYOUT as the live app.
import { GRAPH_LAYOUT, GRAPH_STYLE } from "./graph-style";

const CYTOSCAPE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.33.1/cytoscape.min.js";

export interface GraphExportMetrics {
  target: string;
  scope: string;
  jewelPct: string;
  jewelCi: string;
  derivedPct: string;
  assumedPct: string;
  totalEdges: string;
  cutSize: string;
  cutCost: string;
  mcTrials: string;
  seed: string;
  chokepoints: Array<{ label: string; detail: string }>;
}

interface BuildOptions {
  elements: unknown[];
  overlays: Record<string, boolean>;
  metrics: GraphExportMetrics;
  lib: string; // inlined Cytoscape source, or "" to fall back to the CDN <script src>
}

// Safe JSON for embedding inside <script>: neutralise "</" so it can never close the tag.
function j(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}
function esc(s: string): string {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
}

// The interactive runtime, as a plain JS string (no backticks / no ${} so it can
// be concatenated verbatim). Reads ELEMENTS/STYLE/LAYOUT/OVERLAYS injected above it.
const RUNTIME = `
function shortLabel(raw){var m=String(raw).match(/^(\\w[\\w-]*)\\s+(?:GET|POST|PUT|PATCH|DELETE)\\s+https?:\\/\\/[^/]+(\\/[^?\\s]*)/i);if(m){var p=m[2];return m[1]+" \\u00b7 "+(p.length>26?p.slice(0,25)+"\\u2026":p);}var s=String(raw);return s.length>34?s.slice(0,33)+"\\u2026":s;}
function pct(v){return typeof v==="number"?(v*100).toFixed(1)+"%":"\\u2014";}
function scorecard(rows){if(!Array.isArray(rows)||!rows.length)return "";var out=[];for(var i=0;i<rows.length;i++){var r=rows[i];if(typeof r.contribution!=="number")continue;var v=r.contribution;var sign=v>=0?"+":"\\u2212";out.push("<tr><td>"+(r.signal||"?")+"</td><td class='"+(v>=0?"pos":"neg")+"'>"+sign+Math.abs(v).toFixed(2)+"</td></tr>");}if(!out.length)return "";return "<div class='tt-sub'>Log-odds scorecard</div><table class='tt-score'>"+out.join("")+"</table>";}
var PROV={evidence:"#3b82f6",observed:"#3b82f6",verified:"#3b82f6",cvss_vector:"#64748b",class_table:"#64748b",assumed:"#eab308"};
var cy=cytoscape({container:document.getElementById("cy"),elements:ELEMENTS,style:STYLE,layout:LAYOUT,wheelSensitivity:0.2,minZoom:0.1,maxZoom:6});
cy.nodes().forEach(function(n){n.data("display",shortLabel(n.data("label")||n.id()));});
function applyOverlays(o){cy.batch(function(){cy.nodes().forEach(function(node){node.toggleClass("cut",!!(o.cut&&node.data("in_min_cut")));node.toggleClass("dominator",!!(o.dominators&&Number(node.data("dominated_assets")||0)>0));node.toggleClass("risk",!!(o.probability&&Number(node.data("compromise_prob")||0)>=0.5));node.style("label",o.provenance?shortLabel(node.data("label")||node.id())+"  \\u00b7  "+(node.data("provenance")||"derived"):(node.data("display")||node.id()));});cy.edges().forEach(function(edge){edge.toggleClass("heat",!!(o.probability&&Number(edge.data("witness")||0)>0.02));edge.toggleClass("modal",!!(o.modal&&edge.data("on_modal_path")));edge.toggleClass("evidence",!!(edge.data("evidence_id")&&!o.provenance));});});}
var box=document.getElementById("tip");
function showTip(evt){var el=evt.target,d=el.data(),isEdge=el.isEdge();var title=isEdge?((d.provenance||"derived")+" edge"):shortLabel(d.label||el.id());var rows=[];if(isEdge){rows.push("<div><span>probability</span><b>"+pct(d.p)+"</b></div>");rows.push("<div><span>pressure</span><b>"+pct(d.witness)+"</b></div>");rows.push("<div><span>provenance</span><b style='color:"+(PROV[d.provenance]||"#94a3b8")+"'>"+(d.provenance||"\\u2014")+"</b></div>");}else{if(d.type==="vuln")rows.push("<div><span>status</span><b>"+(d.status||"\\u2014")+"</b></div>");if(d.compromise_prob!==undefined)rows.push("<div><span>compromise</span><b>"+pct(d.compromise_prob)+" \\u00b1"+pct(d.prob_ci)+"</b></div>");if(Number(d.dominated_assets)>0)rows.push("<div><span>gates assets</span><b class='warn'>"+d.dominated_assets+"</b></div>");if(d.in_min_cut)rows.push("<div><span>min-cut</span><b class='warn'>yes</b></div>");if(Array.isArray(d.mitre)&&d.mitre.length)rows.push("<div><span>ATT&CK</span><b>"+d.mitre.join(", ")+"</b></div>");}var card=scorecard(isEdge?d.contributions:d.score_contributions);box.innerHTML="<div class='tt-title'>"+title+"</div><div class='tt-rows'>"+rows.join("")+"</div>"+card;box.style.display="block";}
function moveTip(evt){var rect=document.getElementById("cy").getBoundingClientRect();var x=(evt.renderedPosition&&evt.renderedPosition.x)||0,y=(evt.renderedPosition&&evt.renderedPosition.y)||0;box.style.left=Math.min(x+16,rect.width-260)+"px";box.style.top=Math.min(y+12,rect.height-40)+"px";}
cy.on("mouseover","node,edge",showTip);cy.on("mousemove","node,edge",moveTip);cy.on("mouseout","node,edge",function(){box.style.display="none";});
cy.on("mouseover","node",function(evt){var nb=evt.target.closedNeighborhood();cy.elements().addClass("dim");nb.removeClass("dim").addClass("hl");});
cy.on("mouseout","node",function(){cy.elements().removeClass("dim hl");});
function zoomBy(f){cy.zoom({level:cy.zoom()*f,renderedPosition:{x:cy.width()/2,y:cy.height()/2}});}
document.getElementById("zin").onclick=function(){zoomBy(1.25);};
document.getElementById("zout").onclick=function(){zoomBy(0.8);};
document.getElementById("zfit").onclick=function(){cy.fit(undefined,44);};
document.getElementById("zreset").onclick=function(){cy.zoom(1);cy.center();};
var toggles=document.querySelectorAll(".ov");function readOverlays(){var o={};for(var i=0;i<toggles.length;i++){o[toggles[i].dataset.key]=toggles[i].checked;}return o;}
for(var i=0;i<toggles.length;i++){toggles[i].addEventListener("change",function(){applyOverlays(readOverlays());});}
applyOverlays(OVERLAYS);cy.fit(undefined,44);
`;

export function buildStandaloneGraphHtml(opts: BuildOptions): string {
  const { elements, overlays, metrics, lib } = opts;
  const overlayLabels: Record<string, string> = {
    probability: "Heatmap", modal: "Modal path", cut: "Min-cut", dominators: "Chokepoints", provenance: "Provenance",
  };
  const toggleHtml = Object.keys(overlayLabels)
    .map((k) => `<label class="ovl"><input type="checkbox" class="ov" data-key="${k}" ${overlays[k] ? "checked" : ""}/> ${overlayLabels[k]}</label>`)
    .join("");
  const chokeHtml = metrics.chokepoints.length
    ? metrics.chokepoints.map((c, i) => `<div class="choke"><span class="rk">#${i + 1}</span><div><b>${esc(c.label)}</b><small>${esc(c.detail)}</small></div></div>`).join("")
    : `<div class="muted">No single-point gate to the crown jewels.</div>`;

  const scriptTag = lib
    ? `<script>${lib.replace(/<\/script/gi, "<\\/script")}</script>`
    : `<script src="${CYTOSCAPE_CDN}"></script>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SENTINAL X — Attack Graph — ${esc(metrics.target)}</title>
<style>
:root{--bg:#0a0a0b;--s1:#121214;--s2:#17171a;--bd:#26262b;--hi:#f4f4f5;--mid:#a1a1aa;--lo:#6b6b73;--acc:#e5484d;--ok:#22c55e;--yellow:#eab308;--mono:'JetBrains Mono','IBM Plex Mono',Consolas,monospace}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--hi);font:13px/1.45 Inter,system-ui,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:12px 18px;border-bottom:1px solid var(--bd);background:#0d0d0f}
header .mark{font:700 15px var(--mono);letter-spacing:.1em}header .mark b{color:var(--acc)}header .meta{color:var(--mid);font:12px var(--mono)}
#wrap{position:absolute;top:49px;left:0;right:0;bottom:0;display:grid;grid-template-columns:minmax(0,1fr) 320px}
#stage{position:relative;background:#0d0d0f}#cy{position:absolute;inset:0}
#controls{position:absolute;top:12px;right:12px;display:flex;flex-direction:column;gap:6px;z-index:5}
#controls button{width:34px;height:34px;border:1px solid var(--bd);background:rgba(18,18,20,.9);color:var(--hi);border-radius:7px;cursor:pointer;font-size:16px;line-height:1}
#controls button:hover{background:var(--s2);border-color:var(--acc)}
aside{border-left:1px solid var(--bd);background:var(--s1);overflow:auto;padding:16px}
aside h2{font-size:12px;color:var(--lo);letter-spacing:.07em;margin:0 0 10px;font-family:var(--mono)}
aside section{border-top:1px solid var(--bd);padding:14px 0}aside section:first-of-type{border-top:0;padding-top:0}
.big{font:700 30px var(--mono);letter-spacing:-.03em}.big.red{color:var(--acc)}
.kv{display:flex;justify-content:space-between;border-top:1px solid var(--bd);padding:7px 0;font-family:var(--mono)}.kv:first-child{border-top:0}.kv span{color:var(--lo)}
.ovl{display:flex;align-items:center;gap:8px;padding:5px 0;color:var(--mid);font-weight:600;cursor:pointer}
.choke{display:flex;gap:9px;padding:7px 0;border-top:1px solid var(--bd)}.choke:first-child{border-top:0}.choke .rk{color:var(--acc);font:700 11px var(--mono)}.choke b{font:600 11px var(--mono);display:block;overflow-wrap:anywhere}.choke small{color:var(--lo)}
.muted{color:var(--lo)}
.legend{display:flex;flex-wrap:wrap;gap:8px 14px;color:var(--mid);font-size:11px}.legend i{display:inline-block;width:11px;height:11px;margin-right:5px;vertical-align:-1px;border-radius:2px}
#tip{position:absolute;display:none;max-width:250px;background:#0d0d0f;border:1px solid var(--bd);border-radius:8px;padding:9px 11px;font:11px var(--mono);z-index:9;pointer-events:none;box-shadow:0 8px 24px rgba(0,0,0,.5)}
#tip .tt-title{font-weight:700;margin-bottom:6px;overflow-wrap:anywhere}#tip .tt-rows div{display:flex;justify-content:space-between;gap:10px}#tip span{color:var(--lo)}#tip .warn{color:var(--yellow)}
#tip .tt-sub{color:var(--lo);margin-top:6px}#tip .tt-score{width:100%;margin-top:3px}#tip .tt-score .pos{color:var(--ok)}#tip .tt-score .neg{color:var(--acc)}
@media(max-width:820px){#wrap{grid-template-columns:1fr}aside{display:none}}
</style></head>
<body>
<header><span class="mark">SENTINAL <b>X</b></span><span class="meta">Attack Graph &middot; ${esc(metrics.target)} &middot; ${esc(metrics.scope)}</span></header>
<div id="wrap">
  <div id="stage">
    <div id="cy"></div>
    <div id="controls">
      <button id="zin" title="Zoom in">+</button>
      <button id="zout" title="Zoom out">&minus;</button>
      <button id="zfit" title="Fit to view">&#9974;</button>
      <button id="zreset" title="Reset">&#8634;</button>
    </div>
    <div id="tip"></div>
  </div>
  <aside>
    <section><h2>CROWN-JEWEL COMPROMISE PROBABILITY</h2><div class="big red">${esc(metrics.jewelPct)}</div><div class="muted" style="font:11px var(--mono);margin-top:4px">bounded risk &plusmn;${esc(metrics.jewelCi)} &middot; ${esc(metrics.mcTrials)} MC trials &middot; seed ${esc(metrics.seed)}</div></section>
    <section><h2>OVERLAYS</h2>${toggleHtml}</section>
    <section><h2>MINIMUM LOCKDOWN (MIN-CUT)</h2><div class="kv"><span>Patches to sever all paths</span><b>${esc(metrics.cutSize)}</b></div><div class="kv"><span>Effort</span><b>${esc(metrics.cutCost)}h</b></div></section>
    <section><h2>DATA PROVENANCE</h2><div class="kv"><span>Evidence / observed</span><b>${esc(metrics.derivedPct)}</b></div><div class="kv"><span>Assumed (blind spots)</span><b style="color:var(--yellow)">${esc(metrics.assumedPct)}</b></div><div class="kv"><span>Total edges</span><b>${esc(metrics.totalEdges)}</b></div></section>
    <section><h2>UNBYPASSABLE CHOKEPOINTS</h2>${chokeHtml}</section>
    <section><h2>LEGEND</h2><div class="legend"><span><i style="background:#a16207"></i>crown jewel</span><span><i style="background:#7c2d12"></i>vulnerability</span><span><i style="background:#14532d"></i>privilege</span><span><i style="background:#3b82f6"></i>verified</span><span><i style="background:#64748b"></i>CVSS prior</span><span><i style="background:#eab308"></i>assumed</span></div></section>
  </aside>
</div>
${scriptTag}
<script>
var ELEMENTS=${j(elements)};
var STYLE=${j(GRAPH_STYLE)};
var LAYOUT=${j(GRAPH_LAYOUT as unknown)};
var OVERLAYS=${j(overlays)};
var METRICS=${j(metrics)};
${RUNTIME}
</script>
</body></html>`;
}

export async function exportInteractiveGraph(
  elements: unknown[],
  overlays: Record<string, boolean>,
  metrics: GraphExportMetrics,
): Promise<void> {
  // Inline the library so the file is offline-capable; fall back to the CDN tag.
  let lib = "";
  try {
    const res = await fetch(CYTOSCAPE_CDN, { cache: "force-cache" });
    if (res.ok) lib = await res.text();
  } catch { /* offline at export time — the export falls back to a CDN <script src> */ }
  const html = buildStandaloneGraphHtml({ elements, overlays, metrics, lib });
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const slug = metrics.target.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").slice(0, 40) || "graph";
  a.href = url;
  a.download = `sentinalx-attack-graph-${slug}.html`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
