"""Dependency-free browser view for the Cytoscape-compatible graph payload."""

GRAPH_VIEW_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SENTINAL X Attack Graph</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, system-ui, sans-serif; }
    body { margin: 0; background: #090d16; color: #e8eefc; }
    header { display:flex; gap:12px; align-items:center; padding:14px 18px;
             border-bottom:1px solid #26324a; background:#101728; }
    button { border:1px solid #3b4a68; border-radius:7px; padding:9px 12px;
             color:#eef4ff; cursor:pointer; background:#2856d8; }
    #status { color:#9db0d2; margin-left:auto; }
    main { display:grid; grid-template-columns:minmax(0,1fr) 310px; height:calc(100vh - 61px); }
    svg { width:100%; height:100%; background:radial-gradient(circle,#162036,#090d16 68%); }
    aside { padding:16px; border-left:1px solid #26324a; overflow:auto; }
    .card { background:#111a2c; border:1px solid #273650; border-radius:9px;
            padding:12px; margin-bottom:12px; }
    .metric { display:flex; justify-content:space-between; margin:7px 0; }
    .legend span { display:block; margin:7px 0; }
    .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:7px; }
    text { fill:#e8eefc; font-size:10px; pointer-events:none; }
    line { stroke:#526381; stroke-opacity:.7; marker-end:url(#arrow); }
    circle { stroke:#dbe7ff; stroke-width:1.2; cursor:pointer; }
    .error { color:#ff8f9b; white-space:pre-wrap; }
  </style>
</head>
<body>
  <header>
    <strong>SENTINAL X Attack Graph</strong>
    <button id="load">Render snapshot</button>
    <span id="status">Ready</span>
  </header>
  <main>
    <svg id="graph" role="img" aria-label="Attacker-state graph">
      <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3"
        orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="#526381"/></marker></defs>
    </svg>
    <aside>
      <section class="card" id="summary">Loading graph snapshot…</section>
      <section class="card legend">
        <strong>Node types</strong>
        <span><i class="dot" style="background:#4f8cff"></i>Attacker state</span>
        <span><i class="dot" style="background:#ff5d73"></i>Patchable finding</span>
        <span><i class="dot" style="background:#f4b942"></i>Fact / enabler</span>
        <span><i class="dot" style="background:#9b7bff"></i>Source / sink</span>
      </section>
      <section class="card" id="detail">Click a node for its evidence and provenance.</section>
    </aside>
  </main>
  <script>
    const svg = document.querySelector('#graph');
    const statusEl = document.querySelector('#status');
    const detail = document.querySelector('#detail');
    const colors = {state:'#4f8cff', vuln:'#ff5d73', fact:'#f4b942', meta:'#9b7bff'};
    const ns = 'http://www.w3.org/2000/svg';
    function el(name, attrs) {
      const node = document.createElementNS(ns, name);
      for (const [key,value] of Object.entries(attrs)) node.setAttribute(key,value);
      return node;
    }
    function short(label) { return label.length > 28 ? label.slice(0,25) + '…' : label; }
    const payload = __GRAPH_PAYLOAD__;
    function loadGraph() {
      render(payload);
      statusEl.textContent = payload.cached ? 'Loaded cached snapshot' : 'New snapshot stored';
    }
    function render(payload) {
      [...svg.children].filter(node => node.tagName !== 'defs').forEach(node => node.remove());
      const nodes = payload.cytoscape.elements.nodes.map(item => item.data);
      const edges = payload.cytoscape.elements.edges.map(item => item.data);
      const width = svg.clientWidth || 900, height = svg.clientHeight || 650;
      const radius = Math.max(120, Math.min(width,height) * .36);
      const positions = new Map();
      nodes.forEach((node,index) => {
        const angle = (2*Math.PI*index/nodes.length) - Math.PI/2;
        positions.set(node.id, {x:width/2+radius*Math.cos(angle), y:height/2+radius*Math.sin(angle)});
      });
      edges.forEach(edge => {
        const a=positions.get(edge.source), b=positions.get(edge.target);
        if (a && b) svg.appendChild(el('line',{x1:a.x,y1:a.y,x2:b.x,y2:b.y}));
      });
      nodes.forEach(node => {
        const p=positions.get(node.id), group=el('g',{});
        const circle=el('circle',{cx:p.x,cy:p.y,r:node.type==='vuln'?12:9,
          fill:colors[node.type]||'#8892a8'});
        circle.addEventListener('click',() => {
          detail.textContent = JSON.stringify(node,null,2);
          detail.style.whiteSpace='pre-wrap';
        });
        group.appendChild(circle);
        const text=el('text',{x:p.x+14,y:p.y+4}); text.textContent=short(node.label||node.id);
        group.appendChild(text); svg.appendChild(group);
      });
      const s=payload.summary, inv=s.invariants?.all_passed;
      document.querySelector('#summary').innerHTML = `
        <strong>${s.diagnosis.status}</strong>
        <div class="metric"><span>Snapshot</span><span>${payload.snapshot_id.slice(0,8)}</span></div>
        <div class="metric"><span>Nodes / edges</span><span>${nodes.length} / ${edges.length}</span></div>
        <div class="metric"><span>Reachable jewels</span><span>${s.reachable_jewels.length}</span></div>
        <div class="metric"><span>Derived edges</span><span>${Math.round(100*s.provenance.derived_fraction)}%</span></div>
        <div class="metric"><span>Invariants</span><span>${inv?'PASS':'FAIL'}</span></div>`;
    }
    document.querySelector('#load').addEventListener('click', loadGraph);
    loadGraph();
  </script>
</body>
</html>"""
