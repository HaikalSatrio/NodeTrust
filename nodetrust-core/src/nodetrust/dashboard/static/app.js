// NodeTrust dashboard (NT-026). Vanilla JS, no external resources (CSP: 'self' only).
// All data comes from the real API with the project key held in sessionStorage.
"use strict";

const $ = (s) => document.querySelector(s);
const state = { pid: null, key: null, role: null, scans: [], scanId: null, verdict: null, graph: null,
                selected: null, listMode: false };

// ---------------------------------------------------------------- helpers
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined) e.append(k instanceof Node ? k : String(k));
  return e;
}
const SVGNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}
const badge = (text, cls) => el("span", { class: `badge ${cls}` }, text);
const decisionBadge = (d) => badge(d.replace("_", " "), `d-${d}`);
const tierBadge = (t) => badge(t, `t-${t}`);
const empty = (msg) => el("div", { class: "empty" }, msg);
function table(headers, rows) {
  return el("div", { class: "table-wrap" },
    el("table", {}, el("thead", {}, el("tr", {}, headers.map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, rows)));
}
function kv(pairs) {
  return el("dl", { class: "kv" }, pairs.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
}
function showError(msg) {
  const box = $("#error");
  box.textContent = msg;
  box.classList.toggle("hidden", !msg);
}
function fill(sel, ...nodes) { const t = $(sel); t.replaceChildren(...nodes); }

async function api(path, opts = {}) {
  const headers = { Authorization: `Bearer ${state.key}` };
  if (opts.body) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(path, { ...opts, headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
  } catch (e) {
    throw new Error("Cannot reach the NodeTrust server.");
  }
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-JSON */ }
  if (!res.ok) {
    const msg = data && data.error ? data.error.message : `HTTP ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

// ---------------------------------------------------------------- session
function saveSession() {
  try { sessionStorage.setItem("nt", JSON.stringify({ pid: state.pid, key: state.key })); } catch (_) {}
}
function loadSession() {
  try { return JSON.parse(sessionStorage.getItem("nt") || "null"); } catch (_) { return null; }
}
function forget() {
  try { sessionStorage.removeItem("nt"); } catch (_) {}
  Object.assign(state, { pid: null, key: null, role: null, scans: [], scanId: null });
  $("#login").classList.remove("hidden");
  $("#session").classList.add("hidden");
  $("#tabs").classList.add("hidden");
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  $("#intro").classList.remove("hidden");
  showError("");
}

async function connect(pid, key) {
  state.pid = pid.trim();
  state.key = key.trim();
  showError("");
  try {
    const info = await api(`/v1/projects/${encodeURIComponent(state.pid)}`);
    state.role = /\((admin|ci)\)$/.exec(info.you)?.[1] || "ci";
    saveSession();
    $("#who").textContent = `${info.project.name} · ${state.role} key · policy v${info.policy_version} (${info.policy.mode})`;
    $("#login").classList.add("hidden");
    $("#session").classList.remove("hidden");
    $("#tabs").classList.remove("hidden");
    $("#intro").classList.add("hidden");
    const meta = await api("/v1/meta");
    const b = [];
    if (meta.snapshot_mode) b.push(badge("offline snapshot - not live", "b-snap"));
    if (!meta.network_enabled) b.push(badge("network disabled", "b-snap"));
    fill("#badges", ...b);
    selectTab("overview");
    await loadScans();
  } catch (e) {
    forget();
    showError(e.status === 401 || e.status === 404 ? "Project ID or key not accepted." : e.message);
  }
}

// ---------------------------------------------------------------- tabs
function selectTab(name) {
  document.querySelectorAll("#tabs [role=tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("hidden", v.id !== `view-${name}`));
  const loaders = { graph: loadGraph, alerts: loadAlerts, policy: loadPolicy, audit: loadAudit };
  if (loaders[name]) loaders[name]().catch((e) => showError(e.message));
}

// ---------------------------------------------------------------- overview
async function loadScans() {
  const { scans } = await api(`/v1/projects/${state.pid}/scans?limit=30`);
  state.scans = scans;
  if (!scans.length) {
    fill("#scans", empty("No scans yet. Submit one from CI with the nodetrust-ci action."));
    ["#verdict", "#report", "#drift"].forEach((s) => fill(s, empty("Nothing to show until a scan exists.")));
    return;
  }
  if (!state.scanId || !scans.some((s) => s.id === state.scanId)) state.scanId = scans[0].id;
  renderScans();
  await loadScanDetails();
}

function renderScans() {
  const rows = state.scans.map((s) => {
    const tr = el("tr", { class: `selectable${s.id === state.scanId ? " selected" : ""}`, tabindex: "0",
      "aria-selected": String(s.id === state.scanId) },
      el("td", {}, s.received_at), el("td", { class: "path" }, s.commit_sha.slice(0, 12)), el("td", {}, s.branch),
      el("td", {}, String(s.component_count)), el("td", {}, s.quality),
      el("td", {}, s.decision ? decisionBadge(s.decision) : "-"));
    const pick = () => { state.scanId = s.id; state.graph = null; renderScans(); loadScanDetails().catch((e) => showError(e.message)); };
    tr.addEventListener("click", pick);
    tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); } });
    return tr;
  });
  fill("#scans", table(["Received", "Commit", "Branch", "Components", "Data", "Decision"], rows));
}

async function loadScanDetails() {
  const sid = state.scanId;
  const [verdict, report, drift] = await Promise.all([
    api(`/v1/projects/${state.pid}/scans/${sid}/verdict`).catch((e) => ({ _error: e.message })),
    api(`/v1/projects/${state.pid}/scans/${sid}/report`),
    api(`/v1/projects/${state.pid}/scans/${sid}/drift`),
  ]);
  state.verdict = verdict._error ? null : verdict;
  renderVerdict(verdict);
  renderReport(report);
  renderDrift(drift);
}

function renderVerdict(v) {
  if (v._error) return fill("#verdict", empty(`No verdict: ${v._error}`));
  const labels = [];
  if (v.labels.includes("simulation")) labels.push(badge("SIMULATION", "b-sim"));
  if (v.labels.includes("offline_snapshot")) labels.push(badge("offline snapshot", "b-snap"));
  const head = kv([
    ["Decision", el("span", {}, decisionBadge(v.decision), " ", badge(`assessment: ${v.assessment}`, `a-${v.assessment}`), " ", ...labels)],
    ["Mode / policy", `${v.mode} · policy v${v.policy_version}`],
    ["Data quality", `${v.data_quality.status} · graph ${v.data_quality.graph_snapshot}`],
    ["Scan", `${v.scan.commit.slice(0, 12)} on ${v.scan.branch} · run ${v.scan.run_id || "-"}`],
    ["Override", v.override ? `${v.override.id} by ${v.override.by}: ${v.override.reason}` : "none"],
  ]);
  const reasons = el("ul", { class: "reasons" }, v.reasons.map((r) => el("li", {}, r.message)));
  let findings;
  if (!v.findings.length) findings = empty("No incident matches an exact version in this scan. This is not a certification of safety.");
  else findings = table(["Package", "Tier", "Evidence", "Exposure", "Decision", "Paths from root"],
    v.findings.map((f) => el("tr", {},
      el("td", {}, `${f.package}@${f.versions.join(", ")}`, f.is_simulation ? el("div", {}, badge("SIMULATION", "b-sim")) : null),
      el("td", {}, tierBadge(f.tier), el("div", { class: "muted" }, `score ${f.risk_score} (heuristic)`)),
      el("td", {}, f.evidence_status), el("td", {}, f.exposure, el("div", { class: "muted" }, radiusText(f.radius))),
      el("td", {}, decisionBadge(f.decision), f.reasons.map((r) => el("div", { class: "muted" }, r.message))),
      el("td", { class: "path" }, f.paths.length ? f.paths.map((p) => el("div", {}, p.join(" → "))) : "path unknown"))));
  fill("#verdict", head, reasons, findings);
}

function radiusText(r) {
  if (!r || !r.status) return "";
  if (r.status !== "KNOWN") return `radius UNKNOWN (${r.reason || "incomplete"})`;
  return `radius ${r.affected_versions}/${r.total_versions} (${Math.round(r.ratio * 100)}%)`;
}

function renderReport(r) {
  const c = r.counts, cov = r.coverage;
  const parts = [kv([
    ["npm components", `${c.npm_components} (direct ${c.direct}, transitive ${c.transitive}, max depth ${c.max_depth})`],
    ["In graph", `${cov.in_graph} of ${c.npm_components} · not assessed ${cov.not_assessed}`],
    ["Out of scope", String(c.out_of_scope_components)],
  ]), el("p", { class: "muted" }, cov.note)];
  parts.push(el("h3", {}, "Choke points"));
  parts.push(r.choke_points.length ? table(["Package", "Only path for", "Dependents in project"],
    r.choke_points.map((p) => el("tr", {}, el("td", {}, p.package), el("td", {}, String(p.dominates)), el("td", {}, String(p.dependents_in_project)))))
    : empty("No single package gates others."));
  parts.push(el("h3", {}, "Heuristic risk signals"));
  parts.push(r.risk.length ? table(["Package", "Tier", "Signals"], r.risk.map((x) => el("tr", {},
    el("td", {}, x.package), el("td", {}, tierBadge(x.tier), ` ${x.score}`), el("td", {}, x.reasons.join(", ")))))
    : empty("No scored signals above NORMAL for packages in the graph."));
  parts.push(el("h3", {}, "Vulnerability advisories (not evidence of compromise)"));
  parts.push(r.vulnerabilities.length ? table(["Package", "Advisory", "Summary"], r.vulnerabilities.map((x) => el("tr", {},
    el("td", {}, x.package), el("td", {}, x.ids.join(", ")), el("td", {}, x.summary)))) : empty("None matched."));
  if (r.not_assessed.length) {
    parts.push(el("h3", {}, "Not assessed (unknown, not safe)"));
    parts.push(el("ul", {}, r.not_assessed.slice(0, 30).map((x) => el("li", {}, `${x.package}@${x.version || "?"}: ${x.why}`))));
  }
  fill("#report", ...parts);
}

function renderDrift(d) {
  if (d.first_scan) return fill("#drift", empty("First scan on this branch: no baseline to compare."));
  const list = (items, fmt) => items.length ? el("ul", {}, items.map((i) => el("li", {}, fmt(i)))) : el("p", { class: "muted" }, "none");
  fill("#drift", kv([["Baseline", `${d.baseline.commit_sha.slice(0, 12)} (${d.baseline.received_at})`],
    ["This scan", `${d.scan.commit_sha.slice(0, 12)} (${d.scan.received_at})`]]),
  el("h3", {}, `Added (${d.added.length})`), list(d.added, (i) => `${i.name}@${i.versions.join(", ")}`),
  el("h3", {}, `Removed (${d.removed.length})`), list(d.removed, (i) => `${i.name}@${i.versions.join(", ")}`),
  el("h3", {}, `Changed (${d.changed.length})`), list(d.changed, (i) => `${i.name}: ${i.from.join(", ")} → ${i.to.join(", ")}`));
}

// ---------------------------------------------------------------- graph
async function loadGraph() {
  if (!state.scanId) return fill("#graph", empty("No scan selected."));
  if (!state.graph) state.graph = await api(`/v1/projects/${state.pid}/scans/${state.scanId}/graph?limit=400`);
  if (!state.verdict) state.verdict = await api(`/v1/projects/${state.pid}/scans/${state.scanId}/verdict`).catch(() => null);
  const g = state.graph;
  fill("#graph-note", g.truncated ? `Showing ${g.nodes.length} of ${g.total_nodes} nodes (large graph truncated; use the list view or the API for the rest).` : "");
  if (g.nodes.length <= 1) { fill("#graph", empty("This scan has no dependency relations to draw.")); return; }
  renderGraph();
}

function flaggedNames() {
  const s = new Set();
  (state.verdict?.findings || []).forEach((f) => s.add(f.package));
  return s;
}

function layout(g) {
  const root = g.nodes.find((n) => n.root);
  const adj = new Map();
  g.edges.forEach((e) => { if (!adj.has(e.from)) adj.set(e.from, []); adj.get(e.from).push(e.to); });
  const depth = new Map([[root.id, 0]]);
  const q = [root.id];
  while (q.length) {
    const n = q.shift();
    for (const m of adj.get(n) || []) if (!depth.has(m)) { depth.set(m, depth.get(n) + 1); q.push(m); }
  }
  let maxD = 0;
  depth.forEach((d) => { maxD = Math.max(maxD, d); });
  g.nodes.forEach((n) => { if (!depth.has(n.id)) depth.set(n.id, maxD + 1); }); // unreachable: last column
  const cols = new Map();
  g.nodes.forEach((n) => { const d = depth.get(n.id); if (!cols.has(d)) cols.set(d, []); cols.get(d).push(n); });
  const pos = new Map();
  const W = 210, H = 40;
  let maxRows = 0;
  [...cols.keys()].sort((a, b) => a - b).forEach((d) => {
    const nodes = cols.get(d).sort((a, b) => a.label.localeCompare(b.label));
    maxRows = Math.max(maxRows, nodes.length);
    nodes.forEach((n, i) => pos.set(n.id, { x: 16 + d * W, y: 16 + i * H }));
  });
  return { pos, width: 16 + (Math.max(...cols.keys()) + 1) * W, height: 32 + maxRows * H, adj };
}

function pathsTo(target, adj, rootId, max = 3) {
  const dist = new Map([[rootId, 0]]), preds = new Map([[rootId, []]]);
  const q = [rootId];
  while (q.length) {
    const n = q.shift();
    for (const m of adj.get(n) || []) {
      if (!dist.has(m)) { dist.set(m, dist.get(n) + 1); preds.set(m, [n]); q.push(m); }
      else if (dist.get(m) === dist.get(n) + 1) preds.get(m).push(n);
    }
  }
  if (!dist.has(target)) return [];
  const out = [], stack = [[target, [target]]];
  while (stack.length && out.length < max) {
    const [n, acc] = stack.pop();
    if (n === rootId) { out.push(acc.slice().reverse()); continue; }
    for (const p of preds.get(n)) stack.push([p, acc.concat(p)]);
  }
  return out;
}

function renderGraph() {
  const g = state.graph;
  const { pos, width, height, adj } = layout(g);
  const flagged = flaggedNames();
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const rootId = g.nodes.find((n) => n.root).id;
  const s = svg("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "group" });
  const edgeEls = [];
  g.edges.forEach((e) => {
    const a = pos.get(e.from), b = pos.get(e.to);
    const p = svg("path", { class: "edge", d: `M${a.x + 180},${a.y + 13} C${a.x + 195},${a.y + 13} ${b.x - 15},${b.y + 13} ${b.x},${b.y + 13}` });
    p.dataset.from = e.from; p.dataset.to = e.to;
    edgeEls.push(p); s.append(p);
  });
  const nodeEls = new Map();
  g.nodes.forEach((n) => {
    const p = pos.get(n.id);
    const cls = ["node", n.root ? "root" : "", flagged.has(n.name) ? "flag" : "", n.status && n.status !== "exact" ? "unknown" : ""].join(" ");
    const grp = svg("g", { class: cls, transform: `translate(${p.x},${p.y})`, tabindex: "0", role: "button",
      "aria-label": `${n.label}${flagged.has(n.name) ? ", flagged by an incident" : ""}${n.status && n.status !== "exact" ? ", version unknown" : ""}` });
    grp.append(svg("rect", { width: 180, height: 26, rx: 6 }));
    const t = svg("text", { x: 8, y: 17 });
    t.textContent = n.label.length > 28 ? n.label.slice(0, 27) + "…" : n.label;
    grp.append(t);
    const pick = () => select(n.id);
    grp.addEventListener("click", pick);
    grp.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); } });
    nodeEls.set(n.id, grp);
    s.append(grp);
  });
  fill("#graph", s);
  renderList(byId, flagged);

  function select(id) {
    state.selected = id;
    const paths = pathsTo(id, adj, rootId);
    const onNodes = new Set(paths.flat());
    const onEdges = new Set(paths.flatMap((p) => p.slice(1).map((n, i) => `${p[i]}→${n}`)));
    nodeEls.forEach((elm, nid) => {
      elm.classList.toggle("sel", nid === id);
      elm.classList.toggle("on", onNodes.has(nid) && nid !== id);
    });
    edgeEls.forEach((e) => e.classList.toggle("on", onEdges.has(`${e.dataset.from}→${e.dataset.to}`)));
    showNode(byId.get(id), paths.map((p) => p.map((x) => byId.get(x).label)), adj, byId);
  }
}

function renderList(byId, flagged) {
  const rows = [...byId.values()].filter((n) => !n.root).sort((a, b) => a.label.localeCompare(b.label)).map((n) =>
    el("tr", {}, el("td", {}, n.label), el("td", {}, n.direct ? "direct" : "transitive"), el("td", {}, n.status),
      el("td", {}, flagged.has(n.name) ? badge("flagged", "t-CRITICAL") : "")));
  fill("#graph-list", table(["Package", "Relation", "Version status", "Incident"], rows));
}

async function showNode(n, paths, adj, byId) {
  if (n.root) return fill("#node-detail", el("p", {}, "The project root."));
  const findings = (state.verdict?.findings || []).filter((f) => f.package === n.name);
  const rev = new Map();
  adj.forEach((kids, parent) => kids.forEach((k) => { if (!rev.has(k)) rev.set(k, []); rev.get(k).push(parent); }));
  const anc = new Set(), q = [n.id];
  while (q.length) for (const p of rev.get(q.shift()) || []) if (!anc.has(p) && !byId.get(p).root) { anc.add(p); q.push(p); }
  const parts = [kv([["Package", n.label], ["Relation", n.direct ? "direct dependency" : "transitive"],
    ["Version", n.status === "exact" ? "exact" : "unknown (not assessed)"],
    ["Depends on it here", `${anc.size} package(s) in this project`]])];
  parts.push(el("h3", {}, "Impact paths from your project"));
  parts.push(paths.length ? el("div", { class: "path" }, paths.map((p) => el("div", {}, p.join(" → ")))) : empty("Not reachable from the root in this SBOM (path unknown)."));
  if (findings.length) {
    parts.push(el("h3", {}, "Incidents on this package"));
    findings.forEach((f) => parts.push(el("div", {}, tierBadge(f.tier), " ", decisionBadge(f.decision), " ",
      f.is_simulation ? badge("SIMULATION", "b-sim") : "", el("div", {}, f.title), el("div", { class: "muted" }, `evidence: ${f.evidence_status}`))));
  }
  const detail = el("div", {}, el("p", { class: "muted" }, "Loading registry blast radius…"));
  parts.push(el("h3", {}, "Registry blast radius & forecast"), detail);
  fill("#node-detail", ...parts);
  if (n.status !== "exact" || !n.version) { detail.replaceChildren(empty("Needs an exact version.")); return; }
  try {
    const b = await api(`/v1/graph/blast?name=${encodeURIComponent(n.name)}&version=${encodeURIComponent(n.version)}&max_nodes=500`);
    const fc = b.forecast;
    const kids = [kv([["Dependents in registry graph", `${b.count}${b.truncated ? " (truncated: " + b.truncation_reason + ")" : ""}`],
      ["By hop", Object.entries(b.by_hop).map(([h, c]) => `hop ${h}: ${c}`).join(", ") || "none"],
      ["Semantics", b.semantics]])];
    kids.push(el("p", {}, badge("heuristic simulation, not validated", "b-sim")));
    if (fc.status !== "ok") kids.push(empty(`Forecast unavailable: ${fc.reason}`));
    else kids.push(el("table", { class: "horizon" }, el("thead", {}, el("tr", {}, ["Horizon", "Expected", "Range"].map((h) => el("th", {}, h)))),
      el("tbody", {}, fc.horizons.map((h) => el("tr", {}, el("td", {}, `T+${h.hours}h`), el("td", {}, String(h.expected)), el("td", {}, `${h.low}–${h.high}`))))));
    detail.replaceChildren(...kids);
  } catch (e) { detail.replaceChildren(empty(`Could not load: ${e.message}`)); }
}

// ---------------------------------------------------------------- alerts / approvals
async function loadAlerts() {
  const [{ alerts }, { approvals }] = await Promise.all([
    api(`/v1/projects/${state.pid}/alerts`), api(`/v1/projects/${state.pid}/approvals`)]);
  const admin = state.role === "admin";
  fill("#approvals", approvals.length ? table(["Requested", "Incident", "Scan", "Status", "Decision"],
    approvals.map((a) => el("tr", {}, el("td", {}, a.requested_at), el("td", {}, a.incident_id), el("td", { class: "path" }, a.scan_id),
      el("td", {}, a.status, a.decided_by ? el("div", { class: "muted" }, `${a.decided_by}: ${a.decision_note}`) : null),
      el("td", {}, a.status === "pending" && admin ? decisionForm(["allow", "block"], (d, note) =>
        api(`/v1/projects/${state.pid}/approvals/${a.id}`, { method: "POST", body: { decision: d, note } })) : "")))) :
    empty("No approvals requested."));
  fill("#alerts", alerts.length ? table(["Created", "Package", "Tier", "Delivery", "Triage", "Action"],
    alerts.map((a) => el("tr", {}, el("td", {}, a.created_at),
      el("td", {}, `${a.payload.exposure.package}@${a.payload.exposure.versions.join(", ")}`,
        a.payload.incident.is_simulation ? el("div", {}, badge("SIMULATION", "b-sim")) : null,
        el("div", { class: "muted" }, a.payload.incident.title)),
      el("td", {}, tierBadge(a.tier)), el("td", {}, `${a.delivery_status} (${a.attempts})`), el("td", {}, a.triage_status),
      el("td", {}, a.triage_status === "open" && admin ? decisionForm(["confirm", "reject"], (d, note) =>
        api(`/v1/projects/${state.pid}/alerts/${a.id}/triage`, { method: "POST", body: { decision: d, note } })) : "")))) :
    empty("No alerts. Alerts are sent only when this project is proven exposed."));
}

function decisionForm(choices, submit) {
  const note = el("input", { placeholder: "note (required)", "aria-label": "Decision note", maxlength: "1000" });
  const buttons = choices.map((c) => el("button", { type: "button", onclick: async () => {
    if (note.value.trim().length < 5) { showError("Please write a note of at least 5 characters."); note.focus(); return; }
    try { await submit(c, note.value.trim()); showError(""); await loadAlerts(); } catch (e) { showError(e.message); }
  } }, c));
  return el("div", { class: "actions" }, note, ...buttons);
}

// ---------------------------------------------------------------- policy / audit
async function loadPolicy() {
  const p = await api(`/v1/projects/${state.pid}/policy`);
  fill("#policy", kv(Object.entries(p.policy).map(([k, v]) => [k, String(v)])),
    el("h3", {}, "History"), table(["Version", "Created", "By"], p.history.map((h) =>
      el("tr", {}, el("td", {}, `v${h.version}`), el("td", {}, h.created_at), el("td", {}, h.created_by)))));
}

async function loadAudit() {
  if (state.role !== "admin") return fill("#audit", empty("The audit log needs a project admin key."));
  const { events } = await api(`/v1/projects/${state.pid}/audit?limit=200`);
  fill("#audit", events.length ? table(["Time", "Actor", "Action", "Target"], events.map((e) =>
    el("tr", {}, el("td", {}, e.ts), el("td", {}, e.actor), el("td", {}, e.action), el("td", { class: "path" }, e.target || "")))) :
    empty("No audit events yet."));
}

// ---------------------------------------------------------------- boot
document.addEventListener("DOMContentLoaded", () => {
  $("#login").addEventListener("submit", (ev) => { ev.preventDefault(); connect($("#pid").value, $("#key").value); $("#key").value = ""; });
  $("#logout").addEventListener("click", forget);
  document.querySelectorAll("#tabs [role=tab]").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));
  $("#toggle-list").addEventListener("click", () => {
    state.listMode = !state.listMode;
    $("#graph").classList.toggle("hidden", state.listMode);
    $("#graph-list").classList.toggle("hidden", !state.listMode);
    $("#toggle-list").textContent = state.listMode ? "Show as graph" : "Show as list";
  });
  const saved = loadSession();
  if (saved && saved.pid && saved.key) connect(saved.pid, saved.key);
});
