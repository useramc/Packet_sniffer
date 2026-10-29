"use strict";
/* Pocket Packet Sniffer dashboard (PPS-F-011..014, PPS-F-016/017, PPS-F-021, PPS-SR-005).
   All server text is inserted with textContent, never innerHTML. */
const $ = (id) => document.getElementById(id);
const HISTORY_LEN = 90;
let token = null;
try { token = sessionStorage.getItem("pps_token"); } catch (e) { /* storage blocked */ }
let status = "idle", sessionId = null, mode = "mock", hosts = [], history = [];
let ws = null, wsLive = false, wsAllowed = true, ifaceNames = {}, setupRequired = false, booted = false;
let pollTimer = null, sessionTimer = null;

/* ---------------------------------------------------------------- helpers */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleTimeString() : "");
const fmtDateTime = (iso) => (iso ? new Date(iso).toLocaleString() : "");

async function api(path, method = "GET", body) {
  const headers = {};
  if (token) headers.Authorization = "Bearer " + token;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  } catch (e) {
    return { ok: false, status: 0, data: { message: "Cannot reach the dashboard server." } };
  }
  let data = null;
  try { data = await res.json(); } catch (e) { /* no body */ }
  if (res.status === 401 && token && !path.startsWith("/api/auth/")) showAuth();
  return { ok: res.ok, status: res.status, data: data || {} };
}

/* ------------------------------------------------------------------- auth */
async function showAuth() {
  token = null;
  try { sessionStorage.removeItem("pps_token"); } catch (e) { /* ignore */ }
  stopLive();
  const st = await api("/api/auth/state");
  setupRequired = !!st.data.setupRequired;
  $("app").hidden = true;
  $("auth").hidden = false;
  $("auth-confirm-row").hidden = !setupRequired;
  $("auth-confirm").required = setupRequired;
  $("auth-pass").autocomplete = setupRequired ? "new-password" : "current-password";
  $("auth-submit").textContent = setupRequired ? "Create administrator" : "Sign in";
  $("auth-intro").textContent = setupRequired
    ? "First run: create the administrator account. There is no default password."
    : "Sign in to monitor and control captures.";
  $("auth-error").textContent = "";
}

$("auth-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const username = $("auth-user").value.trim(), password = $("auth-pass").value;
  if (setupRequired && password !== $("auth-confirm").value) {
    $("auth-error").textContent = "Passwords do not match.";
    return;
  }
  const res = await api(setupRequired ? "/api/auth/setup" : "/api/auth/login", "POST", { username, password });
  if (!res.ok) { $("auth-error").textContent = res.data.message || "Sign-in failed."; return; }
  token = res.data.token;
  try { sessionStorage.setItem("pps_token", token); } catch (e) { /* ignore */ }
  $("auth-pass").value = ""; $("auth-confirm").value = "";
  enterApp();
});

$("logout-btn").onclick = () => showAuth();

function tokenUser() {
  try { return JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).sub; } catch (e) { return ""; }
}

/* -------------------------------------------------------------- app start */
async function enterApp() {
  $("auth").hidden = true;
  $("app").hidden = false;
  $("whoami").textContent = tokenUser();
  const cfg = await api("/api/config");
  mode = cfg.data.mode || "mock";
  wsAllowed = cfg.data.websocket !== false;
  $("mode-badge").textContent = mode === "live" ? "Live capture" : "Demo data";
  $("mode-badge").className = "badge " + (mode === "live" ? "ok" : "warn");
  await loadInterfaces();
  await refreshSnapshot();
  refreshSessions();
  startLive();
}

async function loadInterfaces() {
  const sel = $("interface");
  const res = await api("/api/interfaces");
  sel.textContent = "";
  if (!res.ok) { $("message").textContent = res.data.message || "Could not list interfaces."; return; }
  const details = res.data.details || res.data.interfaces.map((n) => ({ id: n, name: n, addresses: [] }));
  ifaceNames = {};
  for (const d of details) {
    ifaceNames[d.id] = d.name;
    const o = el("option", "", d.name + (d.addresses && d.addresses.length ? " (" + d.addresses[0] + ")" : ""));
    o.value = d.id;
    sel.appendChild(o);
  }
}

/* ------------------------------------------------------- live data plumbing */
function startLive() {
  stopLive();
  pollTimer = setInterval(() => { if (!wsLive) refreshSnapshot(); }, 1000);
  sessionTimer = setInterval(refreshSessions, 8000);
  if (wsAllowed) connectWs();
  setLink();
}
function stopLive() {
  clearInterval(pollTimer); clearInterval(sessionTimer);
  if (ws) { ws.onclose = null; try { ws.close(); } catch (e) { /* ignore */ } }
  ws = null; wsLive = false;
}
function setLink() {
  const b = $("link-badge");
  b.textContent = wsLive ? "WebSocket" : "Polling";
  b.className = "badge " + (wsLive ? "ok" : "");
}
function connectWs() {
  if (!token) return;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(proto + "//" + location.host + "/ws/live?token=" + encodeURIComponent(token));
  ws.onopen = () => { wsLive = true; setLink(); };
  ws.onmessage = (m) => { try { const msg = JSON.parse(m.data); if (msg.type === "snapshot") applySnapshot(msg.payload); } catch (e) { /* ignore */ } };
  ws.onclose = () => { wsLive = false; setLink(); if (token) setTimeout(() => { if (token && !wsLive) connectWs(); }, 5000); };
  ws.onerror = () => { try { ws.close(); } catch (e) { /* ignore */ } };
}
async function refreshSnapshot() {
  const res = await api("/api/snapshot");
  if (res.ok) applySnapshot(res.data);
}

/* ---------------------------------------------------------------- rendering */
function applySnapshot(s) {
  if (s.sessionId !== sessionId) { history = []; sessionId = s.sessionId; refreshSessions(); }
  const changed = s.status !== status;
  status = s.status;
  updateControls(s);
  const stats = s.stats;
  $("no-session").hidden = status !== "idle";
  if (stats) {
    const pps = status === "running" ? stats.packets_per_sec : 0;
    $("packets-per-sec").textContent = pps;
    $("total-packets").textContent = stats.total_packets !== undefined ? stats.total_packets + " packets captured" : "";
    if (status === "running") { history.push(stats.packets_per_sec); if (history.length > HISTORY_LEN) history.shift(); }
    renderBars($("protocols-body"), Object.entries(stats.protocols || {}));
    renderBars($("talkers-body"), (stats.top_talkers || []).map((t) => [t.ip, t.packets]));
  } else {
    $("packets-per-sec").textContent = "0"; $("total-packets").textContent = "";
    renderBars($("protocols-body"), []); renderBars($("talkers-body"), []);
  }
  hosts = s.hosts || [];
  renderHosts();
  renderAlerts(s.alerts || []);
  renderZeek(s.zeek);
  drawPulse();
  if (changed) refreshSessions();
}

function updateControls(s) {
  const active = status === "running" || status === "paused";
  const chip = $("status");
  chip.textContent = status; chip.className = "chip " + status;
  $("session-id").textContent = s.sessionId ? s.sessionId : "";
  for (const id of ["interface", "filter", "session-name"]) $(id).disabled = active;
  $("start-btn").disabled = active;
  $("pause-btn").disabled = !active;
  $("stop-btn").disabled = !active;
  $("pause-btn").textContent = status === "paused" ? "Resume" : "Pause";
}

function renderZeek(z) {
  const b = $("zeek-badge");
  if (!z || z.status === "mock") { b.textContent = "Zeek: demo"; b.className = "badge"; b.title = ""; return; }
  const text = { idle: "Zeek: ready", running: "Zeek: analysing", done: "Zeek: " + (z.notices || 0) + " notices",
                 unavailable: "Zeek: not installed", error: "Zeek: error" }[z.status] || "Zeek";
  b.textContent = text;
  b.className = "badge " + (z.status === "done" || z.status === "idle" ? "ok" : z.status === "running" ? "" : "warn");
  b.title = z.message || "";
}

function renderBars(box, entries) {
  box.textContent = "";
  if (!entries.length) { box.appendChild(el("p", "empty", "No data yet.")); return; }
  const max = Math.max(...entries.map((e) => e[1]), 1);
  for (const [label, n] of entries) {
    const row = el("div", "bar-row");
    row.appendChild(el("span", "", label));
    const track = el("div", "bar-track"), fill = el("div", "bar-fill");
    fill.style.width = Math.max(2, (n / max) * 100) + "%";
    track.appendChild(fill); row.appendChild(track);
    row.appendChild(el("span", "num", n));
    box.appendChild(row);
  }
}

function renderHosts() {
  const q = $("host-search").value.trim().toLowerCase();
  const rows = hosts.filter((h) => !q || [h.ip, h.mac, h.vendor, h.protocol].join(" ").toLowerCase().includes(q));
  const body = $("hosts-body");
  body.textContent = "";
  for (const h of rows) {
    const tr = body.insertRow();
    tr.insertCell().textContent = h.ip;
    tr.insertCell().textContent = h.mac || "n/a";
    tr.insertCell().textContent = h.vendor || "n/a";
    tr.insertCell().textContent = h.protocol || "";
    const n = tr.insertCell(); n.className = "num"; n.textContent = h.packets;
    tr.insertCell().textContent = fmtTime(h.last_seen);
  }
  $("hosts-empty").hidden = rows.length > 0;
  $("host-count").textContent = hosts.length ? "(" + hosts.length + ")" : "";
}
$("host-search").addEventListener("input", renderHosts);

function renderAlerts(alerts) {
  const box = $("alerts-body");
  box.textContent = "";
  for (const a of alerts) {
    const sev = ["high", "medium", "low"].includes(a.severity) ? a.severity : "low";
    const card = el("article", "alert " + sev);
    const row = el("div", "row");
    row.appendChild(el("span", "sev", sev[0].toUpperCase() + sev.slice(1)));
    row.appendChild(el("strong", "", a.message));
    row.appendChild(el("span", "muted small", fmtTime(a.time)));
    card.appendChild(row);
    const meta = [a.src ? "from " + a.src : "", a.source ? "via " + a.source : "", a.detail].filter(Boolean).join(" - ");
    if (meta) card.appendChild(el("div", "muted small", meta));
    box.appendChild(card);
  }
  $("alerts-empty").hidden = alerts.length > 0;
  $("alert-count").textContent = alerts.length ? "(" + alerts.length + ")" : "";
}

function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
function drawPulse() {
  const c = $("pulse"), dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth, h = c.clientHeight;
  if (!w || !h) return;
  if (c.width !== w * dpr || c.height !== h * dpr) { c.width = w * dpr; c.height = h * dpr; }
  const g = c.getContext("2d");
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, w, h);
  g.strokeStyle = cssVar("--line"); g.lineWidth = 1;
  for (let i = 1; i < 4; i++) { g.beginPath(); g.moveTo(0, (h * i) / 4); g.lineTo(w, (h * i) / 4); g.stroke(); }
  if (history.length < 2) return;
  const max = Math.max(10, ...history) * 1.15, step = w / (HISTORY_LEN - 1), x0 = w - (history.length - 1) * step;
  const pt = (i) => [x0 + i * step, h - 6 - (history[i] / max) * (h - 12)];
  g.beginPath();
  history.forEach((_, i) => { const [x, y] = pt(i); i ? g.lineTo(x, y) : g.moveTo(x, y); });
  g.strokeStyle = cssVar("--accent"); g.lineWidth = 2.2; g.lineJoin = "round"; g.stroke();
  const [lx, ly] = pt(history.length - 1);
  g.lineTo(lx, h); g.lineTo(x0, h); g.closePath();
  g.globalAlpha = 0.12; g.fillStyle = cssVar("--accent"); g.fill(); g.globalAlpha = 1;
  g.beginPath(); g.arc(lx, ly, 4, 0, 7); g.fill();
}
window.addEventListener("resize", drawPulse);

/* ----------------------------------------------------------------- actions */
async function sendAction(url, body) {
  const res = await api(url, "POST", body || {});
  $("message").textContent = res.ok ? "" : res.data.message || "Action failed.";
  await refreshSnapshot();
  refreshSessions();
}
$("start-btn").onclick = () => sendAction("/api/capture/start", {
  interface: $("interface").value, filter: $("filter").value.trim(), sessionName: $("session-name").value.trim() });
$("stop-btn").onclick = () => sendAction("/api/capture/stop");
$("pause-btn").onclick = () => sendAction(status === "paused" ? "/api/capture/resume" : "/api/capture/pause");

/* ------------------------------------------------------ session history/export */
async function refreshSessions() {
  const res = await api("/api/sessions");
  if (!res.ok) return;
  const body = $("sessions-body");
  body.textContent = "";
  for (const s of res.data.sessions) {
    const tr = body.insertRow();
    tr.insertCell().textContent = s.name + (s.tags.length ? "  [" + s.tags.join(", ") + "]" : "");
    tr.insertCell().textContent = ifaceNames[s.interface] || s.interface;
    tr.insertCell().textContent = fmtDateTime(s.startedAt);
    tr.insertCell().textContent = s.status;
    const act = tr.insertCell();
    const add = (label, fn) => { const b = el("button", "", label); b.onclick = fn; act.appendChild(b); };
    add("Open", () => openSession(s.id));
    add("Rename / tag", () => tagSession(s));
    add("CSV", () => exportSession(s.id, "csv"));
    if (s.hasPcap) add("PCAP", () => exportSession(s.id, "pcap"));
    if (s.mode === "live") add("Zeek logs", () => exportSession(s.id, "zeek-logs"));
  }
  $("sessions-empty").hidden = res.data.sessions.length > 0;
}

async function exportSession(id, format) {
  const res = await api("/api/export/session/" + encodeURIComponent(id), "POST", { format });
  if (!res.ok) { $("message").textContent = res.data.message || "Export failed."; return; }
  $("message").textContent = "";
  window.location.href = res.data.downloadUrl;
}

async function tagSession(s) {
  const name = prompt("Session name", s.name);
  if (name === null) return;
  const tags = prompt("Tags (comma separated)", s.tags.join(", "));
  const res = await api("/api/sessions/" + encodeURIComponent(s.id), "PATCH",
    { name, tags: tags === null ? s.tags : tags.split(",") });
  if (!res.ok) $("message").textContent = res.data.message || "Update failed.";
  refreshSessions();
}

function miniTable(headers, rows) {
  const t = el("table"), hr = t.createTHead().insertRow();
  headers.forEach((h) => hr.appendChild(el("th", "", h)));
  const tb = t.createTBody();
  rows.forEach((r) => { const tr = tb.insertRow(); r.forEach((c) => tr.insertCell().textContent = c === null || c === undefined ? "" : c); });
  const wrap = el("div", "scroll"); wrap.appendChild(t); return wrap;
}

async function openSession(id) {
  const res = await api("/api/sessions/" + encodeURIComponent(id));
  if (!res.ok) { $("message").textContent = res.data.message || "Could not open session."; return; }
  const s = res.data, box = $("dialog-body");
  $("dialog-title").textContent = s.name;
  box.textContent = "";
  box.appendChild(el("p", "muted", "Started " + fmtDateTime(s.startedAt) + (s.stoppedAt ? ", stopped " + fmtDateTime(s.stoppedAt) : "")
    + (s.filter ? ", filter: " + s.filter : "")));
  const stats = s.stats || {};
  box.appendChild(el("h3", "", "Protocols"));
  box.appendChild(miniTable(["Protocol", "Packets"], Object.entries(stats.protocols || {})));
  box.appendChild(el("h3", "", "Hosts"));
  box.appendChild(miniTable(["IP", "MAC", "Vendor", "Protocol", "Packets"],
    (s.hosts || []).map((h) => [h.ip, h.mac || "n/a", h.vendor || "n/a", h.protocol, h.packets])));
  box.appendChild(el("h3", "", "Alerts"));
  box.appendChild(miniTable(["Time", "Severity", "Message", "Detail"],
    (s.alerts || []).map((a) => [fmtTime(a.time), a.severity, a.message, a.detail])));
  $("session-dialog").showModal();
}
$("dialog-close").onclick = () => $("session-dialog").close();

/* -------------------------------------------------------------------- boot */
(async function boot() {
  if (token) {
    const ok = await api("/api/capture/status");
    if (ok.ok) { enterApp(); return; }
  }
  showAuth();
})();
