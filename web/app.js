/* ============================================================
   FinSpark Security AI — app.js
   Pure HTML/CSS/JS frontend connecting to FastAPI backend
   ============================================================ */

const API = 'http://localhost:8000';
let currentPage = 'dashboard';
let liveData = { kpis: {}, feed: [], alerts: [], fraudTx: [], quantum: [], users: [] };
let interceptionState = { phase: 'idle', scores: null };
let pollInterval = null;
let graphNetwork = null;
let charts = {};

// ── Utilities ──────────────────────────────────────────────────────────────
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];
const fmt = (n) => n?.toLocaleString('en-IN') ?? '—';
const fmtAmt = (n) => `₹${fmt(Math.round(n))}`;
const fmtScore = (n) => (n ?? 0).toFixed(2);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function fmtTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleTimeString('en-IN', { hour12: false }); } catch { return '—'; }
}

function scoreColor(s) {
  if (s >= 0.65) return 'var(--red)';
  if (s >= 0.35) return 'var(--amber)';
  return 'var(--green)';
}
function scoreLabel(s) {
  if (s >= 0.65) return 'High';
  if (s >= 0.35) return 'Medium';
  return 'Low';
}
function statusBadge(status) {
  const m = { high: 'badge-red', medium: 'badge-amber', low: 'badge-green', open: 'badge-red', closed: 'badge-green' };
  return `<span class="badge ${m[status] || 'badge-blue'}">${status}</span>`;
}
function eventTypeBadge(t) {
  const m = { LOGIN: 'badge-blue', TRANSACTION: 'badge-cyan', SIM_SWAP: 'badge-purple', DATA_TRANSFER: 'badge-amber' };
  return `<span class="badge ${m[t] || 'badge-blue'}">${t}</span>`;
}

// ── Backend connectivity ───────────────────────────────────────────────────
async function checkBackend() {
  try {
    const r = await fetch(`${API}/`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      $('#backend-status .status-dot').className = 'status-dot connected';
      $('#backend-status .status-text').textContent = 'Backend Connected';
      return true;
    }
  } catch {}
  $('#backend-status .status-dot').className = 'status-dot error';
  $('#backend-status .status-text').textContent = 'Backend Offline';
  return false;
}

async function api(path, opts = {}) {
  try {
    const r = await fetch(`${API}${path}`, { signal: AbortSignal.timeout(5000), ...opts });
    if (!r.ok) return null;
    return r.json();
  } catch (e) {
    console.warn('API error:', path, e.message);
    return null;
  }
}

// ── Live Polling ───────────────────────────────────────────────────────────
async function pollLiveData() {
  // Tick one event
  await api('/api/tick', { method: 'POST' });

  // Fetch all at once
  const [kpis, feed, alerts, fraud] = await Promise.all([
    api('/api/kpis'),
    api('/api/live-feed?limit=35'),
    api('/api/alerts?limit=12'),
    api('/api/fraud-transactions?limit=25'),
  ]);
  if (kpis) liveData.kpis = kpis;
  if (feed) liveData.feed = feed;
  if (alerts) liveData.alerts = alerts;
  if (fraud) liveData.fraudTx = fraud;

  // Update notification badge
  const alertCount = liveData.kpis.high_risk_alerts ?? 0;
  const badge = $('#notif-count');
  const navBadge = $('#alert-badge');
  if (alertCount > 0) {
    badge.textContent = alertCount; badge.style.display = 'flex';
    navBadge.textContent = alertCount; navBadge.style.display = 'inline-block';
  }

  // Re-render current page if it consumes live data
  refreshCurrentPage();
}

function refreshCurrentPage() {
  if (currentPage === 'dashboard') renderDashboard();
  if (currentPage === 'live-monitoring') refreshLiveFeed();
  if (currentPage === 'fraud') renderFraudTable();
}

// ── Clock ──────────────────────────────────────────────────────────────────
function startClock() {
  const el = $('#clock');
  setInterval(() => {
    el.textContent = new Date().toLocaleTimeString('en-IN', { hour12: false });
  }, 1000);
  el.textContent = new Date().toLocaleTimeString('en-IN', { hour12: false });
}

// ── Navigation ─────────────────────────────────────────────────────────────
function goToPage(page) {
  currentPage = page;
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  renderPage(page);
}

window.goToPage = goToPage;

// ── Page Router ────────────────────────────────────────────────────────────
function renderPage(page) {
  const content = $('#page-content');
  content.innerHTML = '';
  destroyCharts();

  switch (page) {
    case 'dashboard': renderDashboard(); break;
    case 'live-monitoring': renderLiveMonitoring(); break;
    case 'correlation': renderCorrelation(); break;
    case 'fraud': renderFraudDetection(); break;
    case 'threats': renderCyberThreats(); break;
    case 'quantum': renderQuantumRisk(); break;
    case 'explainable-ai': renderExplainableAI(); break;
    case 'analytics': renderAnalytics(); break;
    case 'reports': renderReports(); break;
    case 'settings': renderSettings(); break;
    default: content.innerHTML = `<div class="page-header"><h1 class="page-title">Coming Soon</h1></div>`;
  }
}

function destroyCharts() {
  Object.values(charts).forEach(c => c?.destroy?.());
  charts = {};
  if (graphNetwork) { graphNetwork.destroy(); graphNetwork = null; }
}

// ══════════════════════════════════════════════════════════════════════════
//  DASHBOARD
// ══════════════════════════════════════════════════════════════════════════
function renderDashboard() {
  const k = liveData.kpis;
  const content = $('#page-content');
  if (!content.querySelector('.kpi-grid')) {
    content.innerHTML = `
      <div class="page-header">
        <h1 class="page-title">Dashboard</h1>
        <p class="page-sub">Real-time overview of financial security posture</p>
      </div>
      <div class="kpi-grid" id="kpi-grid"></div>
      <div class="grid-2" style="gap:16px;margin-top:0">
        <div class="card" id="dashboard-feed-card">
          <div class="card-header"><span class="card-icon">⚡</span><span class="card-title">Live Cyber-Telemetry Feed</span></div>
          <div class="card-body"><div class="feed-list" id="dash-feed"></div></div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-icon">🤖</span><span class="card-title">AI Model Status</span></div>
          <div class="card-body"><div class="model-cards" id="model-cards"></div></div>
        </div>
      </div>`;
    loadModelCards();
  }

  // KPI grid
  const kpiDefs = [
    { label: 'Transactions Processed', value: fmt(k.total_transactions ?? 0), sub: 'All scored by AI', color: 'blue', pulse: false },
    { label: 'Cyber Security Events', value: fmt(k.cyber_events ?? 0), sub: 'Logins, SIM swaps, transfers', color: 'cyan', pulse: false },
    { label: 'High Risk Alerts', value: fmt(k.high_risk_alerts ?? 0), sub: 'Requires immediate action', color: 'red', pulse: true },
    { label: 'False Positives Avoided', value: fmt(k.false_positives_avoided ?? 0), sub: 'Correlation saved legit txns', color: 'green', pulse: false },
    { label: 'Sequence Threats Blocked', value: fmt(k.sequence_threats_blocked ?? 0), sub: 'Proactive detection', color: 'purple', pulse: false },
    { label: 'HNDL Risks Flagged', value: fmt(k.hndl_risks ?? 0), sub: 'Quantum harvest threats', color: 'amber', pulse: false },
  ];
  const grid = $('#kpi-grid');
  if (grid) {
    grid.innerHTML = kpiDefs.map(d => `
      <div class="kpi-card ${d.color}">
        ${d.pulse ? '<div class="kpi-pulse"></div>' : ''}
        <div class="kpi-label">${d.label}</div>
        <div class="kpi-value">${d.value}</div>
        <div class="kpi-sub">${d.sub}</div>
      </div>`).join('');
  }

  // Feed
  const feed = $('#dash-feed');
  if (feed) renderFeedList(feed, liveData.feed.slice(0, 14));
}

async function loadModelCards() {
  const data = await api('/api/ai-models');
  const container = $('#model-cards');
  if (!container || !data) return;
  container.innerHTML = data.map(m => `
    <div class="model-card">
      <div class="model-running">
        <div class="pulse-dot"></div>
        <span class="model-status-label">Running</span>
      </div>
      <div class="model-name">${m.name}</div>
      <div class="model-type">${m.type}</div>
      <div class="model-stats">
        <div class="model-stat"><span class="model-stat-label">Accuracy</span><span class="model-stat-val green">${m.accuracy}%</span></div>
        <div class="model-stat"><span class="model-stat-label">Latency</span><span class="model-stat-val cyan">${m.latency_ms}ms</span></div>
      </div>
    </div>`).join('');
}

// ══════════════════════════════════════════════════════════════════════════
//  LIVE MONITORING
// ══════════════════════════════════════════════════════════════════════════
function renderLiveMonitoring() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Live Monitoring</h1>
      <p class="page-sub">Real-time transaction interception & correlated threat analysis</p>
    </div>
    <div class="grid-2" style="gap:16px">
      <div class="card">
        <div class="card-header">
          <span class="card-icon">⚡</span>
          <span class="card-title">Live Data Stream</span>
          <span class="spinner" style="margin-left:auto"></span>
        </div>
        <div class="card-body"><div class="feed-list" id="live-feed-list"></div></div>
      </div>
      <div class="card" style="grid-column:span 1">
        <div class="card-header">
          <span class="card-icon">🎯</span>
          <span class="card-title">Real-Time Transaction Interception</span>
          <span id="ml-badge" class="badge badge-amber" style="margin-left:auto;font-size:9px">Detecting ML Engine...</span>
        </div>
        <div class="card-body">
          <p style="font-size:11px;color:var(--text-muted);margin-bottom:14px">Select a scenario to trigger the AI correlation engine live</p>
          <div class="scenario-grid">
            <button class="scenario-btn safe" id="btn-safe" onclick="triggerScenario('safe_transaction')">
              <div class="scenario-title safe">✅ Simulate Safe Transaction</div>
              <div class="scenario-desc">Normal transaction, no accompanying security signals</div>
            </button>
            <button class="scenario-btn fraud" id="btn-fraud" onclick="triggerScenario('attack_chain')">
              <div class="scenario-title fraud">🚨 Simulate SIM-Swap Fraud</div>
              <div class="scenario-desc">Transaction preceded by SIM-swap + new device event</div>
            </button>
            <button class="scenario-btn legit" id="btn-legit" onclick="triggerScenario('legitimate_large')">
              <div class="scenario-title legit">🛡️ Large-But-Legitimate</div>
              <div class="scenario-desc">Big amount, zero security signals — avoids false positive</div>
            </button>
          </div>
          <div id="interception-panel">
            <div class="interception-idle">Select a scenario above to begin the demo</div>
          </div>
        </div>
      </div>
    </div>`;
  
  refreshLiveFeed();
  checkMLBadge();
}
window.triggerScenario = triggerScenario;

async function checkMLBadge() {
  const badge = $('#ml-badge');
  if (!badge) return;
  try {
    const r = await fetch(`${API}/`, { signal: AbortSignal.timeout(2000) });
    if (r.ok) { badge.className = 'badge badge-green'; badge.style.marginLeft='auto'; badge.textContent = '🟢 FastAPI ML Engine Active'; }
  } catch {
    badge.className = 'badge badge-amber'; badge.textContent = '🟡 Simulated Fallback';
  }
}

function refreshLiveFeed() {
  const el = $('#live-feed-list');
  if (el) renderFeedList(el, liveData.feed.slice(0, 20));
}

function renderFeedList(container, events) {
  if (!events?.length) { container.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:20px 0">No events yet...</div>`; return; }
  container.innerHTML = events.map(e => {
    const type = e.event_type?.toUpperCase() ?? 'EVENT';
    const riskMap = { transaction: 'medium', login: 'low', sim_swap: 'critical', data_transfer: 'high' };
    const risk = riskMap[e.event_type] ?? 'low';
    const msg = buildFeedMsg(e);
    return `<div class="feed-item">
      <div class="feed-dot ${risk}"></div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px">
          ${eventTypeBadge(type)}
          <span class="feed-time">${fmtTime(e.timestamp)}</span>
        </div>
        <div class="feed-msg">${msg}</div>
      </div>
    </div>`;
  }).join('');
}

function buildFeedMsg(e) {
  switch (e.event_type) {
    case 'login': return `${e.user} — ${e.success ? '✅ Login' : '❌ Failed Login'} — ${e.ip_address} (${e.location || '?'}) — ${e.device_id}`;
    case 'transaction': return `${e.user} — Transfer ${fmtAmt(e.amount)} → ${e.destination_account} ${e.is_new_beneficiary ? '⚠ New Beneficiary' : ''}`;
    case 'sim_swap': return `SIM Swap — ${e.user} ${e.flagged ? '🚨 FLAGGED' : '— Normal'}`;
    case 'data_transfer': return `Data Transfer — ${e.system_name || '?'} → ${e.destination_ip} — ${((e.bytes_transferred || 0) / 1e9).toFixed(1)} GB`;
    default: return JSON.stringify(e).slice(0, 80);
  }
}

async function triggerScenario(scenario) {
  if (interceptionState.phase !== 'idle') return;
  
  // Disable all buttons
  $$('.scenario-btn').forEach(b => { b.disabled = true; });
  interceptionState.phase = 'running';

  const panel = $('#interception-panel');
  if (!panel) return;

  // Phase 1: PENDING
  panel.innerHTML = `
    <div class="interception-pending">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <div class="spinner"></div>
        <div>
          <div style="font-size:13px;font-weight:600;color:#fff">Verifying transaction...</div>
          <div style="font-size:11px;color:var(--text-muted)">Computing raw anomaly score</div>
        </div>
      </div>
      <div class="progress-bar"><div class="progress-fill" style="width:30%"></div></div>
    </div>`;

  await sleep(1000);

  // Animate analyzing
  panel.querySelector('.progress-fill').style.width = '60%';
  panel.querySelector('div[style*="font-size:13"]').textContent = 'Running AI correlation engine...';
  panel.querySelector('div[style*="font-size:11"]').textContent = 'Cross-referencing security domain signals';

  await sleep(800);

  // Call real backend
  let result = null;
  try {
    const resp = await fetch(`${API}/api/score-transaction`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: 'USR-338', scenario:
        scenario === 'safe_transaction' ? 'safe' :
        scenario === 'attack_chain' ? 'sim_swap_fraud' : 'large_legit' })
    });
    if (resp.ok) result = await resp.json();
  } catch (e) {
    console.warn('Backend scoring failed, using fallback');
  }

  // Fallback
  if (!result) {
    const fallbacks = {
      safe_transaction: { raw_score: 0.21, correlated_score: 0.18, status: 'low', adjustment_reason: 'No anomalies detected. All security signals nominal.', transaction: { amount: 12000, user: 'USR-338' } },
      attack_chain: { raw_score: 0.48, correlated_score: 0.91, status: 'high', adjustment_reason: 'Raw score: Medium → Correlated: High — SIM swap detected 12 min ago, new device registered.', transaction: { amount: 85000, user: 'USR-338' } },
      legitimate_large: { raw_score: 0.62, correlated_score: 0.24, status: 'low', adjustment_reason: 'Raw score: Medium (large amount) → Correlated: Low (no security signals found) → Released. False positive avoided.', transaction: { amount: 250000, user: 'USR-338' } },
    };
    result = fallbacks[scenario];
  }

  // Phase 2: Score reveal
  panel.innerHTML = `
    <div class="interception-scores">
      <div style="font-size:12px;font-weight:600;color:var(--purple);margin-bottom:14px">⚙ AI Scoring Analysis</div>
      <div class="grid-2">
        <div>
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:8px">Raw Anomaly Score</div>
          <div class="score-bar-wrap">
            <div class="score-bar-label">
              <span>Transaction data alone — ${scoreLabel(result.raw_score)}</span>
              <span style="color:var(--amber);font-weight:700">${fmtScore(result.raw_score)}</span>
            </div>
            <div class="score-bar-track">
              <div class="score-bar-fill" style="width:${result.raw_score * 100}%;background:${scoreColor(result.raw_score)}"></div>
            </div>
          </div>
        </div>
        <div>
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted);margin-bottom:8px">Correlated Score</div>
          <div class="score-bar-wrap">
            <div class="score-bar-label">
              <span>Adjusted for security signals — ${scoreLabel(result.correlated_score)}</span>
              <span style="font-weight:700;color:${scoreColor(result.correlated_score)}">${fmtScore(result.correlated_score)}</span>
            </div>
            <div class="score-bar-track">
              <div class="score-bar-fill" style="width:${result.correlated_score * 100}%;background:${scoreColor(result.correlated_score)}"></div>
            </div>
          </div>
        </div>
      </div>
      <div class="progress-bar" style="margin-top:16px"><div class="progress-fill" style="width:100%;background:linear-gradient(90deg,var(--purple),var(--cyan))"></div></div>
    </div>`;

  await sleep(1300);

  // Phase 3: Outcome
  const outcome = result.status === 'high' ? 'held' : result.status === 'medium' ? 'step-up' : 'released';
  const outcomeCfg = {
    released: { icon: '✅', title: 'Transaction Successful', cls: 'released' },
    held:     { icon: '🚫', title: 'Transaction Held', cls: 'held' },
    'step-up':{ icon: '🔑', title: 'Verify to Continue', cls: 'step-up' },
  }[outcome];

  const amount = result.transaction?.amount ?? 0;
  panel.innerHTML = `
    <div class="interception-outcome ${outcomeCfg.cls}">
      <div class="outcome-icon">${outcomeCfg.icon}</div>
      <div class="outcome-title" style="color:${outcome==='released'?'var(--green)':outcome==='held'?'var(--red)':'var(--amber)'}">${outcomeCfg.title}</div>
      <div class="outcome-reason">${result.adjustment_reason || result.explanation || ''}</div>
      <div class="tx-meta-grid">
        <div class="tx-meta-box"><div class="tx-meta-label">Amount</div><div class="tx-meta-value">${fmtAmt(amount)}</div></div>
        <div class="tx-meta-box"><div class="tx-meta-label">Raw → Correlated</div><div class="tx-meta-value">${scoreLabel(result.raw_score)} → ${scoreLabel(result.correlated_score)}</div></div>
        <div class="tx-meta-box"><div class="tx-meta-label">User</div><div class="tx-meta-value">${result.transaction?.user ?? 'USR-338'}</div></div>
      </div>
      ${outcome === 'step-up' ? `
        <div class="otp-panel">
          <div class="otp-label">Enter OTP sent to registered mobile</div>
          <div class="otp-hint">Demo OTP: <code style="color:#fff;font-weight:700">847291</code></div>
          <div class="otp-row">
            <input class="otp-input" id="otp-input" type="text" maxlength="6" placeholder="6-digit OTP">
            <button class="btn btn-amber" onclick="confirmOTP()">Confirm</button>
          </div>
        </div>` : ''}
      <div class="action-row">
        <button class="btn btn-ghost" onclick="resetInterception()">↺ Reset / Run Another</button>
        ${outcome === 'held' ? `<button class="btn btn-red" onclick="goToPage('fraud')">View Alerts</button>` : ''}
      </div>
    </div>`;

  interceptionState.phase = 'idle';

  // Re-fetch to update KPIs
  const [kpis, feed] = await Promise.all([api('/api/kpis'), api('/api/live-feed?limit=35')]);
  if (kpis) liveData.kpis = kpis;
  if (feed) liveData.feed = feed;
  refreshLiveFeed();
}

window.confirmOTP = function() {
  const v = $('#otp-input').value;
  if (v === '847291') {
    $('#otp-input').parentElement.parentElement.innerHTML = `<div style="color:var(--green);font-size:13px;font-weight:600;margin-top:10px">✅ OTP Verified — Transaction Completed</div>`;
  } else {
    $('#otp-input').style.borderColor = 'var(--red)';
  }
};

window.resetInterception = function() {
  interceptionState.phase = 'idle';
  $$('.scenario-btn').forEach(b => { b.disabled = false; });
  const panel = $('#interception-panel');
  if (panel) panel.innerHTML = `<div class="interception-idle">Select a scenario above to begin the demo</div>`;
};

// ══════════════════════════════════════════════════════════════════════════
//  CORRELATION GRAPH
// ══════════════════════════════════════════════════════════════════════════
async function renderCorrelation() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Correlation Graph</h1>
      <p class="page-sub">Entity relationship graph — suspicious paths highlighted in red</p>
    </div>
    <div class="card" style="margin-bottom:16px">
      <div class="card-header">
        <span class="card-icon">⬡</span>
        <span class="card-title">Network Entity Correlation</span>
        <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
          <label style="font-size:11px;color:var(--text-muted)">Focus:</label>
          <select id="graph-user-select" style="background:var(--bg2);border:1px solid var(--glass-border);color:var(--text);font-size:12px;padding:4px 8px;border-radius:6px;outline:none" onchange="loadGraph()">
            <option value="all">All Users</option>
          </select>
        </div>
      </div>
      <div class="card-body">
        <div id="graph-container"></div>
        <div id="graph-rules" style="margin-top:12px"></div>
      </div>
    </div>`;

  // Load user list
  const users = await api('/api/users');
  const sel = $('#graph-user-select');
  if (users?.users && sel) {
    users.users.forEach(u => {
      const opt = document.createElement('option');
      opt.value = u; opt.textContent = u;
      sel.appendChild(opt);
    });
  }
  liveData.users = users?.users ?? [];
  loadGraph();
}

window.loadGraph = async function() {
  const user = $('#graph-user-select')?.value ?? 'all';
  const data = await api(`/api/graph/${user}`);
  if (!data) return;

  const container = $('#graph-container');
  if (!container) return;

  if (graphNetwork) { graphNetwork.destroy(); graphNetwork = null; }

  const typeColors = {
    User: '#3b82f6', Device: '#6b7280', IP: '#06b6d4',
    SIM: '#d946ef', Transaction: '#10b981', Account: '#eab308'
  };

  const nodes = new vis.DataSet(data.nodes.map(n => ({
    id: n.id,
    label: n.label.length > 14 ? n.label.slice(0, 14) + '…' : n.label,
    color: n.suspicious
      ? { background: '#ef4444', border: '#dc2626', highlight: { background: '#f87171', border: '#ef4444' } }
      : { background: typeColors[n.type] ?? '#94a3b8', border: 'rgba(255,255,255,0.1)' },
    font: { color: '#e2e8f0', size: 11 },
    size: n.suspicious ? 18 : 12,
    borderWidth: n.suspicious ? 2 : 1,
    title: `${n.type}: ${n.label}`
  })));

  const edges = new vis.DataSet(data.edges.map((e, i) => ({
    id: i, from: e.from, to: e.to,
    color: e.suspicious
      ? { color: '#ef4444', opacity: 0.9 }
      : { color: 'rgba(148,163,184,0.2)', opacity: 0.6 },
    width: e.suspicious ? 3 : 1,
    dashes: e.suspicious,
    smooth: { type: 'curvedCW', roundness: 0.15 },
    arrows: { to: { enabled: false } }
  })));

  const options = {
    physics: { barnesHut: { gravitationalConstant: -4000, centralGravity: 0.3, springLength: 120 }, stabilization: { iterations: 150 } },
    interaction: { hover: true, tooltipDelay: 150 },
    layout: { improvedLayout: true },
    nodes: { shape: 'dot', borderWidth: 1 },
    background: 'transparent'
  };

  graphNetwork = new vis.Network(container, { nodes, edges }, options);
  container.style.background = 'rgba(0,0,0,0)';

  // Show rules
  const rulesEl = $('#graph-rules');
  if (rulesEl && data.rules?.length) {
    rulesEl.innerHTML = data.rules.map(r =>
      `<div class="alert-banner danger" style="margin-bottom:6px">
        <div class="alert-banner-title">🚨 Rule Triggered</div>
        <div class="alert-banner-body">${r}</div>
      </div>`).join('');
  } else if (rulesEl) {
    rulesEl.innerHTML = `<div style="color:var(--green);font-size:12px">✅ No suspicious correlation paths detected for selected entity</div>`;
  }
};

// ══════════════════════════════════════════════════════════════════════════
//  FRAUD DETECTION
// ══════════════════════════════════════════════════════════════════════════
function renderFraudDetection() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Fraud Detection</h1>
      <p class="page-sub">Transaction anomaly scoring & correlation alignment</p>
    </div>
    <div class="card" style="margin-bottom:16px">
      <div class="card-header">
        <span class="card-title">Scored Transactions</span>
        <label style="margin-left:auto">
          <input type="checkbox" id="fp-filter" onchange="renderFraudTable()">
          <span style="font-size:11px;color:var(--text-muted);margin-left:4px">Show only FP Avoided</span>
        </label>
      </div>
      <div class="card-body" style="padding-top:0">
        <table class="data-table">
          <thead><tr>
            <th>TXN ID</th><th>User</th><th>Amount</th>
            <th>Raw Score</th><th>Correlated Score</th><th>Status</th><th>Adjustment</th>
          </tr></thead>
          <tbody id="fraud-tbody"></tbody>
        </table>
      </div>
    </div>`;
  renderFraudTable();
}

function renderFraudTable() {
  const tbody = $('#fraud-tbody');
  if (!tbody) return;
  let txns = liveData.fraudTx ?? [];
  const fpFilter = $('#fp-filter')?.checked;
  if (fpFilter) txns = txns.filter(t => (t.raw_score - t.correlated_score) > 0.1);
  
  if (!txns.length) { tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:20px">No transactions scored yet</td></tr>`; return; }

  tbody.innerHTML = txns.map(t => {
    const delta = (t.raw_score - t.correlated_score).toFixed(2);
    return `<tr>
      <td class="mono" style="color:var(--cyan);font-size:11px">${t.transaction_id}</td>
      <td>${t.user}</td>
      <td class="mono">${fmtAmt(t.amount)}</td>
      <td><span style="color:${scoreColor(t.raw_score)};font-weight:700">${fmtScore(t.raw_score)}</span></td>
      <td><span style="color:${scoreColor(t.correlated_score)};font-weight:700">${fmtScore(t.correlated_score)}</span></td>
      <td>${statusBadge(t.status)}</td>
      <td style="max-width:200px;font-size:10px;color:var(--text-muted)">${(t.adjustment_reason || '').slice(0, 60)}${t.adjustment_reason?.length > 60 ? '…' : ''}</td>
    </tr>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════════════════
//  CYBER THREATS
// ══════════════════════════════════════════════════════════════════════════
async function renderCyberThreats() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Cyber Threats</h1>
      <p class="page-sub">Active threat intelligence & attack sequence detection</p>
    </div>
    <div class="grid-2" style="margin-bottom:16px">
      <div class="card">
        <div class="card-header"><span class="card-icon">⚔</span><span class="card-title">Proactive Sequence Alerts</span></div>
        <div class="card-body" id="seq-alerts"></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-icon">⚛</span><span class="card-title">HNDL Risk Alerts</span></div>
        <div class="card-body" id="hndl-alerts"></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-icon">⏱</span><span class="card-title">Threat Timeline — Attack Chain Anatomy</span></div>
      <div class="card-body">
        <div class="timeline" id="timeline"></div>
      </div>
    </div>`;

  // Sequence alerts
  const seq = await api('/api/sequence-alerts');
  const seqEl = $('#seq-alerts');
  if (seqEl) {
    if (!seq?.length) { seqEl.innerHTML = `<div style="color:var(--green);font-size:12px">✅ No active sequence threats</div>`; }
    else {
      seqEl.innerHTML = seq.map(a => `
        <div class="alert-banner danger">
          <div class="alert-banner-title">User: ${a.user} | ${fmtTime(a.timestamp)}</div>
          <div class="alert-banner-body">${a.reason}<br>Target TXN: ${a.transaction_id} — ${fmtAmt(a.amount)}</div>
        </div>`).join('');
    }
  }

  // HNDL alerts
  const hndl = await api('/api/hndl-alerts');
  const hndlEl = $('#hndl-alerts');
  if (hndlEl) {
    if (!hndl?.length) { hndlEl.innerHTML = `<div style="color:var(--green);font-size:12px">✅ No HNDL risks detected</div>`; }
    else {
      hndlEl.innerHTML = hndl.map(a => `
        <div class="alert-banner warning">
          <div class="alert-banner-title">${a.system_name} (${a.algorithm}) — HNDL Risk</div>
          <div class="alert-banner-body">${a.transfer_size_gb} GB transferred to ${a.destination}. Quantum-vulnerable ciphertext at risk of retroactive decryption.</div>
        </div>`).join('');
    }
  }

  // Timeline
  const timelineEl = $('#timeline');
  if (timelineEl) {
    const steps = [
      { label: 'Login Attempt', sub: 'User authenticates from known device', color: 'var(--blue)', border: 'var(--blue)' },
      { label: 'Failed Login Burst', sub: '4–7 failed logins within 5 minutes', color: 'var(--amber)', border: 'var(--amber)' },
      { label: 'SIM Swap Detected', sub: 'Operator-level SIM reassignment flagged', color: 'var(--red)', border: 'var(--red)' },
      { label: 'New Device Login', sub: 'Successful login from foreign IP / new device', color: 'var(--red)', border: 'var(--red)' },
      { label: 'Large Transaction Initiated', sub: 'High-value transfer to new beneficiary', color: 'var(--red)', border: 'var(--red)' },
      { label: 'Fraud Alert Generated', sub: 'AI correlation engine escalates — transaction held', color: 'var(--purple)', border: 'var(--purple)' },
    ];
    timelineEl.innerHTML = steps.map((s, i) => `
      <div class="timeline-item">
        <div class="timeline-line-wrap">
          <div class="timeline-dot" style="background:${s.color};border-color:${s.border}"></div>
          ${i < steps.length - 1 ? '<div class="timeline-line"></div>' : ''}
        </div>
        <div class="timeline-content">
          <div class="timeline-label">${s.label}</div>
          <div class="timeline-sub">${s.sub}</div>
        </div>
      </div>`).join('');
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  QUANTUM RISK
// ══════════════════════════════════════════════════════════════════════════
async function renderQuantumRisk() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Quantum Risk</h1>
      <p class="page-sub">Post-quantum cryptography migration status & HNDL threat monitoring</p>
    </div>
    <div class="card" style="margin-bottom:16px">
      <div class="card-header"><span class="card-icon">⚛</span><span class="card-title">Post-Quantum Migration Progress</span></div>
      <div class="card-body">
        <div class="q-progress">
          <div class="q-progress-label"><span>Overall PQ Migration</span><span style="color:var(--green);font-weight:700" id="q-pct">—</span></div>
          <div class="q-bar"><div class="q-fill" id="q-fill" style="width:0%"></div></div>
        </div>
        <table class="data-table">
          <thead><tr><th>System</th><th>Algorithm</th><th>Migration %</th><th>Quantum Risk</th><th>Description</th></tr></thead>
          <tbody id="q-tbody"></tbody>
        </table>
      </div>
    </div>
    <div class="grid-3">
      <div class="card"><div class="card-header"><span class="card-icon">🔐</span><span class="card-title">Kyber-768/1024</span></div><div class="card-body" style="font-size:12px;color:var(--text-muted)">NIST PQC finalist. Key Encapsulation Mechanism — replaces RSA/ECC for key exchange. Quantum-safe.</div></div>
      <div class="card"><div class="card-header"><span class="card-icon">✍</span><span class="card-title">Dilithium</span></div><div class="card-body" style="font-size:12px;color:var(--text-muted)">NIST PQC standard for digital signatures. Replaces ECDSA. Lattice-based, resistant to Shor's algorithm.</div></div>
      <div class="card"><div class="card-header"><span class="card-icon">🌲</span><span class="card-title">SPHINCS+</span></div><div class="card-body" style="font-size:12px;color:var(--text-muted)">Hash-based signature scheme. Stateless, conservative security assumptions. Ideal for auth services.</div></div>
    </div>`;

  const inv = await api('/api/quantum-inventory');
  if (!inv) return;

  const avgProgress = Math.round(inv.reduce((a, r) => a + (r.migration_progress ?? 0), 0) / inv.length);
  const pct = $('#q-pct'); const fill = $('#q-fill');
  if (pct) pct.textContent = `${avgProgress}%`;
  if (fill) fill.style.width = `${avgProgress}%`;

  const tbody = $('#q-tbody');
  if (tbody) {
    tbody.innerHTML = inv.map(r => {
      const riskBadge = r.quantum_risk === 'High' ? 'badge-red' : r.quantum_risk === 'Medium' ? 'badge-amber' : 'badge-green';
      return `<tr>
        <td style="font-weight:600;color:#fff">${r.system_name}</td>
        <td class="mono" style="color:var(--cyan)">${r.algorithm}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;height:4px;background:rgba(255,255,255,0.05);border-radius:2px;overflow:hidden">
              <div style="width:${r.migration_progress}%;height:100%;background:${r.migration_progress >= 90 ? 'var(--green)' : r.migration_progress >= 50 ? 'var(--amber)' : 'var(--red)'};border-radius:2px"></div>
            </div>
            <span style="font-size:11px;color:var(--text-dim);white-space:nowrap">${r.migration_progress}%</span>
          </div>
        </td>
        <td><span class="badge ${riskBadge}">${r.quantum_risk}</span></td>
        <td style="font-size:10px;color:var(--text-muted);max-width:200px">${(r.description || '').slice(0, 70)}</td>
      </tr>`;
    }).join('');
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  EXPLAINABLE AI
// ══════════════════════════════════════════════════════════════════════════
async function renderExplainableAI() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Explainable AI</h1>
      <p class="page-sub">SHAP-powered threat attribution & decision reasoning</p>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header"><span class="card-icon">🔍</span><span class="card-title">Select Transaction</span></div>
        <div class="card-body">
          <select id="xai-select" style="width:100%;background:var(--bg2);border:1px solid var(--glass-border);color:var(--text);font-size:12px;padding:8px 10px;border-radius:8px;outline:none;margin-bottom:14px" onchange="loadExplanation()">
            <option value="">Select a scored transaction…</option>
          </select>
          <div id="xai-meta"></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-icon">◈</span><span class="card-title">Risk Factor Attribution (SHAP)</span></div>
        <div class="card-body"><div class="shap-list" id="shap-list"></div></div>
      </div>
    </div>
    <div class="card" style="margin-top:16px">
      <div class="card-header"><span class="card-icon">💬</span><span class="card-title">AI Decision Narrative</span></div>
      <div class="card-body" id="xai-narrative" style="font-size:13px;color:var(--text-dim);line-height:1.6">Select a transaction to view AI explanation.</div>
    </div>`;

  // Populate select
  const sel = $('#xai-select');
  if (sel && liveData.fraudTx?.length) {
    liveData.fraudTx.slice(0, 20).forEach(t => {
      const opt = document.createElement('option');
      opt.value = t.transaction_id;
      opt.textContent = `${t.transaction_id} — ${t.user} — ${fmtAmt(t.amount)} — ${t.status.toUpperCase()}`;
      sel.appendChild(opt);
    });
  }
}

window.loadExplanation = function() {
  const txnId = $('#xai-select').value;
  if (!txnId) return;
  const txn = liveData.fraudTx.find(t => t.transaction_id === txnId);
  if (!txn) return;

  // Meta
  const meta = $('#xai-meta');
  if (meta) {
    meta.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        ${[
          ['User', txn.user],
          ['Amount', fmtAmt(txn.amount)],
          ['Raw Score', `<span style="color:${scoreColor(txn.raw_score)};font-weight:700">${fmtScore(txn.raw_score)}</span>`],
          ['Correlated Score', `<span style="color:${scoreColor(txn.correlated_score)};font-weight:700">${fmtScore(txn.correlated_score)}</span>`],
          ['Status', statusBadge(txn.status)],
          ['FP Avoided', txn.raw_score - txn.correlated_score > 0.1 ? '<span style="color:var(--green)">✅ Yes</span>' : '<span style="color:var(--text-muted)">No</span>'],
        ].map(([l,v]) => `<div class="tx-meta-box"><div class="tx-meta-label">${l}</div><div class="tx-meta-value">${v}</div></div>`).join('')}
      </div>`;
  }

  // Generate heuristic SHAP values
  const raw = txn.raw_score, corr = txn.correlated_score;
  const delta = corr - raw;
  let factors = [];
  if (txn.amount > 8000) factors.push({ factor: 'Large Transaction Amount', contribution: +(raw * 0.45).toFixed(2) });
  factors.push({ factor: 'Hour of Day Risk', contribution: +(raw * 0.12).toFixed(2) });
  if (txn.is_new_beneficiary) factors.push({ factor: 'New Beneficiary', contribution: +(raw * 0.18).toFixed(2) });
  if (delta > 0.2) factors.push({ factor: 'SIM Swap Detected', contribution: +(delta * 0.6).toFixed(2) });
  if (delta > 0.1) factors.push({ factor: 'New Device & Foreign IP', contribution: +(delta * 0.4).toFixed(2) });
  if (delta < -0.1) factors.push({ factor: 'Clean Security Profile', contribution: +(delta).toFixed(2) });
  factors.sort((a,b) => Math.abs(b.contribution) - Math.abs(a.contribution));

  const max = Math.max(...factors.map(f => Math.abs(f.contribution)), 0.01);
  const shap = $('#shap-list');
  if (shap) {
    shap.innerHTML = factors.map(f => {
      const pct = Math.round((Math.abs(f.contribution) / max) * 100);
      const isPos = f.contribution >= 0;
      return `<div class="shap-item">
        <div class="shap-label">
          <span>${f.factor}</span>
          <span style="color:${isPos ? 'var(--red)' : 'var(--green)'};font-weight:700">${isPos ? '+' : ''}${f.contribution}</span>
        </div>
        <div class="shap-bar-track"><div class="shap-bar-fill ${isPos ? 'positive' : 'negative'}" style="width:${pct}%"></div></div>
      </div>`;
    }).join('');
  }

  // Narrative
  const narr = $('#xai-narrative');
  if (narr) {
    narr.textContent = txn.adjustment_reason || 'No narrative available.';
  }

  // Action buttons
  const card = narr?.closest('.card');
  if (card) {
    const existing = card.querySelector('.action-row');
    if (!existing) {
      const row = document.createElement('div');
      row.className = 'action-row';
      row.style.padding = '0 16px 16px';
      row.innerHTML = `
        <button class="btn btn-green" onclick="alert('Transaction approved.')">✅ Approve</button>
        <button class="btn btn-amber" onclick="alert('Step-Up Auth requested.')">🔑 Step-Up MFA</button>
        <button class="btn btn-red" onclick="alert('Transaction blocked.')">🚫 Block</button>
        <button class="btn btn-ghost" onclick="alert('Escalated to SecOps.')">⚡ Escalate</button>`;
      card.appendChild(row);
    }
  }
};

// ══════════════════════════════════════════════════════════════════════════
//  ANALYTICS
// ══════════════════════════════════════════════════════════════════════════
function renderAnalytics() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Analytics</h1>
      <p class="page-sub">Transaction intelligence, fraud trends, and AI performance metrics</p>
    </div>
    <div class="chart-grid" style="margin-bottom:16px">
      <div class="card chart-wrap">
        <div class="chart-title">Transaction Volume (Weekly)</div>
        <canvas id="chart-volume"></canvas>
      </div>
      <div class="card chart-wrap">
        <div class="chart-title">Fraud Trend (6 Months)</div>
        <canvas id="chart-fraud"></canvas>
      </div>
      <div class="card chart-wrap">
        <div class="chart-title">Attack Categories</div>
        <canvas id="chart-attack"></canvas>
      </div>
      <div class="card chart-wrap">
        <div class="chart-title">False Positive Reduction (%)</div>
        <canvas id="chart-fp"></canvas>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-icon">🤖</span><span class="card-title">AI Model Status</span></div>
      <div class="card-body"><div class="model-cards" id="analytics-models"></div></div>
    </div>`;

  const days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  const months = ['Jan','Feb','Mar','Apr','May','Jun'];
  const rnd = (a,b) => Math.floor(Math.random()*(b-a)+a);
  const chartDefaults = { responsive: true, plugins: { legend: { labels: { color: '#64748b', font: { size: 11 } } } } };

  // Volume chart
  charts.volume = new Chart($('#chart-volume'), {
    type: 'line',
    data: {
      labels: days,
      datasets: [
        { label: 'Transactions', data: days.map(() => rnd(200,900)), borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,0.08)', fill: true, tension: 0.4 },
        { label: 'Fraud', data: days.map(() => rnd(2,25)), borderColor: '#ef4444', backgroundColor: 'transparent', borderDash: [4,3], tension: 0.4 },
      ]
    },
    options: { ...chartDefaults, scales: { x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.03)' } }, y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.03)' } } } }
  });

  // Fraud bar chart
  charts.fraud = new Chart($('#chart-fraud'), {
    type: 'bar',
    data: {
      labels: months,
      datasets: [
        { label: 'Detected', data: months.map(() => rnd(10,60)), backgroundColor: 'rgba(239,68,68,0.65)', borderRadius: 4 },
        { label: 'Blocked', data: months.map(() => rnd(8,55)), backgroundColor: 'rgba(16,185,129,0.65)', borderRadius: 4 },
      ]
    },
    options: { ...chartDefaults, scales: { x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.03)' } }, y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.03)' } } } }
  });

  // Attack pie
  charts.attack = new Chart($('#chart-attack'), {
    type: 'doughnut',
    data: {
      labels: ['SIM Swap','Brute Force','Phishing','Data Exfil','Malware'],
      datasets: [{ data: [31,22,18,16,13], backgroundColor: ['#ef4444','#f97316','#eab308','#8b5cf6','#06b6d4'], borderWidth: 0 }]
    },
    options: { ...chartDefaults, cutout: '60%' }
  });

  // FP reduction line
  charts.fp = new Chart($('#chart-fp'), {
    type: 'line',
    data: {
      labels: months,
      datasets: [{ label: 'FP Rate %', data: months.map((_, i) => Math.max(5, 48 - i * 7 + rnd(-3,3)), 0), borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.08)', fill: true, tension: 0.4, pointRadius: 4 }]
    },
    options: { ...chartDefaults, scales: { x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.03)' } }, y: { min: 0, max: 60, ticks: { color: '#64748b', callback: v => v + '%' }, grid: { color: 'rgba(255,255,255,0.03)' } } } }
  });

  loadModelCards_analytics();
}

async function loadModelCards_analytics() {
  const data = await api('/api/ai-models');
  const container = $('#analytics-models');
  if (!container || !data) return;
  container.innerHTML = data.map(m => `
    <div class="model-card">
      <div class="model-running"><div class="pulse-dot"></div><span class="model-status-label">Running</span></div>
      <div class="model-name">${m.name}</div>
      <div class="model-type">${m.type}</div>
      <div class="model-stats">
        <div class="model-stat"><span class="model-stat-label">Accuracy</span><span class="model-stat-val green">${m.accuracy}%</span></div>
        <div class="model-stat"><span class="model-stat-label">Latency</span><span class="model-stat-val cyan">${m.latency_ms}ms</span></div>
      </div>
    </div>`).join('');
}

// ══════════════════════════════════════════════════════════════════════════
//  REPORTS
// ══════════════════════════════════════════════════════════════════════════
function renderReports() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Reports</h1>
      <p class="page-sub">Compliance, fraud, and threat reports for audit and review</p>
    </div>
    <div class="report-cards">
      ${[
        { icon: '📊', title: 'Daily Fraud Report', desc: 'Comprehensive summary of all transactions scored, alerts raised, and false positives avoided in the past 24 hours.', fmts: ['PDF','CSV'] },
        { icon: '📈', title: 'Weekly Threat Report', desc: 'Analysis of attack chains, SIM-swap events, brute-force attempts, and sequence threats over the past 7 days.', fmts: ['PDF','Excel'] },
        { icon: '📅', title: 'Monthly Risk Analysis', desc: 'Risk posture evolution, false positive trends, quantum migration progress, and model accuracy benchmarks.', fmts: ['PDF','Excel','CSV'] },
        { icon: '⚛', title: 'Quantum Vulnerability Report', desc: 'Detailed HNDL risk exposure, encryption inventory status, and post-quantum migration roadmap.', fmts: ['PDF'] },
        { icon: '🛡', title: 'Compliance Audit Report', desc: 'Full audit trail of all high-risk decisions, analyst actions, escalations, and system approvals.', fmts: ['PDF','CSV'] },
        { icon: '🤖', title: 'AI Model Performance Report', desc: 'Isolation Forest accuracy drift, SHAP stability analysis, and explainability confidence metrics.', fmts: ['PDF','Excel'] },
      ].map(r => `
        <div class="report-card">
          <div class="report-icon">${r.icon}</div>
          <div class="report-title">${r.title}</div>
          <div class="report-desc">${r.desc}</div>
          <div class="report-btns">${r.fmts.map(f => `<button class="btn btn-ghost" onclick="alert('Export as ${f} — demo only')">⬇ ${f}</button>`).join('')}</div>
        </div>`).join('')}
    </div>`;
}

// ══════════════════════════════════════════════════════════════════════════
//  SETTINGS
// ══════════════════════════════════════════════════════════════════════════
function renderSettings() {
  const content = $('#page-content');
  content.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Settings</h1>
      <p class="page-sub">Platform configuration, alert thresholds, and model parameters</p>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header"><span class="card-icon">🔔</span><span class="card-title">Alert Thresholds</span></div>
        <div class="card-body">
          ${[
            ['High Risk Score Threshold', '0.75'],
            ['Step-Up Verification Threshold', '0.50'],
            ['Auto-Block Threshold', '0.90'],
            ['HNDL Transfer Size (GB)', '5.0'],
          ].map(([l,v]) => `<div class="settings-row"><span class="settings-label">${l}</span><input class="settings-input" type="text" value="${v}" /></div>`).join('')}
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-icon">⚙</span><span class="card-title">AI Model Configuration</span></div>
        <div class="card-body">
          ${[
            ['Isolation Forest Contamination', '0.05'],
            ['Sequence Window (min)', '25'],
            ['Correlation Time Window (min)', '30'],
            ['Quantum Scan Frequency (hr)', '6'],
          ].map(([l,v]) => `<div class="settings-row"><span class="settings-label">${l}</span><input class="settings-input" type="text" value="${v}" /></div>`).join('')}
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-icon">👤</span><span class="card-title">User Profile</span></div>
        <div class="card-body">
          ${[['Name','Admin User'],['Role','Security Analyst'],['Department','Fraud Prevention'],['Access Level','Level 3 — Full Access']].map(([l,v]) => `<div class="settings-row"><span class="settings-label">${l}</span><span class="settings-value">${v}</span></div>`).join('')}
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-icon">🔒</span><span class="card-title">Platform Security</span></div>
        <div class="card-body">
          ${[['MFA Enabled','Yes'],['Session Timeout','30 min'],['Audit Logging','Active'],['Data Encryption','AES-256'],['PQ-Safe Auth','SPHINCS+']].map(([l,v]) => `<div class="settings-row"><span class="settings-label">${l}</span><span style="font-size:12px;font-weight:600;color:var(--green)">${v}</span></div>`).join('')}
          <div style="margin-top:12px">
            <button class="btn btn-red" style="font-size:11px" onclick="resetDashboard()">🗑 Clear Dashboard State</button>
          </div>
        </div>
      </div>
    </div>`;
}

window.resetDashboard = async function() {
  if (!confirm('Reset all dashboard data?')) return;
  await api('/api/reset', { method: 'DELETE' });
  liveData = { kpis: {}, feed: [], alerts: [], fraudTx: [], quantum: [], users: [] };
  alert('Dashboard reset. Refreshing...');
  location.reload();
};

// ── Bootstrap ──────────────────────────────────────────────────────────────
async function init() {
  startClock();

  // Navigation
  $$('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => goToPage(btn.dataset.page));
  });

  // Check backend
  await checkBackend();

  // Initial data load
  const [kpis, feed, alerts, fraud] = await Promise.all([
    api('/api/kpis'), api('/api/live-feed?limit=35'),
    api('/api/alerts?limit=12'), api('/api/fraud-transactions?limit=25')
  ]);
  if (kpis) liveData.kpis = kpis;
  if (feed) liveData.feed = feed;
  if (alerts) liveData.alerts = alerts;
  if (fraud) liveData.fraudTx = fraud;

  // Render default page
  renderPage('dashboard');

  // Start live polling every 4 seconds
  pollInterval = setInterval(pollLiveData, 4000);

  // Re-check backend every 15 seconds
  setInterval(checkBackend, 15000);
}

document.addEventListener('DOMContentLoaded', init);
