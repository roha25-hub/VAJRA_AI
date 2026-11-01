// AEGIS dashboard — dark theme, real data from /api/*, Chart.js charts, SVG flow.

const COLORS = {
  no_defense:     '#ef4444',
  keyword_filter: '#f59e0b',
  llm_only:       '#3b82f6',
  full_guardian:  '#22c55e',
  cyan:           '#22d3ee',
  purple:         '#a855f7',
  muted:          '#7b89b3',
  grid:           '#1f2740',
  text:           '#e6ecff',
};

Chart.defaults.color = COLORS.text;
Chart.defaults.borderColor = COLORS.grid;
Chart.defaults.font.family = '-apple-system, Segoe UI, sans-serif';
Chart.defaults.animation = false;
// Prevent runaway canvas growth: never maintain the HTML aspect-ratio for any
// chart; honor the parent container's fixed height instead.
Chart.defaults.responsive = true;
Chart.defaults.maintainAspectRatio = false;

const charts = {};

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path} HTTP ${r.status}`);
  return r.json();
}

function el(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'className') n.className = v;
    else if (k === 'onclick') n.onclick = v;
    else n.setAttribute(k, v);
  }
  for (const c of (Array.isArray(children) ? children : [children])) {
    if (c == null) continue;
    n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return n;
}

function destroyChart(k) { if (charts[k]) { charts[k].destroy(); charts[k] = null; } }

// -------- Top bar --------

function updateDateChip() {
  const d = new Date();
  const date = d.toLocaleDateString(undefined, {month:'short', day:'2-digit', year:'numeric'});
  const time = d.toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
  document.getElementById('dateChip').textContent = `${date}  ${time}`;
}
setInterval(updateDateChip, 10000);

// -------- KPIs + sparklines --------

function renderSpark(id, data, color) {
  destroyChart(id);
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map((_, i) => i),
      datasets: [{
        data,
        borderColor: color,
        backgroundColor: color + '22',
        borderWidth: 1.5,
        pointRadius: 0,
        tension: 0.35,
        fill: true,
      }],
    },
    options: {
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: { x: { display: false }, y: { display: false } },
    },
  });
}

function renderKPIs(summary, scoreboardRows, utilityRows) {
  // Total checks = scoreboard cells + task cells
  const totalChecks = summary.scoreboard_cells + summary.task_cells;
  // Blocked attacks = scoreboard - successes
  const blocked = summary.scoreboard_cells - summary.scoreboard_successes;
  // Pending review (from approvals endpoint, filled later)
  const pending = window._approvalsCount || 0;
  // Guardian catch rate = blocked / scoreboard_cells
  const catchRate = summary.scoreboard_cells
    ? Math.round(100 * blocked / summary.scoreboard_cells)
    : 0;

  document.getElementById('kpi1Val').textContent = totalChecks;
  document.getElementById('kpi2Val').textContent = blocked;
  document.getElementById('kpi3Val').textContent = pending;
  document.getElementById('kpi4Val').textContent = catchRate + '%';

  // Deltas: compare against the previous run if we can; otherwise show the mode spread.
  document.getElementById('kpi1Delta').textContent = `+${scoreboardRows.length} rows`;
  document.getElementById('kpi2Delta').textContent = `${blocked}/${summary.scoreboard_cells}`;
  document.getElementById('kpi3Delta').textContent = pending ? 'needs action' : 'clear';
  document.getElementById('kpi3Delta').className = pending ? 'delta down' : 'delta up';
  document.getElementById('kpi4Delta').textContent = catchRate >= 75 ? 'strong' : 'weak';
  document.getElementById('kpi4Delta').className = catchRate >= 75 ? 'delta up' : 'delta down';

  // Sparklines: derive synthetic series from the per-mode rows (not real time, but shows shape).
  const asrByMode = {};
  for (const r of scoreboardRows) {
    (asrByMode[r.mode] = asrByMode[r.mode] || []).push(r.asr_pct);
  }
  const modes = ['no_defense','keyword_filter','llm_only','full_guardian'];
  const total = modes.map(m => (asrByMode[m] || []).reduce((a,b) => a+b, 0) / Math.max(1, (asrByMode[m]||[]).length));
  renderSpark('spark1', total,                                 COLORS.cyan);
  renderSpark('spark2', total.map(v => 100 - v),               COLORS.no_defense);
  renderSpark('spark3', utilityRows.map(u => u.false_block_pct), COLORS.keyword_filter);
  renderSpark('spark4', total.map(v => 100 - v),               COLORS.purple);
}

// -------- Threat chart (allowed vs blocked per mode) --------

function renderThreatChart(scoreboardRows, utilityRows) {
  destroyChart('threat');
  // Collapse scoreboard rows per mode to attempts and successes.
  const byMode = {};
  for (const r of scoreboardRows) {
    const m = byMode[r.mode] = byMode[r.mode] || { attempts: 0, successes: 0 };
    m.attempts   += r.attempts;
    m.successes  += r.successes;
  }
  const modes = Object.keys(byMode).sort();
  const blocked = modes.map(m => byMode[m].attempts - byMode[m].successes);
  const allowed = modes.map(m => byMode[m].successes);

  // Unread badge: compare total notifications to last-seen count
  (async () => {
    try {
      const list = await fetch('/api/notifications?limit=100').then(r => r.json());
      const seen = parseInt(localStorage.getItem('vajra-notif-seen') || '0', 10);
      const dot = document.getElementById('navUnread');
      if (dot) dot.style.display = (list.length > seen) ? 'inline-block' : 'none';
    } catch {}
  })();

  const labelFor = m => m === 'full_guardian' ? 'full_guardian (VAJRA)' : m + ' (baseline)';
  charts.threat = new Chart(document.getElementById('threatChart'), {
    type: 'bar',
    data: {
      labels: modes.map(labelFor),
      datasets: [
        { label: 'allowed (attack won)', data: allowed, backgroundColor: COLORS.no_defense + 'cc' },
        { label: 'blocked',              data: blocked, backgroundColor: COLORS.cyan + 'cc' },
      ],
    },
    options: {
      plugins: {
        legend: { position: 'top' },
        tooltip: {
          callbacks: {
            afterTitle: (items) => {
              const raw = modes[items[0].dataIndex];
              if (raw === 'full_guardian') return 'This is VAJRA — the 5-layer guardian';
              if (raw === 'no_defense') return 'Control: nothing defending (baseline)';
              return 'Simpler baseline for comparison';
            },
          },
        },
      },
      scales: {
        x: { stacked: true, grid: { color: COLORS.grid } },
        y: { stacked: true, grid: { color: COLORS.grid }, title: { display: true, text: 'attempts' } },
      },
    },
  });
}

// -------- Tradeoff + Improvement curve --------

function renderTradeoff(rows) {
  destroyChart('tradeoff');
  charts.tradeoff = new Chart(document.getElementById('tradeoffChart'), {
    type: 'bubble',
    data: {
      datasets: rows.map(r => ({
        label: r.mode,
        data: [{ x: r.asr_pct, y: r.completion_pct, r: 10 }],
        backgroundColor: (COLORS[r.mode] || COLORS.cyan) + 'cc',
      })),
    },
    options: {
      scales: {
        x: { title: { display:true, text:'ASR % (lower = better)' }, min: 0, max: 100, grid: { color: COLORS.grid } },
        y: { title: { display:true, text:'completion % (higher = better)' }, min: 0, max: 105, grid: { color: COLORS.grid } },
      },
    },
  });
}

function renderCurveChart(points) {
  destroyChart('curve');
  const labels = points.map(p => `r${p.round}·${p.family}`);
  charts.curve = new Chart(document.getElementById('curveChart'), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'ASR %',
        data: points.map(p => p.asr_pct),
        borderColor: COLORS.cyan,
        backgroundColor: COLORS.cyan + '33',
        tension: 0.3,
        pointRadius: 4,
        fill: true,
      }],
    },
    options: { scales: { y: { beginAtZero: true, max: 100, grid: { color: COLORS.grid } } } },
  });
}

// -------- Recent decisions --------

function renderDecisions(attackDetail) {
  const tbody = document.querySelector('#decisionsTbl tbody');
  tbody.innerHTML = '';
  const rows = attackDetail.slice(0, 6);
  if (!rows.length) {
    tbody.appendChild(el('tr', {}, el('td', { colspan: '3' }, el('div', { className: 'empty' }, ['Nothing yet']))));
    return;
  }
  for (const r of rows) {
    const badge = r.success ? 'block' : 'allow'; // from the attacker's POV: "attack won" or "guardian allowed defense"
    // From the DEFENDER's POV it's better framed as: block means the guardian blocked it.
    const defBadge = r.success ? 'block' : 'allow';
    const defLabel = r.success ? 'ATTACK WON' : 'BLOCKED';
    const timeStr = new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    tbody.appendChild(el('tr', {}, [
      el('td', {}, [timeStr]),
      el('td', {}, el('span', { className: `badge ${defBadge === 'allow' ? 'allow' : 'block'}` }, [defLabel])),
      el('td', {}, el('span', { className: 'id-link', onclick: () => showPayload(r.attack_id) }, [`${r.attack_id} · ${r.defense_mode}`])),
    ]));
  }
}

// -------- Flow note --------

function updateFlowNote(summary) {
  const blocked = summary.scoreboard_cells - summary.scoreboard_successes;
  const n = document.getElementById('flowNoteText');
  if (summary.scoreboard_cells === 0) {
    n.textContent = 'Awaiting data — pick a run.';
  } else {
    n.textContent = `Across this run: ${blocked}/${summary.scoreboard_cells} attack attempts blocked by the guardian.`;
  }
}

// -------- Payload modal --------

async function showPayload(attackId) {
  document.getElementById('payloadTitle').textContent = `Attack ${attackId}`;
  document.getElementById('payloadBody').textContent = 'Loading…';
  document.getElementById('payloadModal').classList.remove('hidden');
  try {
    const d = await api(`/api/attack/${encodeURIComponent(attackId)}`);
    const header = `family: ${d.family}\ngoal: ${d.goal}\ninjection_point: ${d.injection_point}\n`
      + `generated_by: ${d.generated_by}  seed: ${d.is_seed}  split: ${d.split}\n--- payload ---\n`;
    document.getElementById('payloadBody').textContent = header + (d.payload || '');
  } catch (e) {
    document.getElementById('payloadBody').textContent = `Error: ${e.message}`;
  }
}

// -------- Detail tables --------

function renderAttackDetail(rows) {
  const box = document.getElementById('atkDetailWrap');
  box.innerHTML = '';
  if (!rows.length) {
    box.appendChild(el('div', { className: 'empty' }, ['No attack rows for this run.']));
    return;
  }
  const t = el('table', { className: 'detail' });
  t.appendChild(el('thead', {}, el('tr', {}, [
    el('th', {}, ['attack_id']), el('th', {}, ['mode']),
    el('th', {}, ['round']), el('th', {}, ['result']), el('th', {}, ['blocked by']),
  ])));
  const tb = el('tbody');
  for (const r of rows) {
    tb.appendChild(el('tr', r.success ? { className: 'bad' } : {}, [
      el('td', {}, el('span', { className: 'id-link', onclick: () => showPayload(r.attack_id) }, [r.attack_id])),
      el('td', {}, [r.defense_mode]),
      el('td', {}, [String(r.round)]),
      el('td', {}, [r.success ? 'ATTACK WON' : 'blocked']),
      el('td', {}, [r.blocked_layer || '—']),
    ]));
  }
  t.appendChild(tb);
  box.appendChild(t);
}

function renderTaskDetail(rows) {
  const box = document.getElementById('taskDetailWrap');
  box.innerHTML = '';
  if (!rows.length) {
    box.appendChild(el('div', { className: 'empty' }, ['No task rows for this run.']));
    return;
  }
  const t = el('table', { className: 'detail' });
  t.appendChild(el('thead', {}, el('tr', {}, [
    el('th', {}, ['task_id']), el('th', {}, ['mode']),
    el('th', {}, ['completed']), el('th', {}, ['false blocks']), el('th', {}, ['latency ms']),
  ])));
  const tb = el('tbody');
  for (const r of rows) {
    tb.appendChild(el('tr', (r.completed === false) ? { className: 'bad' } : {}, [
      el('td', {}, el('code', {}, [r.task_id])),
      el('td', {}, [r.defense_mode]),
      el('td', {}, [r.completed ? 'yes' : 'NO']),
      el('td', {}, [String(r.false_blocks)]),
      el('td', {}, [String(r.latency_ms ?? '—')]),
    ]));
  }
  t.appendChild(tb);
  box.appendChild(t);
}

// -------- Approvals --------

async function resolveApproval(id, decision) {
  const r = await fetch(`/api/approvals/${id}/resolve`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision }),
  });
  if (!r.ok) alert(`Failed: HTTP ${r.status}`);
  await boot();
}

function renderApprovals(rows) {
  window._approvalsCount = rows.length;
  const box = document.getElementById('approvalsBox');
  box.innerHTML = '';
  if (!rows.length) {
    box.appendChild(el('div', { className: 'empty' }, ['None pending.']));
    return;
  }
  const t = el('table', { className: 'detail' });
  t.appendChild(el('thead', {}, el('tr', {}, [
    el('th', {}, ['tool']), el('th', {}, ['args']), el('th', {}, ['reason']), el('th', {}, ['action']),
  ])));
  const tb = el('tbody');
  for (const r of rows) {
    tb.appendChild(el('tr', {}, [
      el('td', {}, el('span', { className: 'badge review' }, [r.tool])),
      el('td', {}, el('code', {}, [JSON.stringify(r.args)])),
      el('td', {}, [r.reason || '']),
      el('td', { className: 'actions' }, [
        el('button', { className: 'btn-allow', onclick: () => resolveApproval(r.id, 'allow') }, ['allow']),
        el('button', { className: 'btn-deny',  onclick: () => resolveApproval(r.id, 'deny') },  ['deny']),
      ]),
    ]));
  }
  t.appendChild(tb);
  box.appendChild(t);
}

function renderAttacks(rows) {
  const box = document.getElementById('attacksBox');
  box.innerHTML = '';
  if (!rows.length) {
    box.appendChild(el('div', { className: 'empty' }, ['No agent-generated attacks yet.']));
    return;
  }
  const t = el('table', { className: 'detail' });
  t.appendChild(el('thead', {}, el('tr', {}, [
    el('th', {}, ['id']), el('th', {}, ['family']), el('th', {}, ['goal']),
    el('th', {}, ['by']), el('th', {}, ['round']),
  ])));
  const tb = el('tbody');
  for (const r of rows) {
    tb.appendChild(el('tr', {}, [
      el('td', {}, el('span', { className: 'id-link', onclick: () => showPayload(r.attack_id) }, [r.attack_id])),
      el('td', {}, [r.family]),
      el('td', {}, [r.goal]),
      el('td', {}, [r.generated_by]),
      el('td', {}, [String(r.round)]),
    ]));
  }
  t.appendChild(tb);
  box.appendChild(t);
}

// -------- Orchestration --------

async function loadRunPicker() {
  const runs = await api('/api/runs?limit=10');
  const sel = document.getElementById('runPicker');
  sel.innerHTML = '';
  if (!runs.length) {
    sel.appendChild(el('option', {}, ['(no runs yet)']));
    return null;
  }
  for (const r of runs) {
    const label = `${r.run_id}  (${(r.started_at || '').slice(0, 16).replace('T', ' ')})`;
    sel.appendChild(el('option', { value: r.run_id }, [label]));
  }
  return runs[0].run_id;
}

async function loadRun(runId) {
  if (!runId) return;
  const [summary, sb, ut, to, curve, apps, atks, atkDetail, taskDetail] = await Promise.all([
    api(`/api/run/${runId}/summary`),
    api(`/api/run/${runId}/scoreboard`),
    api(`/api/run/${runId}/utility`),
    api(`/api/run/${runId}/tradeoff`),
    api(`/api/improvement-curve`),
    api(`/api/approvals`),
    api(`/api/attacks?generated_by=red_agent_v1&limit=20`),
    api(`/api/run/${runId}/attack-detail`),
    api(`/api/run/${runId}/task-detail`),
  ]);

  renderApprovals(apps);  // must run before KPIs so pending count is set
  renderKPIs(summary, sb.rows, ut);
  renderThreatChart(sb.rows, ut);
  renderTradeoff(to);
  renderCurveChart(curve);
  renderDecisions(atkDetail);
  renderAttackDetail(atkDetail);
  renderTaskDetail(taskDetail);
  renderAttacks(atks);
  updateFlowNote(summary);
}

async function boot() {
  updateDateChip();
  try {
    const h = await api('/api/health');
    document.getElementById('apiStatus').textContent = h.ok ? 'System Online' : 'Offline';
  } catch {
    document.getElementById('apiStatus').textContent = 'Offline';
  }
  const first = await loadRunPicker();
  if (first) await loadRun(first);
  document.getElementById('runPicker').onchange = (e) => loadRun(e.target.value);
  document.getElementById('refreshBtn').onclick = () => boot();
}

document.getElementById('payloadClose').onclick = () =>
  document.getElementById('payloadModal').classList.add('hidden');
document.getElementById('payloadModal').onclick = (e) => {
  if (e.target.id === 'payloadModal') e.target.classList.add('hidden');
};

// Nav anchors should scroll smoothly without changing the URL hash, which
// otherwise makes the page jump on every re-render.
for (const a of document.querySelectorAll('.nav a[href^="#"]')) {
  a.addEventListener('click', (ev) => {
    ev.preventDefault();
    const target = document.querySelector(a.getAttribute('href'));
    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

// -------- Theme toggle --------
function applyTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  const label = document.getElementById('themeLabel');
  if (label) label.textContent = mode === 'light' ? 'Dark' : 'Light';
  try { localStorage.setItem('vajra-theme', mode); } catch {}
}
(function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem('vajra-theme'); } catch {}
  applyTheme(saved || 'dark');
})();
const _tt = document.getElementById('themeToggle');
if (_tt) _tt.onclick = () => {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(cur === 'light' ? 'dark' : 'light');
};

boot().catch(e => {
  document.body.insertBefore(
    el('div', { className: 'empty' }, [`Failed to load: ${e.message}`]),
    document.body.firstChild,
  );
});
