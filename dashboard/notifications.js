// Notifications page
const $ = id => document.getElementById(id);
let allRows = [];
let filterMode = 'all';

function fmtTs(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleString();
}

function render() {
  const list = $('notifList');
  const rows = allRows.filter(r => filterMode === 'all' || r.severity === filterMode);
  if (!rows.length) {
    list.innerHTML = '<div class="empty">No notifications match this filter.</div>';
    return;
  }
  list.innerHTML = '';
  for (const r of rows) {
    const sev = r.severity;
    const el = document.createElement('div');
    el.className = 'notif ' + sev;
    const title = sev === 'breach' ? 'BREACH' : 'BLOCKED';
    const msg = sev === 'breach'
      ? `Attack <b>won</b> on <b>${r.goal}</b> using <b>${r.family}</b> (mode: ${r.defense_mode})`
      : `VAJRA blocked attack on <b>${r.goal}</b> at <b>${r.layer || 'guardian'}</b> (mode: ${r.defense_mode})`;
    const fp = r.fingerprint ? `<span style="color:var(--cyan)">#${r.fingerprint}</span>` : '';
    const preview = r.payload_preview
      ? `<div class="prev">${(r.payload_preview || '').replace(/</g,'&lt;').slice(0, 120)}…</div>` : '';
    // Attribution chip (zero-LLM TF-IDF label)
    let attrChip = '';
    if (r.attribution && r.attribution.pattern && r.attribution.pattern !== 'unknown') {
      const sev = r.attribution.severity || 'low';
      attrChip = `<span class="attr-chip sev-${sev}" title="${r.attribution.family} · conf ${r.attribution.confidence}">${r.attribution.label}</span>`;
    } else if (r.attribution) {
      attrChip = `<span class="attr-chip sev-low">Unknown pattern</span>`;
    }
    el.innerHTML = `
      <div class="pulse"></div>
      <span class="tag">${title}</span>
      <div class="msg">${msg} ${attrChip}${preview}</div>
      <div class="meta">${r.attack_id}<br>${r.generated_by} ${fp}</div>
      <div class="ts">${fmtTs(r.ts)}</div>`;
    list.appendChild(el);
  }
}

function renderKpis() {
  const total = allRows.length;
  const breach = allRows.filter(r => r.severity === 'breach').length;
  const safe = total - breach;
  $('kTotal').textContent = total;
  $('kBreach').textContent = breach;
  $('kSafe').textContent = safe;
}

function renderAttrStats(data) {
  const host = $('attrStats');
  if (!host) return;
  const counts = (data && data.counts) || [];
  if (!counts.length) {
    host.innerHTML = '<div class="empty">No classified attacks yet.</div>';
    return;
  }
  const max = Math.max(...counts.map(c => c.count));
  host.innerHTML = counts.map(c => {
    const pct = Math.round(100 * c.count / Math.max(1, max));
    return `<div class="attr-row sev-${c.severity}">
      <div class="attr-head">
        <span class="attr-label">${c.label}</span>
        <span class="attr-fam">${c.family}</span>
        <span class="attr-count">${c.count}</span>
      </div>
      <div class="attr-bar"><div class="attr-bar-fill" style="width:${pct}%"></div></div>
    </div>`;
  }).join('');
}

async function load() {
  try {
    const [rows, status, stats] = await Promise.all([
      fetch('/api/notifications?limit=100').then(r => r.json()),
      fetch('/api/alerts/status').then(r => r.json()).catch(() => ({})),
      fetch('/api/attribution/stats?limit=300').then(r => r.json()).catch(() => ({counts:[]})),
    ]);
    allRows = Array.isArray(rows) ? rows : [];
    render();
    renderKpis();
    renderAttrStats(stats);
    const chan = [];
    if (status.twilio) chan.push('Twilio');
    if (status.elevenlabs) chan.push('ElevenLabs');
    chan.push('Browser');
    $('kChan').textContent = chan.join(' + ');
  } catch (e) {
    $('notifList').innerHTML = `<div class="empty">load failed: ${e}</div>`;
  }
}

$('refreshBtn').onclick = load;
$('filter').onchange = (e) => { filterMode = e.target.value; render(); };
$('markRead').onclick = () => {
  try { localStorage.setItem('vajra-notif-seen', String(allRows.length)); } catch {}
};

// Theme toggle (same as other pages)
function applyTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  const l = $('themeLabel'); if (l) l.textContent = mode === 'light' ? 'Dark' : 'Light';
  try { localStorage.setItem('vajra-theme', mode); } catch {}
}
(function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem('vajra-theme'); } catch {}
  applyTheme(saved || 'dark');
})();
$('themeToggle').onclick = () => {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(cur === 'light' ? 'dark' : 'light');
};

load();
setInterval(load, 5000);
