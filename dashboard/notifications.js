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
    el.innerHTML = `
      <div class="pulse"></div>
      <span class="tag">${title}</span>
      <div class="msg">${msg}${preview}</div>
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

async function load() {
  try {
    const [rows, status] = await Promise.all([
      fetch('/api/notifications?limit=100').then(r => r.json()),
      fetch('/api/alerts/status').then(r => r.json()).catch(() => ({})),
    ]);
    allRows = Array.isArray(rows) ? rows : [];
    render();
    renderKpis();
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
