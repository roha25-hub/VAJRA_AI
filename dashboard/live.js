// Live Flow page: SSE events → glowing dot + node highlights + log.

const NODES = [
  { id: 'nodeAttacker',   cx:  60, label: 'Attacker',   stages: ['boot', 'redteam_try', 'redteam_live', 'redteam_fallback', 'inject'] },
  { id: 'nodePayload',    cx: 290, label: 'Payload',    stages: ['world_ready'] },
  { id: 'nodeMiddleware', cx: 530, label: 'Middleware', stages: ['guardian_decision', 'run_start'] },
  { id: 'nodeLLM',        cx: 770, label: 'Target LLM', stages: ['tool_call'] },
  { id: 'nodeOutput',     cx: 970, label: 'Output',     stages: ['verdict'] },
];
const SEGS = ['segA', 'segB', 'segC', 'segD'];

let eventSrc = null;
let currentNodeIdx = -1;
let steps = 0;
let layersHit = new Set();

function $(id) { return document.getElementById(id); }

function moveDotTo(nodeIdx) {
  if (nodeIdx === currentNodeIdx) return;
  const n = NODES[nodeIdx];
  if (!n) return;
  $('flowDot').setAttribute('cx', n.cx);

  // Light segments up to this node, keep rest dim.
  SEGS.forEach((segId, i) => {
    const el = $(segId);
    if (i < nodeIdx) el.classList.add('hot');
    else el.classList.remove('hot');
  });

  // Node states: previous = done, current = active, future = idle
  NODES.forEach((node, i) => {
    const el = $(node.id);
    el.classList.remove('active', 'done', 'err');
    if (i < nodeIdx) el.classList.add('done');
    if (i === nodeIdx) el.classList.add('active');
  });

  $('currentStage').textContent = n.label;
  currentNodeIdx = nodeIdx;
}

function nodeIdxForStage(stage) {
  for (let i = 0; i < NODES.length; i++) {
    if (NODES[i].stages.includes(stage)) return i;
  }
  return -1;
}

function appendEvent(evt) {
  const log = $('eventLog');
  if (log.firstElementChild && log.firstElementChild.className === 'empty') log.innerHTML = '';
  const ts = (evt.ts || '').slice(11, 19);
  let bodyText;
  const copy = { ...evt };
  delete copy.stage; delete copy.ts;
  try { bodyText = JSON.stringify(copy); } catch { bodyText = String(copy); }

  let cls = 'evt';
  if (evt.stage === 'verdict') cls += evt.success ? ' verdict-win' : ' verdict-block';
  if (evt.stage === 'error')   cls += ' error';

  const row = document.createElement('div');
  row.className = cls;
  row.innerHTML = `<span class="ts">${ts}</span><span class="stage">${evt.stage}</span><span class="body"></span>`;
  row.querySelector('.body').textContent = bodyText;
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
}

// ---- Alert toast + beep ----
function playBeep(freq, dur) {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const g = ctx.createGain();
    osc.type = 'sine'; osc.frequency.value = freq;
    g.gain.value = 0.08;
    osc.connect(g); g.connect(ctx.destination);
    osc.start(); osc.stop(ctx.currentTime + dur);
  } catch {}
}
function showAlert(evt) {
  const host = document.body;
  const el = document.createElement('div');
  el.className = 'vajra-toast ' + (evt.severity === 'breach' ? 'breach' : 'safe');
  const title = evt.severity === 'breach' ? 'BREACH DETECTED' : 'YOU ARE SAFE';
  el.innerHTML = `
    <div class="t">${title}</div>
    <div class="s">${evt.severity === 'breach'
      ? 'Attack succeeded on <b>' + evt.goal + '</b> via <b>' + evt.family + '</b>'
      : 'VAJRA blocked attack on <b>' + evt.goal + '</b> at <b>' + (evt.layer || 'guardian') + '</b>'}</div>
    <button class="x">×</button>`;
  el.querySelector('.x').onclick = () => el.remove();
  host.appendChild(el);
  if (evt.severity === 'breach') {
    playBeep(880, 0.2); setTimeout(() => playBeep(660, 0.3), 220);
    if (window.Notification && Notification.permission === 'granted') {
      new Notification('VAJRA BREACH', { body: evt.goal + ' / ' + evt.family });
    }
  } else {
    playBeep(520, 0.12);
  }
  setTimeout(() => el.remove(), evt.severity === 'breach' ? 15000 : 6000);
}

// Specialist name -> DOM id for sub-node + its link
const SPEC_MAP = {
  'PaymentGuardian': { node: 'specPayment', link: 'specLinkPay'  },
  'EmailGuardian':   { node: 'specEmail',   link: 'specLinkMail' },
  'FileGuardian':    { node: 'specFile',    link: 'specLinkFile' },
  'BrowserGuardian': { node: 'specBrowser', link: 'specLinkWeb'  },
};
function resetSpecialists() {
  Object.values(SPEC_MAP).forEach(({node, link}) => {
    const n = $(node); if (n) n.classList.remove('active','block','allow','abstain');
    const l = $(link); if (l) l.classList.remove('hot','block','allow');
  });
}
function lightSpecialist(name, vote) {
  const m = SPEC_MAP[name]; if (!m) return;
  const n = $(m.node); const l = $(m.link);
  if (!n || !l) return;
  n.classList.remove('active','block','allow','abstain');
  l.classList.remove('hot','block','allow');
  if (vote === 'block')   { n.classList.add('block'); l.classList.add('block'); }
  else if (vote === 'allow'){ n.classList.add('allow'); l.classList.add('allow'); }
  else                    { n.classList.add('abstain'); l.classList.add('hot'); }
}

function handleEvent(evt) {
  appendEvent(evt);
  if (evt.stage === 'alert') { showAlert(evt); return; }
  if (evt.stage === 'specialist_vote') {
    lightSpecialist(evt.specialist, evt.vote);
    return;
  }
  if (evt.stage === 'tool_call') { resetSpecialists(); }
  const idx = nodeIdxForStage(evt.stage);
  if (idx >= 0) moveDotTo(idx);

  if (evt.stage === 'redteam_live') {
    $('currentStageSub').textContent = 'live LLM payload (fresh)';
    $('currentStageSub').style.color = 'var(--green)';
  }
  if (evt.stage === 'redteam_fallback') {
    $('currentStageSub').textContent = 'fallback → DB payload (' + (evt.reason || '') + ')';
    $('currentStageSub').style.color = 'var(--orange)';
  }
  if (evt.stage === 'inject' && evt.source) {
    const badge = evt.source === 'live_llm' ? 'LIVE LLM' : 'DB FALLBACK';
    $('phaseChip').textContent = badge;
    $('phaseChip').style.color = evt.source === 'live_llm' ? 'var(--green)' : 'var(--orange)';
  }
  if (evt.stage === 'tool_call') {
    steps += 1;
    $('stepsCount').textContent = steps;
  }
  if (evt.stage === 'guardian_decision' && evt.blocked && evt.layer) {
    layersHit.add(evt.layer);
    $('layersHit').textContent = layersHit.size;
    $('layersBreakdown').textContent = Array.from(layersHit).join(', ');
  }
  if (evt.stage === 'verdict') {
    const vb = $('verdictBox');
    vb.textContent = evt.success ? 'ATTACK WON' : 'BLOCKED';
    vb.style.color = evt.success ? 'var(--red)' : 'var(--green)';
    vb.classList.remove('reveal'); void vb.offsetWidth; vb.classList.add('reveal');
    $('verdictRules').textContent = (evt.rules_fired || []).join(', ') || '(no judge rule fired)';
    moveDotTo(NODES.length - 1);
    NODES.forEach((_, i) => {
      $(NODES[i].id).classList.remove('active');
      $(NODES[i].id).classList.add('done');
    });
    SEGS.forEach(s => $(s).classList.add('hot'));
    $('phaseChip').textContent = evt.success ? 'ATTACK WON' : 'BLOCKED';
    $('phaseChip').style.background = evt.success
      ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)';
    $('phaseChip').style.color = evt.success ? 'var(--red)' : 'var(--green)';
    $('phaseChip').style.borderColor = evt.success
      ? 'rgba(239,68,68,0.35)' : 'rgba(34,197,94,0.35)';
  }
  if (evt.stage === 'error') {
    NODES.forEach((_, i) => {
      if (i === currentNodeIdx) $(NODES[i].id).classList.add('err');
    });
    $('phaseChip').textContent = 'ERROR';
    $('phaseChip').style.color = 'var(--red)';
  }
  if (evt.stage === 'done') {
    stopStream();
  }
}

function resetUI() {
  steps = 0; layersHit = new Set(); currentNodeIdx = -1;
  $('stepsCount').textContent = 0;
  $('layersHit').textContent = 0;
  $('layersBreakdown').textContent = '';
  $('verdictBox').textContent = '—';
  $('verdictBox').style.color = '';
  $('verdictRules').textContent = '';
  $('currentStage').textContent = 'preparing…';
  $('phaseChip').textContent = 'RUNNING';
  $('phaseChip').style.background = 'rgba(59,130,246,0.15)';
  $('phaseChip').style.color = 'var(--cyan)';
  $('phaseChip').style.borderColor = 'rgba(59,130,246,0.35)';
  $('eventLog').innerHTML = '';
  NODES.forEach(n => $(n.id).classList.remove('active', 'done', 'err'));
  SEGS.forEach(s => $(s).classList.remove('hot'));
  $('flowDot').setAttribute('cx', NODES[0].cx);
  moveDotTo(0);
  // Fade/flash the stage so the viewer sees the run begin
  const stage = document.querySelector('.live-stage');
  if (stage) {
    stage.classList.remove('running');
    void stage.offsetWidth; // restart animation
    stage.classList.add('running');
  }
}

function stopStream() {
  if (eventSrc) { eventSrc.close(); eventSrc = null; }
  $('runBtn').disabled = false;
  $('stopBtn').disabled = true;
}

async function start() {
  const atk = $('atkPicker').value;
  const mode = $('modePicker').value;
  if (!atk) return;
  resetUI();
  $('runBtn').disabled = true;
  $('stopBtn').disabled = false;

  const url = `/api/live/attack?attack_id=${encodeURIComponent(atk)}&mode=${encodeURIComponent(mode)}`;
  eventSrc = new EventSource(url);
  eventSrc.onmessage = (e) => {
    try { handleEvent(JSON.parse(e.data)); }
    catch { /* ignore keep-alives */ }
  };
  eventSrc.onerror = () => {
    appendEvent({ stage: 'error', msg: 'stream disconnected', ts: new Date().toISOString() });
    stopStream();
  };
}

async function loadAttacks() {
  const r = await fetch('/api/live/sample-attacks?limit=15');
  const rows = await r.json();
  const sel = $('atkPicker');
  sel.innerHTML = '';
  for (const a of rows) {
    const label = `${a.attack_id} · ${a.family} · ${a.goal}`;
    const opt = document.createElement('option');
    opt.value = a.attack_id;
    opt.textContent = label;
    sel.appendChild(opt);
  }
}

$('runBtn').onclick = start;
$('stopBtn').onclick = stopStream;

// Theme toggle
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

loadAttacks().then(() => moveDotTo(0));

// Reveal specialist layer only when server is running GUARDIAN_MODE=multi
(async () => {
  try {
    const info = await fetch('/api/guardian/mode').then(r => r.json());
    const chip = $('guardianModeChip');
    if (chip) {
      chip.textContent = 'guardian: ' + info.guardian_mode;
      chip.style.color = info.guardian_mode === 'multi' ? 'var(--cyan)' : 'var(--muted)';
      chip.style.borderColor = info.guardian_mode === 'multi'
        ? 'rgba(34,211,238,0.4)' : 'var(--border)';
    }
    if (info.guardian_mode === 'multi') {
      const sl = $('specialistLayer');
      if (sl) sl.style.display = 'block';
      const sub = $('middlewareSub');
      if (sub) sub.textContent = '5 layers + 4 agents';
    }
  } catch {}
})();

// Ask for native notifications (user prompt, no harm if denied)
if (window.Notification && Notification.permission === 'default') {
  try { Notification.requestPermission(); } catch {}
}

// Sidebar unread dot
(async () => {
  try {
    const list = await fetch('/api/notifications?limit=100').then(r => r.json());
    const seen = parseInt(localStorage.getItem('vajra-notif-seen') || '0', 10);
    const dot = document.getElementById('navUnread');
    if (dot) dot.style.display = (list.length > seen) ? 'inline-block' : 'none';
  } catch {}
})();
