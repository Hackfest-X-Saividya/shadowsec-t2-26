/* Dashboard logic. Pasted or uploaded code is analysed locally by analyzer.js (never uploaded, never run).
 * Real execution exists only for the bundled sample: live via server.py, or replayed from a recording
 * when the page is opened as a static demo (window.__DEMO__). */
(function () {
'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const colorFor = n => n >= 80 ? 'var(--red)' : n >= 50 ? 'var(--amber)' : 'var(--green)';
const DEMO = window.__DEMO__ || null;
const SAMPLE_LABEL = 'sample_app/vulnerable.py';

const EXAMPLES = {
  js: {label: 'JavaScript / Express login service', file: 'app.js', code: [
    '// Express login service',
    'function sanitizeInput(text) {', '  return text;', '}',
    'const validateUsername = (name) => true;',
    'function verifyToken(token) {', '  return token !== null && token !== "";', '}',
    'function hashPassword(password) {', '  return crypto.createHash("md5").update(password).digest("hex");', '}',
    'function escapeHtml(s) {', '  return s.replace(/[&<>"\']/g, c => ENTITIES[c]);', '}',
    'app.get("/search", (req, res) => {', '  const term = sanitizeInput(req.query.q);',
    '  res.send(db.query("SELECT * FROM users WHERE name = \'" + term + "\'"));', '});',
    'app.post("/register", (req, res) => {',
    '  res.send(db.query("INSERT INTO credentials VALUES (\'" + hashPassword(req.body.password) + "\')"));', '});', ''].join('\n')},
  java: {label: 'Java authentication class', file: 'Auth.java', code: [
    'public class Auth {', '    /** Escapes input so it is safe for SQL. */',
    '    public static String sanitizeInput(String input) {', '        return input;', '    }',
    '    public boolean verifyToken(String token) {', '        return token != null && !token.isEmpty();', '    }',
    '    public static String hashPassword(String pw) throws Exception {',
    '        MessageDigest md = MessageDigest.getInstance("MD5");', '        return new String(md.digest(pw.getBytes()));', '    }',
    '    public static boolean validateAge(int age) {',
    '        if (age < 0 || age > 130) { throw new IllegalArgumentException("bad age"); }', '        return true;', '    }', '}', ''].join('\n')},
  php: {label: 'PHP login page', file: 'login.php', code: [
    '<?php', 'function sanitize_input($text) {', '    return $text;', '}',
    'function validate_email($email) {', '    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;', '}',
    'function handle_login($username) {', '    $safe = sanitize_input($username);', '    return $safe;', '}', ''].join('\n')},
  go: {label: 'Go token service', file: 'auth.go', code: [
    'package main', '', '// verifyToken checks the session token', 'func verifyToken(token string) bool {', '    return token != ""', '}', '',
    'func hashPassword(pw string) string {', '    sum := md5.Sum([]byte(pw))', '    return hex.EncodeToString(sum[:])', '}', ''].join('\n')},
};

let SAMPLE = DEMO ? DEMO.sample : null;
let serverOK = false, useServer = false, busy = false, state = null, analyzedSource = '', fileName = '';
let client = null;

/* ---------------------------------------------------------------- backend switch */
async function api(path, body) {
  if (useServer) {
    const r = await fetch(path, body === undefined ? {} : {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    return r.json();
  }
  await sleep(120);
  return client.handle(path, body);
}

function setStatus(msg, cls) { const b = $('status'); b.textContent = msg; b.className = 'banner' + (cls ? ' ' + cls : ''); }
function banner(text, cls) { const b = $('banner'); b.textContent = text; b.className = 'banner' + (cls ? ' ' + cls : ''); }

/* ---------------------------------------------------------------- analyze */
async function analyze() {
  const src = $('code').value;
  if (!src.trim()) { setStatus('Paste some code or upload a file first.', 'warn'); return; }
  if (src.indexOf('\u0000') >= 0) { setStatus('That looks like a binary file. Upload source code as text.', 'bad'); return; }
  const isSample = !!SAMPLE && LD.normalize(src) === LD.normalize(SAMPLE);
  const lang = isSample ? 'python' : ($('lang').value === 'auto' ? LD.detectLang(src, fileName) : $('lang').value);
  const label = isSample ? SAMPLE_LABEL : (fileName || 'pasted code');
  setStatus('Analyzing...');
  try {
    if (isSample && serverOK) { useServer = true; await api('/api/reset', {}); }
    else { useServer = false; client.load(src, lang, label); }
  } catch (e) { setStatus(e.message || 'Could not analyze that code.', 'bad'); return; }
  analyzedSource = src;
  clearLab();
  await refresh();
  const info = state.source_info;
  const claiming = state.trust.total;
  if (!claiming) {
    setStatus((info ? info.functions_found + ' functions found' : 'Done') + ', but none claim to be security checks. This tool looks for functions named like sanitize, clean, escape, validate, verify, auth, hash or encrypt.', 'warn');
  } else {
    const lies = state.findings.length;
    setStatus(`${label} (${lang}): ${claiming} security-claiming functions, ${lies} do not do what they claim.` +
      (isSample ? ' Attacks on this sample run for real in the sandbox.' : ' Attacks on this code are predictions, not executions.'), lies ? 'bad' : 'good');
  }
  renderSource(state);
}

/* ---------------------------------------------------------------- render */
async function refresh() { state = await api('/api/scan'); render(); }

function render() {
  const t = state.trust;
  $('target').textContent = state.target + ' · ' + t.total + ' security-claiming functions';
  $('trustNow').textContent = t.total ? t.after + '%' : 'n/a';
  $('trustBefore').textContent = t.total && t.after !== t.before ? '(was ' + t.before + '%)' : '';
  $('meter').style.width = (t.total ? t.after : 0) + '%';
  $('counts').innerHTML = ['Open', 'Fixed', 'Verified'].map(s => `<div class="stat ${s}"><b>${state.counts[s]}</b><span>${s}</span></div>`).join('');
  renderRows(); renderPick(); renderButtons();
}

function renderRows() {
  const fs = $('fStatus').value, fv = $('fSev').value;
  const items = state.findings.map(f => ({...f, kind: 'finding'}))
    .concat(state.honest.map(h => ({...h, kind: 'honest', status: 'Honest', severity: '', owasp: ''})))
    .filter(x => (!fs || x.status === fs) && (!fv || x.severity === fv));
  if (!items.length) {
    $('rows').innerHTML = `<tr><td colspan="10" class="empty">${state.trust.total ? 'No rows match the filters.' : 'No function in this code claims to be a security check. Names containing sanitize, clean, escape, validate, verify, auth, hash or encrypt are checked.'}</td></tr>`;
    return;
  }
  $('rows').innerHTML = items.map(x => {
    const f = x.kind === 'finding';
    let reality = esc(x.reality);
    if (f && x.status !== 'Open') {
      reality = `<s class="sm">${esc(x.reality)}</s><br>` + (x.current_lie_score != null ? `Now: score ${x.current_lie_score}, honest` : 'Reference patch applied, not verified');
    }
    const cls = f && x.status === 'Open' ? 'fix' : f ? '' : 'ok';
    return `<tr class="${cls}">
      <td><b class="mono">${esc(x.name || x.function)}()</b><div class="sm">line ${x.line}${f && x.reachable ? ' · reachable from user input' : ''}</div></td>
      <td class="claim">${esc(x.claim)}</td>
      <td>${reality}</td>
      <td><div class="score"><span>${x.lie_score}</span><span class="bar"><i style="width:${x.lie_score}%;background:${colorFor(x.lie_score)}"></i></span></div></td>
      <td>${f ? `<span class="chip ${esc(x.severity)}" title="${esc(x.cvss_vector)}">${x.cvss_score.toFixed(1)} ${esc(x.severity)}</span>` : ''}</td>
      <td class="sm">${f ? esc(x.exploit_likelihood) : ''}</td>
      <td>${f ? `<span class="chip ${esc(x.priority)}">${esc(x.priority)}</span>` : ''}</td>
      <td class="sm">${esc(x.owasp)}</td>
      <td><span class="chip ${esc(x.status)}">${esc(x.status)}</span></td>
      <td>${f ? `<button class="btn open-lab" type="button" data-id="${esc(x.id)}">Open in Lab</button>` : ''}</td></tr>`;
  }).join('');
}

function renderSource(st) {
  const box = $('src'); box.textContent = '';
  const mark = new Map();
  st.honest.forEach(h => mark.set(h.line, 'honest'));
  st.findings.forEach(f => mark.set(f.line, 'liar'));
  const lines = analyzedSource.replace(/\r\n/g, '\n').split('\n'), cap = 400;
  lines.slice(0, cap).forEach((text, i) => {
    const row = document.createElement('div'); if (mark.has(i + 1)) row.className = mark.get(i + 1);
    const n = document.createElement('b'); n.textContent = String(i + 1);
    const t = document.createElement('span'); t.textContent = text || ' ';
    row.append(n, t); box.appendChild(row);
  });
  if (lines.length > cap) { const m = document.createElement('div'); m.textContent = `... ${lines.length - cap} more lines not shown`; box.appendChild(m); }
  $('srcName').textContent = st.target;
  const lies = st.findings.filter(f => f.status === 'Open').length;
  $('srcFoot').innerHTML = lies ? `<b>${lies}</b> ${lies === 1 ? 'function lies' : 'functions lie'}. Still open.` : (st.trust.total ? '<b class="ok">All security claims hold.</b>' : 'No security claims found.');
  $('srcPanel').hidden = false;
}

function cur() { return state && state.findings.find(f => f.id === $('pick').value); }

function renderPick() {
  const keep = $('pick').value;
  $('pick').innerHTML = state.findings.map(f => `<option value="${esc(f.id)}">${esc(f.function)}() · CVSS ${f.cvss_score.toFixed(1)} · ${esc(f.status)}</option>`).join('');
  if (keep && state.findings.some(f => f.id === keep)) $('pick').value = keep;
  const f = cur();
  $('payload').textContent = f ? f.attack + ': ' + f.payload : 'No findings to attack.';
  renderUsers();
  if (!f) banner(state.trust.total ? 'Nothing to attack: every security-claiming function in this code is honest.' : 'Analyze code that contains security-claiming functions to use the lab.');
}

function renderButtons() {
  const f = cur();
  $('simBtn').disabled = busy || !f;
  $('fixBtn').disabled = busy || !f || f.status !== 'Open' || f.exploit === 'not tested';
  $('mode').textContent = f ? f.mode : '-';
  $('exportBtn').hidden = !!DEMO || !state;
}

function usesUsers() { const f = cur(); return !f || /SQL injection/i.test(f.attack); }

function renderUsers(leaked) {
  leaked = leaked || [];
  const show = usesUsers();
  $('usersTable').hidden = !show;
  $('appHead').textContent = show ? 'The app · users table (fake data)' : 'The app · response';
  const users = (state && state.users) || [];
  $('users').innerHTML = users.map(u => `<tr class="${leaked.includes(u.id) ? 'leak' : ''}"><td>${u.id}</td><td>${esc(u.username)}</td><td>${esc(u.email)}</td></tr>`).join('');
}

async function play(res) {
  $('log').innerHTML = ''; renderUsers(); $('resp').textContent = 'Running...';
  for (const s of res.steps) {
    const d = document.createElement('div'); d.className = s.kind; d.textContent = s.msg;
    $('log').appendChild(d); $('log').scrollTop = 1e6; await sleep(380);
  }
  renderUsers(res.leaked_ids); $('resp').textContent = res.response || '-';
}

function clearLab() {
  $('log').innerHTML = ''; $('patchBox').hidden = true; $('resp').textContent = 'No request yet.';
  banner('Pick a finding and click Simulate Attack.'); renderUsers();
}

function showTab(t) {
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  ['analyze', 'claims', 'lab'].forEach(id => { $(id).hidden = id !== t; });
  $('hero').hidden = t !== 'analyze';
}

/* ---------------------------------------------------------------- events */
$('simBtn').onclick = async () => {
  const f = cur(); if (!f) return;
  busy = true; renderButtons(); banner('Attack in progress...');
  const res = await api('/api/simulate', {id: f.id});
  if (res.error) { banner(res.error, 'bad'); busy = false; return renderButtons(); }
  await play(res);
  banner(res.banner, res.vulnerable ? 'bad' : '');
  busy = false; await refresh();
};

$('fixBtn').onclick = async () => {
  const f = cur(); if (!f) return;
  busy = true; renderButtons(); banner('Patching and replaying the identical attack...');
  const res = await api('/api/fix', {id: f.id});
  if (res.error) { banner(res.error, 'bad'); busy = false; return renderButtons(); }
  $('patch').textContent = res.patch; $('patchBox').hidden = false; $('patchBox').open = true;
  await play(res.result);
  if (res.unverified) banner('Reference patch generated. NOT verified: this code was never executed, so the fix is unproven. Review it before use. The Trust Score does not change.', 'warn');
  else banner(res.needs_review ? 'Patch applied but the attack still works: flagged for human review.' : 'FIXED AND VERIFIED: the same attack is now blocked. Finding is green.', res.needs_review ? 'bad' : 'good');
  busy = false; await refresh();
};

$('analyzeBtn').onclick = () => { fileName = ''; analyze(); };
$('ctaBtn').onclick = () => { $('editor').scrollIntoView({behavior: 'smooth', block: 'center'}); $('code').focus(); };
$('resetBtn').onclick = async () => { if (!state) return; await api('/api/reset', {}); clearLab(); await refresh(); };
$('exportBtn').onclick = () => {
  const blob = new Blob([JSON.stringify(state, null, 2)], {type: 'application/json'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'zday-protocol-report.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};
$('rows').addEventListener('click', e => {
  const b = e.target.closest('.open-lab'); if (!b) return;
  showTab('lab'); $('pick').value = b.dataset.id; renderPick(); renderButtons();
});
document.querySelectorAll('nav button').forEach(b => { b.onclick = () => showTab(b.dataset.tab); });
['fStatus', 'fSev'].forEach(id => { $(id).onchange = renderRows; });
$('pick').onchange = () => { renderPick(); renderButtons(); };

function loadText(text, name) {
  if (text.length > 200000) { setStatus('That file is larger than 200 KB. Paste the relevant part instead.', 'bad'); return; }
  $('code').value = text; fileName = name || ''; $('lang').value = 'auto'; analyze();
}
$('file').onchange = e => {
  const f = e.target.files[0]; if (!f) return;
  if (f.size > 200000) { setStatus('That file is larger than 200 KB. Paste the relevant part instead.', 'bad'); e.target.value = ''; return; }
  const r = new FileReader(); r.onload = () => loadText(String(r.result), f.name); r.onerror = () => setStatus('Could not read that file.', 'bad'); r.readAsText(f); e.target.value = '';
};
const box = $('code');
box.addEventListener('dragover', e => { e.preventDefault(); $('editor').classList.add('drag'); });
box.addEventListener('dragleave', () => $('editor').classList.remove('drag'));
box.addEventListener('drop', e => {
  e.preventDefault(); $('editor').classList.remove('drag');
  const f = e.dataTransfer.files[0]; if (!f) return;
  if (f.size > 200000) { setStatus('That file is larger than 200 KB. Paste the relevant part instead.', 'bad'); return; }
  const r = new FileReader(); r.onload = () => loadText(String(r.result), f.name); r.readAsText(f);
});
$('example').onchange = e => {
  const k = e.target.value; e.target.value = ''; if (!k) return;
  if (k === 'sample') loadText(SAMPLE, ''); else loadText(EXAMPLES[k].code, EXAMPLES[k].file);
};

/* ---------------------------------------------------------------- init */
(async function init() {
  if (!DEMO) {
    try { const r = await fetch('/api/sample'); if (r.ok) { SAMPLE = (await r.json()).source; serverOK = true; } } catch (e) { /* static file or offline */ }
  }
  client = new LD.ClientSession({sampleSource: SAMPLE, recorded: DEMO && DEMO.recorded});
  const ex = $('example');
  if (SAMPLE) ex.insertAdjacentHTML('beforeend', '<option value="sample">Python sample (real sandbox attacks)</option>');
  Object.keys(EXAMPLES).forEach(k => ex.insertAdjacentHTML('beforeend', `<option value="${k}">${esc(EXAMPLES[k].label)}</option>`));
  if (SAMPLE) { $('code').value = SAMPLE; await analyze(); } else { renderUsers(); }
})();
})();
