'use strict';
// Dashboard logic. Every value from the audit is written with textContent, never innerHTML:
// finding text includes names chosen by third parties (extensions, processes, sites).

const TOKEN_KEY = 'mg-token';
const POLL_RUNNING_MS = 3000;
const POLL_IDLE_MS = 30000;
const SEVERITY = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low', PASS: 'pass', INFO: 'info' });
const ACTION = Object.freeze({ ACCEPT: 'accept', REOPEN: 'reopen' });
const LIST = Object.freeze({ OPEN: 'open', ACCEPTED: 'accepted', RESOLVED: 'resolved' });

const $ = (id) => document.getElementById(id);
let pollTimer = null;
let startRequested = false;

// The launcher opens the page as /#n=<one-time nonce>. Trade it for the token, which is kept only
// for this tab (sessionStorage), and clean the URL. A wrong nonce leaves any existing token alone.
async function signInFromUrl() {
  const match = location.hash.match(/^#n=([\w-]+)$/);
  if (!match) return;
  history.replaceState(null, '', '/');
  const response = await fetch('/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nonce: match[1] }),
  });
  if (response.ok) sessionStorage.setItem(TOKEN_KEY, (await response.json()).token);
}

async function api(path, body) {
  const options = { headers: { 'X-MG-Token': sessionStorage.getItem(TOKEN_KEY) || '' } };
  if (body) {
    options.method = 'POST';
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  if (response.status === 401) throw new Error('Not signed in. Run "mac-guard" in a terminal to open the dashboard.');
  return response;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function notice(message) {
  $('notice').textContent = message || '';
  $('notice').hidden = !message;
}

function renderVerdict(state) {
  const count = (sev) => state.open.filter((f) => f.severity === sev).length;
  const high = count(SEVERITY.HIGH), medium = count(SEVERITY.MEDIUM), low = count(SEVERITY.LOW);
  let level = 'good', icon = '✓', title = 'No open findings';
  if (high) { level = SEVERITY.HIGH; icon = '!'; title = `${high} high-severity finding${high > 1 ? 's' : ''} need attention`; }
  else if (medium) { level = SEVERITY.MEDIUM; icon = '!'; title = `${medium} medium finding${medium > 1 ? 's' : ''} to review`; }
  else if (low) { level = SEVERITY.LOW; icon = 'i'; title = `${low} low finding${low > 1 ? 's' : ''} to review`; }
  $('verdict-icon').className = `verdict-icon ${level}`;
  $('verdict-icon').textContent = icon;
  $('verdict-title').textContent = title;
  const run = state.last_run;
  $('verdict-sub').textContent = run
    ? `Last audit found ${run.n_new} new or returning finding${run.n_new === 1 ? '' : 's'}.`
    : 'No audit has completed yet. Press Run audit.';
  $('n-high').textContent = high;
  $('n-medium').textContent = medium;
  $('n-low').textContent = low;
  $('n-accepted').textContent = state.accepted.length;
  $('n-pass').textContent = run ? run.n_pass : 0;
  $('last-run').textContent = state.running ? 'Audit running… this takes a couple of minutes.'
    : run ? `Last audit ${run.finished_at} (${run.trigger})` : 'No audit yet';
}

function renderTools(tools) {
  $('tools').replaceChildren(...tools.map((tool) => {
    const item = el('li');
    const label = tool.running ? 'running' : tool.installed ? 'installed, not running' : 'not installed';
    item.append(el('span', `dot ${tool.running ? 'good' : tool.installed ? 'medium' : 'off'}`), el('strong', '', tool.name), el('span', 'state', label));
    return item;
  }));
}

function renderChanges(text) {
  const box = $('changes');
  if (!text.trim()) { box.textContent = 'Nothing changed in startup items, accounts, settings or browser extensions.'; return; }
  box.replaceChildren(...text.split('\n').filter((line) => /^[<>]/.test(line)).map((line) =>
    el('span', line[0] === '>' ? 'add' : 'del', (line[0] === '>' ? '+ ' : '− ') + line.slice(2))));
}

function findingRow(finding, list) {
  const row = el('li');
  const sev = el('span', 'sev');
  sev.append(el('span', `dot ${finding.severity}`), document.createTextNode(finding.severity));
  const body = el('div');
  const title = el('p', 'f-title', finding.title);
  title.append(el('span', 'tag', finding.category));
  if (finding.reappeared && list === LIST.OPEN) title.append(el('span', 'tag', 'came back'));
  body.append(title);
  if (finding.detail) body.append(el('p', 'f-detail', finding.detail));
  if (finding.fix) {
    const fix = el('p', 'f-fix');
    fix.append(el('strong', '', 'How to fix: '), document.createTextNode(finding.fix));
    body.append(fix);
  }
  const meta = [`first seen ${finding.first_seen}`];
  if (list === LIST.RESOLVED) meta.push(`resolved ${finding.resolved_at}`);
  if (finding.note) meta.push(`note: ${finding.note}`);
  body.append(el('p', 'f-meta', meta.join(' · ')));
  row.append(sev, body);

  const actions = el('div');
  if (list === LIST.OPEN) {
    const accept = el('button', '', 'Accept');
    accept.type = 'button';
    accept.addEventListener('click', () => {
      const form = el('form', 'accept-form');
      const input = el('input');
      input.placeholder = 'Why is this OK? (optional)';
      input.maxLength = 500;
      input.setAttribute('aria-label', 'Reason for accepting');
      const confirm = el('button', '', 'Confirm');
      form.append(input, confirm);
      form.addEventListener('submit', (event) => { event.preventDefault(); act(finding.key, ACTION.ACCEPT, input.value); });
      body.append(form);
      accept.remove();
      input.focus();
    });
    actions.append(accept);
  } else if (list === LIST.ACCEPTED) {
    const reopen = el('button', '', 'Reopen');
    reopen.type = 'button';
    reopen.addEventListener('click', () => act(finding.key, ACTION.REOPEN, ''));
    actions.append(reopen);
  }
  row.append(actions);
  return row;
}

function renderList(id, findings, list, emptyText) {
  const node = $(id);
  if (!findings.length && emptyText) {
    const empty = el('li', 'empty', emptyText);
    node.replaceChildren(empty);
    return;
  }
  node.replaceChildren(...findings.map((f) => findingRow(f, list)));
}

function renderChecks(checks) {
  $('c-checks').textContent = `(${checks.length})`;
  $('checks').replaceChildren(...checks.map((check) => {
    const row = el('li');
    row.append(el('span', 'mark', check.severity === SEVERITY.PASS ? 'PASS' : 'INFO'),
      el('span', '', check.detail ? `${check.title} — ${check.detail}` : check.title));
    return row;
  }));
}

function renderHistory(runs) {
  $('history').replaceChildren(...runs.map((run) => {
    const row = el('tr');
    const bar = el('div', 'bar');
    bar.title = `High ${run.n_high}, medium ${run.n_medium}, low ${run.n_low}`;
    for (const [sev, n] of [[SEVERITY.HIGH, run.n_high], [SEVERITY.MEDIUM, run.n_medium], [SEVERITY.LOW, run.n_low]]) {
      if (n) { const seg = el('i', sev); seg.style.flex = String(n); bar.append(seg); }
    }
    const mix = el('td'); mix.append(bar);
    const report = el('td');
    if (run.status === 'done') {
      const open = el('button', 'link', 'View');
      open.type = 'button';
      open.addEventListener('click', () => showReport(run));
      report.append(open);
    }
    row.append(el('td', '', run.started_at), el('td', '', run.trigger),
      el('td', '', run.status === 'failed' ? `failed: ${run.error || ''}` : run.status),
      el('td', 'num', run.n_high), el('td', 'num', run.n_medium), el('td', 'num', run.n_low), mix, report);
    return row;
  }));
}

async function showReport(run) {
  const response = await api(`/api/report?run=${run.id}`);
  $('report-title').textContent = `Report, ${run.started_at}`;
  $('report-body').textContent = response.ok ? await response.text() : 'Report not available.';
  $('report-dialog').showModal();
}

async function act(key, action, note) {
  try {
    await api('/api/finding', { key, action, note });
    await refresh();
  } catch (error) { notice(error.message); }
}

async function refresh() {
  clearTimeout(pollTimer);
  try {
    const state = await (await api('/api/state')).json();
    if (state.running) startRequested = false;
    const running = state.running || startRequested;
    state.running = running;
    notice('');
    $('app').hidden = false;
    $('run').disabled = running;
    $('run').textContent = running ? 'Running…' : 'Run audit';
    renderVerdict(state);
    renderTools(state.tools);
    renderChanges(state.changes);
    renderList('open', state.open, LIST.OPEN, 'Nothing open. Every finding is fixed or accepted.');
    renderList('accepted', state.accepted, LIST.ACCEPTED);
    renderList('resolved', state.resolved, LIST.RESOLVED);
    $('c-accepted').textContent = `(${state.accepted.length})`;
    $('c-resolved').textContent = `(${state.resolved.length})`;
    renderChecks(state.checks);
    renderHistory(state.runs);
    // stop polling while the tab is hidden so the server can shut itself down when idle
    if (!document.hidden) pollTimer = setTimeout(refresh, running ? POLL_RUNNING_MS : POLL_IDLE_MS);
  } catch (error) {
    notice(error.message);
    $('last-run').textContent = '';
  }
}

$('run').addEventListener('click', async () => {
  try {
    const response = await api('/api/run', {});
    if (response.status === 202 || response.status === 409) {
      startRequested = response.status === 202;
      setTimeout(() => { startRequested = false; }, 15000);
      await refresh();
    } else { notice('Could not start the audit.'); }
  } catch (error) { notice(error.message); }
});
$('report-close').addEventListener('click', () => $('report-dialog').close());
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });

signInFromUrl().catch(() => {}).then(refresh);
