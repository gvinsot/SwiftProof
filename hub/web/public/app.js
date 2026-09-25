// SwiftProof Hub dashboard.
//
// The page holds three things: the repository list with its bootstrap actions,
// the report viewer with its severity filter, and a live event stream that
// opens the report of a new commit as soon as it has been analyzed.
'use strict';

const LEVELS = ['low', 'medium', 'high', 'critical'];
const KINDS = [
  { key: 'all', label: 'Everything' },
  { key: 'issue', label: 'Issues' },
  { key: 'check', label: 'Checks' },
  { key: 'signal', label: 'Signals' },
  { key: 'focus', label: 'Review plan' },
];

const state = {
  me: null,
  csrf: '',
  repos: new Map(),
  repoKey: null,
  commit: null,
  view: null,
  run: null,
  minSeverity: 0,
  kind: 'all',
  query: '',
  onlyMonitored: false,
  onlyMissing: false,
  expanded: new Set(),
};

const el = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ API -- */

async function api(path, options = {}) {
  const init = {
    credentials: 'same-origin',
    headers: Object.assign({ 'Accept': 'application/json' }, options.headers || {}),
    method: options.method || 'GET',
  };
  if (options.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  if (init.method !== 'GET' && init.method !== 'HEAD') {
    init.headers['X-SwiftProof-CSRF'] = state.csrf;
  }
  const response = await fetch(path, init);
  if (response.status === 401) {
    window.location.replace('/index.html');
    throw new Error('signed out');
  }
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(payload.error || ('request failed with ' + response.status));
  }
  return payload;
}

function toast(message, isError) {
  const holder = el('toast');
  const item = document.createElement('div');
  if (isError) item.classList.add('error');
  item.textContent = message;
  holder.appendChild(item);
  setTimeout(() => item.remove(), isError ? 9000 : 4500);
}

/* ------------------------------------------------------------- rendering -- */

function severityClass(severity) { return 'sev-' + (severity || 'low'); }

function chip(text, cls) {
  const span = document.createElement('span');
  span.className = 'chip' + (cls ? ' ' + cls : '');
  span.textContent = text;
  return span;
}

function dotChip(text, severity) {
  const span = chip('', '');
  const dot = document.createElement('span');
  dot.className = 'dot';
  span.classList.add(severityClass(severity));
  span.appendChild(dot);
  span.appendChild(document.createTextNode(text));
  return span;
}

function shortSha(sha) { return sha ? sha.slice(0, 10) : ''; }

function timeAgo(value) {
  if (!value) return '';
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return '';
  const seconds = Math.max(1, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return seconds + 's ago';
  if (seconds < 3600) return Math.round(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.round(seconds / 3600) + 'h ago';
  return Math.round(seconds / 86400) + 'd ago';
}

function verdictChip(run) {
  if (!run) return chip('never analyzed');
  if (run.status === 'queued') return chip('queued', 'busy');
  if (run.status === 'running') return chip('analyzing…', 'busy');
  if (run.status === 'failed') return chip('analysis failed', 'bad');
  const summary = run.summary || {};
  switch (summary.verdict) {
    case 'blocked': return chip('reproduced issue', 'bad');
    case 'review': return chip('review required', 'warn');
    case 'clear': return chip('no blocker', 'ok');
    default: return chip(summary.verdict || 'unknown');
  }
}

/* ------------------------------------------------------- repository list -- */

function visibleRepos() {
  const query = state.query.trim().toLowerCase();
  return Array.from(state.repos.values()).filter((repo) => {
    if (query && !repo.full_name.toLowerCase().includes(query)) return false;
    if (state.onlyMonitored && !repo.monitored) return false;
    if (state.onlyMissing && repo.has_policy) return false;
    return true;
  }).sort((a, b) => {
    if (a.monitored !== b.monitored) return a.monitored ? -1 : 1;
    return a.full_name.localeCompare(b.full_name);
  });
}

function renderRepos() {
  const list = el('repos');
  const repos = visibleRepos();
  list.textContent = '';
  el('repo-count').textContent = String(state.repos.size);
  el('repos-empty').classList.toggle('hidden', repos.length > 0);

  for (const repo of repos) {
    const item = document.createElement('li');
    item.className = 'repo' + (repo.key === state.repoKey ? ' active' : '');
    item.tabIndex = 0;

    const name = document.createElement('div');
    name.className = 'repo-name';
    name.appendChild(document.createTextNode(repo.full_name));
    if (repo.private) name.appendChild(chip('private'));
    item.appendChild(name);

    const meta = document.createElement('div');
    meta.className = 'repo-meta';
    meta.appendChild(chip(repo.default_branch || 'no branch'));
    meta.appendChild(repo.has_policy ? chip('.swiftproof.json', 'ok') : chip('no policy', 'warn'));
    if (repo.monitored) meta.appendChild(chip('monitored', 'ok'));
    meta.appendChild(verdictChip(repo.latest));
    if (repo.latest && repo.latest.summary && repo.latest.summary.counts && repo.latest.status === 'done') {
      const counts = repo.latest.summary.counts;
      if (counts.total > 0) meta.appendChild(dotChip(counts.total + ' alerts', worstSeverity(counts)));
    }
    if (repo.latest && repo.latest.finished_at) meta.appendChild(chip(timeAgo(repo.latest.finished_at)));
    item.appendChild(meta);

    const actions = document.createElement('div');
    actions.className = 'repo-actions';
    if (!repo.has_policy) {
      actions.appendChild(button('Create .swiftproof.json', 'btn small', (event) => {
        event.stopPropagation();
        openPolicyDialog(repo);
      }));
    } else if (!repo.monitored) {
      const monitor = button('Monitor commits', 'btn small', (event) => {
        event.stopPropagation();
        setMonitoring(repo, true, monitor);
      });
      monitor.disabled = !repo.admin;
      if (!repo.admin) monitor.title = 'Your account cannot manage webhooks on this repository';
      actions.appendChild(monitor);
    } else {
      actions.appendChild(button('Stop monitoring', 'btn quiet small', (event) => {
        event.stopPropagation();
        setMonitoring(repo, false);
      }));
    }
    if (repo.has_policy) {
      actions.appendChild(button('Analyze now', 'btn ghost small', (event) => {
        event.stopPropagation();
        analyzeNow(repo);
      }));
    }
    item.appendChild(actions);

    const open = () => selectRepo(repo.key);
    item.addEventListener('click', open);
    item.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); }
    });
    list.appendChild(item);
  }
}

function worstSeverity(counts) {
  if (counts.critical > 0) return 'critical';
  if (counts.high > 0) return 'high';
  if (counts.medium > 0) return 'medium';
  return 'low';
}

function button(label, className, onClick) {
  const b = document.createElement('button');
  b.className = className;
  b.textContent = label;
  b.addEventListener('click', onClick);
  return b;
}

/* ----------------------------------------------------- repository actions -- */

async function openPolicyDialog(repo) {
  const body = el('modal-body');
  const footer = el('modal-footer');
  el('modal-title').textContent = 'Create .swiftproof.json in ' + repo.full_name;
  body.textContent = '';
  footer.textContent = '';

  const intro = document.createElement('p');
  intro.className = 'note';
  intro.textContent = 'The policy is generated by the SwiftProof CLI this service runs, and committed on '
    + (repo.default_branch || 'the default branch')
    + '. Review the sandbox image and the commands before relying on a report.';
  body.appendChild(intro);

  const row = document.createElement('div');
  row.className = 'row';
  const label = document.createElement('label');
  label.className = 'note';
  label.textContent = 'Language';
  const select = document.createElement('select');
  select.className = 'select';
  for (const language of ['auto', 'go', 'typescript', 'javascript', 'python', 'unknown']) {
    const option = document.createElement('option');
    option.value = language;
    option.textContent = language;
    select.appendChild(option);
  }
  row.appendChild(label);
  row.appendChild(select);
  body.appendChild(row);

  const preview = document.createElement('pre');
  preview.className = 'policy';
  preview.textContent = 'Generating a preview…';
  body.appendChild(preview);

  const create = button('Commit the policy', 'btn', async () => {
    create.disabled = true;
    try {
      const payload = await api('/api/repos/' + encodeURIComponent(repo.key) + '/policy', {
        method: 'POST',
        body: { language: select.value === 'auto' ? '' : select.value },
      });
      upsertRepo(payload.repo);
      closeModal();
      toast('Committed .swiftproof.json on ' + repo.default_branch + '. Enable monitoring to analyze new commits.');
    } catch (err) {
      toast(err.message, true);
      create.disabled = false;
    }
  });
  footer.appendChild(button('Cancel', 'btn quiet', closeModal));
  footer.appendChild(create);

  const loadPreview = async () => {
    preview.textContent = 'Generating a preview…';
    create.disabled = true;
    try {
      const payload = await api('/api/repos/' + encodeURIComponent(repo.key) + '/policy', {
        method: 'POST',
        body: { language: select.value === 'auto' ? '' : select.value, preview: true },
      });
      preview.textContent = payload.policy;
      if (select.value === 'auto') {
        intro.textContent = 'Detected language: ' + payload.language + '. ' + intro.textContent;
      }
      create.disabled = false;
    } catch (err) {
      preview.textContent = err.message;
    }
  };
  select.addEventListener('change', loadPreview);
  el('modal').classList.remove('hidden');
  loadPreview();
}

function closeModal() { el('modal').classList.add('hidden'); }

async function setMonitoring(repo, on, trigger) {
  if (trigger) trigger.disabled = true;
  try {
    const payload = await api('/api/repos/' + encodeURIComponent(repo.key) + '/monitor', {
      method: on ? 'POST' : 'DELETE',
    });
    upsertRepo(payload.repo);
    toast(on
      ? 'Monitoring ' + repo.full_name + '. A first analysis is queued; every new commit will follow.'
      : 'Stopped monitoring ' + repo.full_name + '.');
  } catch (err) {
    toast(err.message, true);
    if (trigger) trigger.disabled = false;
  }
}

async function analyzeNow(repo) {
  try {
    await api('/api/repos/' + encodeURIComponent(repo.key) + '/analyze', { method: 'POST', body: {} });
    toast('Analysis queued for ' + repo.full_name + '.');
  } catch (err) {
    toast(err.message, true);
  }
}

function upsertRepo(repo) {
  if (!repo) return;
  state.repos.set(repo.key, repo);
  renderRepos();
}

/* ------------------------------------------------------------- the report -- */

async function selectRepo(repoKey, commit) {
  state.repoKey = repoKey;
  state.commit = commit || null;
  state.expanded.clear();
  const suffix = commit ? '/commit/' + commit : '';
  const hash = '#/repo/' + repoKey + suffix;
  if (window.location.hash !== hash) window.location.hash = hash;
  renderRepos();
  await loadHistory();
}

async function loadHistory() {
  const repo = state.repos.get(state.repoKey);
  if (!repo) return;
  el('report-repo').textContent = repo.full_name;
  try {
    const payload = await api('/api/repos/' + encodeURIComponent(repo.key) + '/runs');
    const select = el('history');
    select.textContent = '';
    const runs = payload.runs || [];
    for (const run of runs) {
      const option = document.createElement('option');
      option.value = run.commit;
      const label = [shortSha(run.commit), run.message || '(no message)'].join(' · ');
      option.textContent = label.length > 70 ? label.slice(0, 69) + '…' : label;
      select.appendChild(option);
    }
    if (runs.length === 0) {
      showNoReport(repo);
      return;
    }
    if (!state.commit || !runs.some((run) => run.commit === state.commit)) {
      state.commit = runs[0].commit;
    }
    select.value = state.commit;
    await loadReport();
  } catch (err) {
    toast(err.message, true);
  }
}

function showNoReport(repo) {
  state.view = null;
  el('filters').classList.add('hidden');
  el('alerts').textContent = '';
  el('extras').classList.add('hidden');
  const empty = el('report-empty');
  empty.classList.remove('hidden');
  empty.textContent = repo.has_policy
    ? 'No report yet. Use “Analyze now”, or enable monitoring to get one on every commit.'
    : 'This repository has no .swiftproof.json on ' + (repo.default_branch || 'its default branch') + '. Create it to start.';
  el('report-sub').textContent = repo.web_url || '';
}

async function loadReport() {
  const repo = state.repos.get(state.repoKey);
  if (!repo || !state.commit) return;
  try {
    const payload = await api('/api/repos/' + encodeURIComponent(repo.key)
      + '/reports/' + encodeURIComponent(state.commit));
    state.view = payload.view;
    state.run = payload.run;
    renderReport();
  } catch (err) {
    showNoReport(repo);
    toast(err.message, true);
  }
}

function renderReport() {
  const repo = state.repos.get(state.repoKey);
  const view = state.view;
  const run = state.run;
  if (!repo || !view) return;

  el('report-empty').classList.add('hidden');
  el('filters').classList.remove('hidden');

  const head = el('report-head');
  head.textContent = '';

  const title = document.createElement('div');
  title.className = 'report-title';
  const h2 = document.createElement('h2');
  h2.id = 'report-repo';
  h2.textContent = repo.full_name;
  title.appendChild(h2);
  const verdict = document.createElement('span');
  verdict.className = 'verdict ' + (view.summary.verdict || 'failed');
  verdict.textContent = verdictLabel(view.summary.verdict);
  title.appendChild(verdict);
  if (run && run.status === 'failed') title.appendChild(chip('analysis failed', 'bad'));
  head.appendChild(title);

  const sub = document.createElement('p');
  sub.className = 'report-sub';
  const parts = [];
  if (run) {
    parts.push(shortSha(run.commit));
    if (run.message) parts.push(run.message);
    if (run.author) parts.push('by ' + run.author);
    if (run.ref) parts.push(run.ref.replace('refs/heads/', ''));
    if (run.finished_at) parts.push(timeAgo(run.finished_at));
    if (run.trigger) parts.push(run.trigger);
  }
  sub.textContent = parts.join(' · ');
  head.appendChild(sub);

  if (run && run.error) {
    const error = document.createElement('p');
    error.className = 'report-sub';
    error.textContent = 'Error: ' + run.error;
    head.appendChild(error);
  }

  const stats = document.createElement('div');
  stats.className = 'stats';
  const s = view.summary;
  stats.appendChild(stat(s.counts.total, 'alerts'));
  stats.appendChild(stat(s.reproduced, 'reproduced'));
  stats.appendChild(stat(s.unverified, 'unverified'));
  stats.appendChild(stat(s.focused_lines + ' / ' + s.changed_lines, 'focused lines'));
  stats.appendChild(stat(s.changed_files, 'files'));
  stats.appendChild(stat('+' + s.additions + ' / -' + s.deletions, 'lines'));
  if (s.checks_passed + s.checks_failed > 0) {
    stats.appendChild(stat(s.checks_passed + ' / ' + (s.checks_passed + s.checks_failed), 'checks passed'));
  }
  head.appendChild(stats);

  const links = document.createElement('div');
  links.className = 'row';
  if (repo.web_url && run) {
    const forgeLink = document.createElement('a');
    forgeLink.className = 'btn quiet small';
    forgeLink.href = commitURL(repo, run.commit);
    forgeLink.target = '_blank';
    forgeLink.rel = 'noopener noreferrer';
    forgeLink.textContent = 'Open the commit';
    links.appendChild(forgeLink);
  }
  const note = document.createElement('span');
  note.className = 'note';
  note.textContent = 'A report states what was observed and what was reproduced. It never approves a change.';
  links.appendChild(note);
  head.appendChild(links);

  el('download').href = '/api/repos/' + encodeURIComponent(repo.key)
    + '/reports/' + encodeURIComponent(state.commit) + '/raw';

  renderKindFilter();
  renderAlerts();
  renderExtras();
}

function verdictLabel(verdict) {
  switch (verdict) {
    case 'blocked': return 'Reproduced issue';
    case 'review': return 'Human review required';
    case 'clear': return 'No reproduced blocker';
    default: return 'Incomplete';
  }
}

function commitURL(repo, commit) {
  if (!repo.web_url) return '#';
  const separator = repo.provider === 'gitlab' ? '/-/commit/' : '/commit/';
  return repo.web_url.replace(/\/$/, '') + separator + commit;
}

function stat(value, label) {
  const box = document.createElement('div');
  box.className = 'stat';
  const b = document.createElement('b');
  b.textContent = String(value);
  const span = document.createElement('span');
  span.textContent = label;
  box.appendChild(b);
  box.appendChild(span);
  return box;
}

function renderKindFilter() {
  const holder = el('kinds');
  holder.textContent = '';
  const alerts = state.view ? state.view.alerts || [] : [];
  for (const kind of KINDS) {
    const count = kind.key === 'all'
      ? alerts.length
      : alerts.filter((a) => a.kind === kind.key).length;
    if (kind.key !== 'all' && count === 0) continue;
    const b = button(kind.label + ' (' + count + ')', state.kind === kind.key ? 'on' : '', () => {
      state.kind = kind.key;
      renderKindFilter();
      renderAlerts();
    });
    holder.appendChild(b);
  }
}

function filteredAlerts() {
  if (!state.view) return [];
  return (state.view.alerts || []).filter((alert) => {
    if (LEVELS.indexOf(alert.severity) < state.minSeverity) return false;
    if (state.kind !== 'all' && alert.kind !== state.kind) return false;
    return true;
  });
}

function renderAlerts() {
  const list = el('alerts');
  list.textContent = '';
  const alerts = filteredAlerts();
  const total = state.view ? (state.view.alerts || []).length : 0;
  el('alert-count').textContent = alerts.length + ' of ' + total + ' alerts shown';

  if (alerts.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty';
    empty.textContent = total === 0
      ? 'This run recorded no alert.'
      : 'No alert at this severity. Lower the filter to see the rest.';
    list.appendChild(empty);
    return;
  }

  for (const alert of alerts) {
    const item = document.createElement('li');
    item.className = 'alert';

    const head = document.createElement('button');
    head.className = 'alert-head';
    head.setAttribute('aria-expanded', state.expanded.has(alert.id) ? 'true' : 'false');

    const dot = document.createElement('span');
    dot.className = 'dot ' + severityClass(alert.severity);
    head.appendChild(dot);

    const middle = document.createElement('span');
    const title = document.createElement('div');
    title.className = 'alert-title';
    title.textContent = alert.title || alert.id;
    middle.appendChild(title);
    const where = document.createElement('div');
    where.className = 'alert-where';
    where.textContent = alertLocation(alert);
    middle.appendChild(where);
    head.appendChild(middle);

    const tags = document.createElement('span');
    tags.className = 'alert-tags';
    tags.appendChild(dotChip(alert.severity, alert.severity));
    tags.appendChild(chip(alert.kind));
    if (alert.status) tags.appendChild(chip(alert.status.toLowerCase(), statusClass(alert.status)));
    head.appendChild(tags);

    head.addEventListener('click', () => {
      if (state.expanded.has(alert.id)) state.expanded.delete(alert.id);
      else state.expanded.add(alert.id);
      renderAlerts();
    });
    item.appendChild(head);

    if (state.expanded.has(alert.id)) {
      item.appendChild(alertBody(alert));
    }
    list.appendChild(item);
  }
}

function statusClass(status) {
  switch (String(status).toUpperCase()) {
    case 'REPRODUCED': return 'bad';
    case 'UNVERIFIED': return 'warn';
    case 'NOT_REPRODUCED':
    case 'DISMISSED':
    case 'PASS': return 'ok';
    case 'FAIL':
    case 'ERROR':
    case 'TIMEOUT': return 'bad';
    default: return '';
  }
}

function alertLocation(alert) {
  if (!alert.path) return alert.reasons ? alert.reasons.join(', ') : '';
  let where = alert.path;
  if (alert.line) {
    where += ':' + alert.line;
    if (alert.end_line && alert.end_line !== alert.line) where += '-' + alert.end_line;
  }
  if (alert.side && alert.side !== 'new') where += ' (' + alert.side + ' side)';
  return where;
}

// alertBody shows the rationale, the recorded evidence and, above all, the
// modifications the alert concerns.
function alertBody(alert) {
  const body = document.createElement('div');
  body.className = 'alert-body';

  if (alert.detail) {
    const detail = document.createElement('div');
    detail.className = 'alert-detail';
    detail.textContent = alert.detail;
    body.appendChild(detail);
  }
  if (alert.reasons && alert.reasons.length > 0) {
    const reasons = document.createElement('div');
    reasons.className = 'row';
    for (const reason of alert.reasons) reasons.appendChild(chip(reason));
    body.appendChild(reasons);
  }
  for (const evidence of alert.evidence || []) {
    const box = document.createElement('div');
    box.className = 'evidence';
    const head = document.createElement('div');
    head.className = 'row';
    head.appendChild(chip(evidence.kind));
    head.appendChild(chip(evidence.status.toLowerCase(), statusClass(evidence.status)));
    if (evidence.runner) head.appendChild(chip(evidence.runner));
    box.appendChild(head);
    const description = document.createElement('div');
    description.textContent = evidence.description || '';
    box.appendChild(description);
    if (evidence.test_names && evidence.test_names.length > 0) {
      const tests = document.createElement('div');
      tests.className = 'note mono';
      tests.textContent = 'tests: ' + evidence.test_names.join(', ');
      box.appendChild(tests);
    }
    if (evidence.output) {
      const output = document.createElement('pre');
      output.className = 'alert-detail mono';
      output.textContent = evidence.output;
      box.appendChild(output);
    }
    body.appendChild(box);
  }

  const file = alert.path ? findFile(alert.path) : null;
  if (file) {
    body.appendChild(renderDiff(file, alert));
  } else if (alert.path) {
    const missing = document.createElement('p');
    missing.className = 'note';
    missing.textContent = 'The analyzed range carries no diff for ' + alert.path + '.';
    body.appendChild(missing);
  }
  return body;
}

function findFile(path) {
  if (!state.view) return null;
  return (state.view.files || []).find((file) => file.path === path || file.old_path === path) || null;
}

// renderDiff shows every modification of the concerned file and highlights the
// lines the alert points at.
function renderDiff(file, alert) {
  const wrapper = document.createElement('div');
  wrapper.className = 'diff';

  const header = document.createElement('div');
  header.className = 'diff-file';
  const path = document.createElement('span');
  path.className = 'path mono';
  path.textContent = file.path;
  header.appendChild(path);
  header.appendChild(chip(statusLabel(file.status)));
  header.appendChild(chip('+' + file.additions + ' / -' + file.deletions));
  if (file.old_path) header.appendChild(chip('was ' + file.old_path));
  wrapper.appendChild(header);

  if (file.binary || !file.hunks || file.hunks.length === 0) {
    const none = document.createElement('div');
    none.className = 'empty';
    none.textContent = file.binary ? 'Binary file: no line-level diff.' : 'No hunk recorded for this file.';
    wrapper.appendChild(none);
    return wrapper;
  }

  const table = document.createElement('table');
  const body = document.createElement('tbody');
  let firstFocus = null;
  for (const hunk of file.hunks) {
    const headerRow = document.createElement('tr');
    headerRow.className = 'hunk-header';
    const cell = document.createElement('td');
    cell.colSpan = 4;
    cell.className = 'mono';
    cell.textContent = '@@ -' + hunk.old_start + ',' + hunk.old_lines
      + ' +' + hunk.new_start + ',' + hunk.new_lines + ' @@';
    headerRow.appendChild(cell);
    body.appendChild(headerRow);

    for (const line of hunk.lines || []) {
      const row = document.createElement('tr');
      row.className = line.kind === 'add' ? 'add' : (line.kind === 'delete' ? 'del' : 'ctx');
      if (inAlertRange(line, alert)) {
        row.classList.add('focus');
        if (!firstFocus) firstFocus = row;
      }
      row.appendChild(cellText(line.old_line || '', 'num mono'));
      row.appendChild(cellText(line.new_line || '', 'num mono'));
      row.appendChild(cellText(line.kind === 'add' ? '+' : (line.kind === 'delete' ? '-' : ' '), 'sign mono'));
      row.appendChild(cellText(line.content, 'mono'));
      body.appendChild(row);
    }
  }
  table.appendChild(body);

  const pre = document.createElement('div');
  pre.appendChild(table);
  wrapper.appendChild(pre);

  if (firstFocus) {
    // Bring the flagged lines into view without stealing the page scroll.
    requestAnimationFrame(() => firstFocus.scrollIntoView({ block: 'center' }));
  }
  return wrapper;
}

function statusLabel(status) {
  switch (status) {
    case 'A': return 'added';
    case 'D': return 'deleted';
    case 'M': return 'modified';
    case 'R': return 'renamed';
    case 'C': return 'copied';
    case 'T': return 'type changed';
    default: return status || 'changed';
  }
}

function inAlertRange(line, alert) {
  if (!alert || !alert.line) return false;
  const side = alert.side === 'old' ? 'old_line' : 'new_line';
  const number = line[side];
  if (!number) return false;
  const end = alert.end_line && alert.end_line >= alert.line ? alert.end_line : alert.line;
  return number >= alert.line && number <= end;
}

function cellText(text, className) {
  const cell = document.createElement('td');
  cell.className = className;
  cell.textContent = String(text);
  return cell;
}

// renderExtras shows what is deliberately not an alert: coverage, the review
// surface, and everything the run left unverified.
function renderExtras() {
  const holder = el('extras');
  holder.textContent = '';
  const view = state.view;
  if (!view) { holder.classList.add('hidden'); return; }
  holder.classList.remove('hidden');

  const surface = document.createElement('p');
  surface.className = 'note';
  surface.textContent = view.review_surface && view.review_surface.note ? view.review_surface.note : '';
  if (surface.textContent) holder.appendChild(surface);

  if (view.coverage) {
    const coverage = document.createElement('div');
    coverage.className = 'row';
    coverage.appendChild(chip('changed-line execution: ' + view.coverage.status));
    if (view.coverage.status === 'measured') {
      coverage.appendChild(chip(view.coverage.executed_lines + ' executed'));
      coverage.appendChild(chip(view.coverage.not_executed_lines + ' not executed'));
      coverage.appendChild(chip(view.coverage.not_measured_lines + ' not measured'));
    } else if (view.coverage.reason) {
      coverage.appendChild(chip(view.coverage.reason));
    }
    holder.appendChild(coverage);
  }

  if (view.unverified && view.unverified.length > 0) {
    const title = document.createElement('p');
    title.className = 'note';
    title.textContent = 'Left unverified by this run:';
    holder.appendChild(title);
    const list = document.createElement('ul');
    for (const item of view.unverified) {
      const li = document.createElement('li');
      li.className = 'note';
      li.textContent = item;
      list.appendChild(li);
    }
    holder.appendChild(list);
  }

  if (view.diff_truncated) {
    const truncated = document.createElement('p');
    truncated.className = 'note';
    truncated.textContent = 'The diff of this change was too large to render in full; download the JSON report for everything.';
    holder.appendChild(truncated);
  }
}

/* ------------------------------------------------------------------ live -- */

function connectEvents() {
  const stream = new EventSource('/api/events');
  stream.onmessage = (message) => {
    let event;
    try { event = JSON.parse(message.data); } catch (err) { return; }
    if (event.type === 'repo' && event.repo) {
      const previous = state.repos.get(event.repo.key);
      state.repos.set(event.repo.key, event.repo);
      renderRepos();
      // The report of the repository on screen refreshes on its own; another
      // repository only gets a discreet notice.
      if (event.repo.key === state.repoKey && event.repo.latest
        && event.repo.latest.status === 'done'
        && (!previous || !previous.latest || previous.latest.commit !== event.repo.latest.commit)) {
        state.commit = event.repo.latest.commit;
        loadHistory();
      }
    } else if (event.type === 'report') {
      const repo = state.repos.get(event.repo_key);
      if (event.repo_key === state.repoKey) {
        state.commit = event.commit;
        loadHistory();
      } else if (repo) {
        toast('New report for ' + repo.full_name + ' (' + shortSha(event.commit) + ').');
      }
    } else if (event.type === 'sync' && event.status === 'finished') {
      loadRepos();
      toast('Repository list refreshed (' + event.count + ').');
    } else if (event.type === 'sync' && event.status === 'failed') {
      toast(event.error || 'The repository sync failed.', true);
    }
  };
  stream.onerror = () => { /* EventSource retries on its own. */ };
}

/* ------------------------------------------------------------------ boot -- */

async function loadRepos() {
  const payload = await api('/api/repos');
  state.repos = new Map((payload.repos || []).map((repo) => [repo.key, repo]));
  renderRepos();
}

function readHash() {
  const match = /^#\/repo\/([^/]+)(?:\/commit\/([0-9a-f]+))?/.exec(window.location.hash || '');
  if (!match) return null;
  return { repoKey: decodeURIComponent(match[1]), commit: match[2] || null };
}

async function boot() {
  let me;
  try {
    me = await api('/api/me');
  } catch (err) {
    window.location.replace('/index.html');
    return;
  }
  if (!me.authenticated) {
    window.location.replace('/index.html');
    return;
  }
  state.me = me;
  state.csrf = me.csrf;
  el('mode-label').textContent = 'Hub ' + (me.version || '') + ' · ' + (me.mode || 'lint') + ' mode';

  const who = el('who');
  if (me.user.avatar_url) {
    const avatar = document.createElement('img');
    avatar.src = me.user.avatar_url;
    avatar.alt = '';
    who.appendChild(avatar);
  }
  who.appendChild(document.createTextNode(me.user.login + ' · ' + me.user.provider));

  el('signout').addEventListener('click', async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch (err) { /* ignore */ }
    window.location.replace('/index.html');
  });
  el('sync').addEventListener('click', async (event) => {
    event.target.disabled = true;
    try {
      await api('/api/repos/sync', { method: 'POST' });
      toast('Refreshing the repository list…');
    } catch (err) {
      toast(err.message, true);
    }
    setTimeout(() => { event.target.disabled = false; }, 3000);
  });
  el('repo-search').addEventListener('input', (event) => {
    state.query = event.target.value;
    renderRepos();
  });
  el('only-monitored').addEventListener('change', (event) => {
    state.onlyMonitored = event.target.checked;
    renderRepos();
  });
  el('only-nopolicy').addEventListener('change', (event) => {
    state.onlyMissing = event.target.checked;
    renderRepos();
  });
  el('severity').addEventListener('input', (event) => {
    state.minSeverity = Number(event.target.value);
    el('severity-value').textContent = LEVELS[state.minSeverity];
    renderAlerts();
  });
  el('history').addEventListener('change', (event) => {
    state.commit = event.target.value;
    state.expanded.clear();
    window.location.hash = '#/repo/' + state.repoKey + '/commit/' + state.commit;
    loadReport();
  });
  el('modal-close').addEventListener('click', closeModal);
  el('modal').addEventListener('click', (event) => {
    if (event.target === el('modal')) closeModal();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeModal();
  });
  window.addEventListener('hashchange', () => {
    const route = readHash();
    if (route && (route.repoKey !== state.repoKey || route.commit !== state.commit)) {
      selectRepo(route.repoKey, route.commit);
    }
  });

  await loadRepos();
  connectEvents();
  const route = readHash();
  if (route && state.repos.has(route.repoKey)) {
    selectRepo(route.repoKey, route.commit);
  }
  if (state.repos.size === 0) {
    // A fresh account has nothing yet; the sign-in already started a sync.
    toast('Listing your repositories…');
  }
}

document.addEventListener('DOMContentLoaded', boot);
