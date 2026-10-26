'use strict';

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char]));
const icon = (name, extra = '') => `<svg class="icon ${extra}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const labels = {safe: 'Likely safe', suspicious: 'Suspicious', spam: 'Likely spam'};
const colors = {safe: '#71935e', suspicious: '#b4974f', spam: '#c47760'};
const state = {page: 'analyzer', current: null, busy: false, offset: 0, total: 0, historyRequest: 0};
let toastTimer;
let searchTimer;
const emptyResult = $('#result-content').innerHTML;

const samples = {
  safe: {sender: 'Alex Morgan <alex@example.com>', subject: 'Coffee on Thursday?', body: 'Hi Jamie,\n\nIt was lovely catching up last week. Are you free for coffee on Thursday afternoon? There’s a new place near the office I’ve been meaning to try.\n\nNo rush — let me know what works for you.\n\nBest,\nAlex'},
  marketing: {sender: 'The Weekend Edit <hello@example.com>', subject: 'A little something for your weekend', body: 'Hi there,\n\nOur spring collection is here. Enjoy an exclusive deal: a 20% discount on your next order. This limited-time offer ends Sunday.\n\nBrowse the collection at https://example.com/collection\n\nYou’re receiving this because you signed up for our newsletter. To unsubscribe, visit https://example.com/preferences.\n\nThe Weekend Edit team'},
  phishing: {sender: 'PayPal Security <security@account-check.example>', subject: 'URGENT: Verify your account immediately', body: 'Dear customer,\n\nWe noticed unusual activity on your account. Your account will be suspended within 24 hours unless you verify your account immediately.\n\nPlease enter your password to confirm your identity at the secure portal below:\nhttp://bit.ly/account-security-check\n\nAct now to avoid losing access!!!\n\nPayPal Security Team'}
};

async function request(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${await window.PostmarkAuth.token()}`);
  const response = await fetch(url, {...options, headers});
  if (response.status === 401) window.location.replace('/auth/login');
  if (!response.ok) {
    let message = 'Something went wrong. Please try again.';
    try {
      const data = await response.json();
      message = Array.isArray(data.detail) ? data.detail.map(item => item.msg).join(' ') : data.detail || message;
    } catch { /* Use a readable fallback when a proxy returns a non-JSON error. */ }
    throw new Error(message);
  }
  return options.asBlob ? response.blob() : response.json();
}

function toast(message) {
  clearTimeout(toastTimer);
  $('#toast').textContent = message;
  $('#toast').hidden = false;
  toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 4500);
}

function navigate(page) {
  if (!['analyzer', 'history', 'engine'].includes(page)) page = 'analyzer';
  state.page = page;
  $$('.page').forEach(section => { section.hidden = section.id !== `page-${page}`; });
  $$('.nav-item').forEach(button => button.classList.toggle('active', button.dataset.page === page));
  $('#breadcrumb-page').textContent = {analyzer: 'Email analyzer', history: 'Analysis history', engine: 'Detection engine'}[page];
  window.history.replaceState(null, '', `#${page}`);
  if (page === 'history') loadHistory().catch(error => toast(error.message));
  if (page === 'engine') loadRules().catch(error => toast(error.message));
}

$$('[data-page]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.page)));
$$('[data-navigate]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.navigate)));
window.addEventListener('hashchange', () => navigate(location.hash.slice(1)));

function updateCount() {
  $('#char-count').textContent = `${$('#body').value.length.toLocaleString()} / 50,000`;
}
$('#body').addEventListener('input', updateCount);

function setInputMode(mode) {
  const upload = mode === 'upload';
  $('#upload-panel').hidden = !upload;
  $('#paste-panel').hidden = upload;
  $('#paste-tab').classList.toggle('active', !upload);
  $('#upload-tab').classList.toggle('active', upload);
  $('#paste-tab').setAttribute('aria-selected', String(!upload));
  $('#upload-tab').setAttribute('aria-selected', String(upload));
  $('#analyze-button').disabled = upload || state.busy;
}
$('#paste-tab').addEventListener('click', () => setInputMode('paste'));
$('#upload-tab').addEventListener('click', () => setInputMode('upload'));
$$('.input-tab').forEach((tab, index, tabs) => tab.addEventListener('keydown', event => {
  if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
    event.preventDefault();
    const next = tabs[(index + 1) % tabs.length];
    next.click(); next.focus();
  }
}));

$('#sample-button').addEventListener('click', () => {
  $('#sample-menu').hidden = !$('#sample-menu').hidden;
  $('#sample-button').setAttribute('aria-expanded', String(!$('#sample-menu').hidden));
});
document.addEventListener('click', event => {
  if (!event.target.closest('.sample-wrap')) {
    $('#sample-menu').hidden = true;
    $('#sample-button').setAttribute('aria-expanded', 'false');
  }
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    $('#sample-menu').hidden = true;
    $('#sample-button').setAttribute('aria-expanded', 'false');
  }
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter' && state.page === 'analyzer' && !state.busy && !$('#paste-panel').hidden) {
    event.preventDefault(); $('#analysis-form').requestSubmit();
  }
});
$$('[data-sample]').forEach(button => button.addEventListener('click', () => {
  const sample = samples[button.dataset.sample];
  for (const key of ['sender', 'subject', 'body']) $(`#${key}`).value = sample[key];
  updateCount();
  $('#sample-menu').hidden = true;
  $('#sample-button').setAttribute('aria-expanded', 'false');
  $('#form-error').hidden = true;
  $('#body').focus();
}));

$('#clear-button').addEventListener('click', () => {
  if (state.busy) return;
  $('#analysis-form').reset();
  $('#form-error').hidden = true;
  $('#file-input').value = '';
  updateCount();
  setInputMode('paste');
  state.current = null;
  $('#result-content').innerHTML = emptyResult;
  $('#result-badge').className = 'badge neutral';
  $('#result-badge').innerHTML = '<span class="small-dot"></span>Awaiting email';
  $('#sender').focus();
});

async function importFile(file) {
  if (!file || state.busy) return;
  if (file.size > 100000) return toast('Files must be smaller than 100 KB.');
  if (!/\.(eml|txt)$/i.test(file.name)) return toast('Please choose an .eml or .txt file.');
  const data = new FormData();
  data.append('file', file);
  $('#dropzone').setAttribute('aria-busy', 'true');
  try {
    const result = await request('/api/import', {method: 'POST', body: data});
    for (const key of ['sender', 'subject', 'body']) $(`#${key}`).value = result[key];
    setInputMode('paste');
    updateCount();
    toast('Email imported. Ready for a closer look.');
  } catch (error) { toast(error.message); }
  finally { $('#dropzone').removeAttribute('aria-busy'); $('#file-input').value = ''; }
}
$('#file-input').addEventListener('change', event => importFile(event.target.files[0]));
['dragenter', 'dragover'].forEach(name => $('#dropzone').addEventListener(name, event => {
  event.preventDefault(); $('#dropzone').classList.add('dragover');
}));
['dragleave', 'drop'].forEach(name => $('#dropzone').addEventListener(name, event => {
  event.preventDefault(); $('#dropzone').classList.remove('dragover');
}));
$('#dropzone').addEventListener('drop', event => importFile(event.dataTransfer.files[0]));

$('#analysis-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy) return;
  const values = Object.fromEntries(['sender', 'subject', 'body'].map(key => [key, $(`#${key}`).value.trim()]));
  if (!values.body) {
    $('#form-error').textContent = 'Add some email content to analyze.';
    $('#form-error').hidden = false;
    return;
  }
  const previous = state.current;
  state.busy = true;
  $('#analyze-button').disabled = true;
  $('#clear-button').disabled = true;
  $$('#analysis-form input, #analysis-form textarea, #sample-button, .input-tab').forEach(input => { input.disabled = true; });
  $('#analyze-button span').textContent = 'Analyzing…';
  $('#result-panel').setAttribute('aria-busy', 'true');
  $('#form-error').hidden = true;
  $('#result-content').innerHTML = '<div class="result-loading"><div class="loading-orbit"></div>Connecting the dots…<p>Checking language, links, sender, and formatting.</p></div>';
  $('#result-badge').className = 'badge neutral';
  $('#result-badge').innerHTML = '<span class="small-dot"></span>Analyzing';
  try {
    state.current = await request('/api/analyze', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(values)});
    renderResult(state.current);
    await refreshWorkspace();
  } catch (error) {
    $('#form-error').textContent = error.message;
    $('#form-error').hidden = false;
    if (previous) renderResult(previous);
    else {
      $('#result-content').innerHTML = emptyResult;
      $('#result-badge').className = 'badge neutral';
      $('#result-badge').innerHTML = '<span class="small-dot"></span>Awaiting email';
    }
  } finally {
    state.busy = false;
    $('#analyze-button').disabled = false;
    $('#clear-button').disabled = false;
    $$('#analysis-form input, #analysis-form textarea, #sample-button, .input-tab').forEach(input => { input.disabled = false; });
    $('#analyze-button span').textContent = 'Analyze email';
    $('#result-panel').setAttribute('aria-busy', 'false');
  }
});

function renderResult(result) {
  $('#result-badge').className = `badge ${result.verdict}`;
  $('#result-badge').innerHTML = `<span class="small-dot"></span>${labels[result.verdict]}`;
  const circumference = 2 * Math.PI * 46;
  const maxCategory = Math.max(40, ...Object.values(result.categories));
  const findings = result.signals.length ? `<div class="signal-list">${result.signals.map(signal => `<div class="signal"><div class="signal-top"><span>${escapeHtml(signal.name)}</span><span class="signal-points">${signal.id === 'ml_model' ? `${signal.points} / 100` : `+${signal.points} pts`}</span></div><p>${escapeHtml(signal.explanation)}</p>${signal.matches.map(match => `<span class="signal-match">${escapeHtml(match)}</span>`).join('')}</div>`).join('')}</div>` : `<div class="no-signals">${icon('check')}<span>No known risk signals matched. Stay mindful: an unflagged message is not proof of authenticity.</span></div>`;
  $('#result-content').innerHTML = `<div class="analysis-result" style="--verdict-color:${colors[result.verdict]}"><div class="score-overview"><div class="score-ring"><svg viewBox="0 0 110 110" aria-hidden="true"><circle class="ring-track" cx="55" cy="55" r="46"/><circle class="ring-fill" cx="55" cy="55" r="46" stroke-dasharray="${circumference}" stroke-dashoffset="${circumference * (1 - result.score / 100)}"/></svg><div class="score-ring-label"><strong>${result.score}</strong><span>RISK SCORE / 100</span></div></div><div class="score-copy"><h3>${labels[result.verdict]}</h3><p>${escapeHtml(result.summary)}</p></div></div><div class="findings-title">What we picked up<span>${result.signals.length} signal${result.signals.length !== 1 ? 's' : ''} detected</span></div>${findings}<div class="category-chart">${Object.entries(result.categories).map(([name, score]) => `<div class="category-row"><span>${escapeHtml(name)}</span><div class="category-track"><span style="width:${score / maxCategory * 100}%"></span></div><span>${score}</span></div>`).join('')}</div><div class="analysis-meta"><span>${result.word_count} words · ${result.link_count} link${result.link_count !== 1 ? 's' : ''}</span><span>${result.elapsed_ms} ms · ${escapeHtml(result.engine_version)}</span></div><div class="report-actions"><button class="text-button" id="download-report">${icon('download')}Download report</button></div></div>`;
  $('#download-report').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], {type: 'application/json'});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `postmark-${result.id}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });
}

function renderTable(items, emptyMessage = 'Your first analysis will appear here.') {
  if (!items.length) return `<div class="empty-history"><span class="empty-history-icon">${icon('history')}</span><div><strong>No analyses to show.</strong><p>${escapeHtml(emptyMessage)}</p></div></div>`;
  return `<div class="table-scroll"><table><thead><tr><th>Email</th><th>Verdict</th><th>Risk score</th><th class="table-date">Analyzed</th><th><span class="sr-only">Open report</span></th></tr></thead><tbody>${items.map(item => `<tr><td class="subject-cell"><button data-analysis="${item.id}">${escapeHtml(item.subject || '(No subject)')}</button><small>${escapeHtml(item.sender || 'No sender provided')}</small></td><td><span class="badge ${item.verdict}"><span class="small-dot"></span>${labels[item.verdict]}</span></td><td><span class="table-score">${item.score}</span><span class="tiny muted"> / 100</span></td><td class="table-date">${escapeHtml(new Date(item.created_at).toLocaleDateString(undefined, {month: 'short', day: 'numeric'}))}<br><span class="muted">${escapeHtml(new Date(item.created_at).toLocaleTimeString(undefined, {hour: '2-digit', minute: '2-digit'}))}</span></td><td><button class="table-open" data-analysis="${item.id}" aria-label="Open analysis for ${escapeHtml(item.subject || 'untitled email')}">${icon('arrow')}</button></td></tr>`).join('')}</tbody></table></div>`;
}

document.addEventListener('click', async event => {
  const button = event.target.closest('[data-analysis]');
  if (!button || state.busy) return;
  try {
    const result = await request(`/api/analyses/${button.dataset.analysis}`);
    state.current = result;
    for (const key of ['sender', 'subject', 'body']) $(`#${key}`).value = result[key];
    updateCount();
    setInputMode('paste');
    $('#form-error').hidden = true;
    navigate('analyzer');
    renderResult(result);
    $('#result-panel').scrollIntoView({behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start'});
  } catch (error) { toast(error.message); }
});

async function refreshWorkspace() {
  const results = await Promise.allSettled([request('/api/stats'), request('/api/analyses?limit=4')]);
  if (results[0].status === 'fulfilled') {
    const stats = results[0].value;
    $('#stat-total').textContent = stats.total.toLocaleString();
    $('#stat-safe').textContent = stats.safe.toLocaleString();
    $('#stat-flagged').textContent = (stats.suspicious + stats.spam).toLocaleString();
    $('#stat-time').innerHTML = `${stats.average_ms === null ? '—' : stats.average_ms}<span> ms</span>`;
    $('#nav-count').textContent = stats.total;
  }
  if (results[1].status === 'fulfilled' && results[1].value.total) $('#recent-list').innerHTML = renderTable(results[1].value.items);
  const failed = results.find(result => result.status === 'rejected');
  if (failed) toast(`Could not refresh workspace: ${failed.reason.message}`);
}

async function loadHistory() {
  const requestId = ++state.historyRequest;
  const params = new URLSearchParams({limit: '10', offset: String(state.offset)});
  if ($('#history-search').value.trim()) params.set('q', $('#history-search').value.trim());
  if ($('#history-filter').value) params.set('verdict', $('#history-filter').value);
  const data = await request(`/api/analyses?${params}`);
  if (requestId !== state.historyRequest) return;
  state.total = data.total;
  $('#history-list').innerHTML = renderTable(data.items, 'Try another search, or analyze an email to start your history.');
  $('#history-total').textContent = data.total ? `Showing ${state.offset + 1}–${Math.min(state.offset + 10, data.total)} of ${data.total}` : '0 analyses';
  $('#previous-page').disabled = state.offset === 0;
  $('#next-page').disabled = state.offset + 10 >= data.total;
}
$('#history-search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  // Invalidate older requests immediately, including during the debounce window.
  state.historyRequest++;
  searchTimer = setTimeout(() => { state.offset = 0; loadHistory().catch(error => toast(error.message)); }, 250);
});
$('#history-filter').addEventListener('change', () => { state.offset = 0; loadHistory().catch(error => toast(error.message)); });
$('#previous-page').addEventListener('click', () => { state.offset = Math.max(0, state.offset - 10); loadHistory().catch(error => toast(error.message)); });
$('#next-page').addEventListener('click', () => { state.offset += 10; loadHistory().catch(error => toast(error.message)); });

let rulesLoaded = false;
async function loadRules() {
  if (rulesLoaded) return;
  const [data, model] = await Promise.all([request('/api/rules'), request('/api/model')]);
  $('#model-summary').textContent = `Trained on ${model.splits.train.total.toLocaleString()} labeled messages with ${model.feature_count.toLocaleString()} learned TF-IDF features. Held-out text-model test: ${(model.test.accuracy * 100).toFixed(2)}% accuracy, ${(model.test.spam_precision * 100).toFixed(2)}% spam precision, ${(model.test.spam_recall * 100).toFixed(2)}% spam recall (${model.splits.test.total} messages). These figures exclude supplemental checks and measure a historical corpus, not current inbox performance.`;
  $('#rules-list').innerHTML = data.rules.map(rule => `<div class="rule-row"><div><h3>${escapeHtml(rule.name)}</h3><p>${escapeHtml(rule.description)}</p></div><span class="rule-category">${escapeHtml(rule.category)}</span><span class="rule-weight">+${rule.points} pts</span></div>`).join('');
  rulesLoaded = true;
}

async function initialize() {
  if (!await window.PostmarkAuth.ready) return;
  navigate(location.hash.slice(1));
  try {
    await request('/api/health');
    await refreshWorkspace();
  } catch (error) {
    $('#system-status').innerHTML = '<span class="small-dot red-dot"></span>Engine unavailable';
    toast('The server is unavailable. Start the Python app and refresh.');
  }
}

$('#export-history').addEventListener('click', async () => {
  const button = $('#export-history');
  button.disabled = true;
  try {
    const blob = await request('/api/export', {asBlob: true});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'postmark-history.csv';
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; }
});
initialize();
