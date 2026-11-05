const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const lines = (s) => s.split('\n').map((l) => l.trim()).filter(Boolean);

class AuthError extends Error {}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(`/api/${path}`, {
    method,
    headers: method === 'GET' ? {} : { 'Content-Type': 'application/json' },
    body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) throw new AuthError(data.error);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ---- Login ---------------------------------------------------------------

function showLogin() {
  $('login').hidden = false;
  document.querySelectorAll('.view').forEach((v) => { v.hidden = true; });
  stopPolling();
}

async function login(token) {
  await api('login', { method: 'POST', body: { token } });
  $('login').hidden = true;
  showTab('overview');
}

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try { await login($('login-token').value); $('login-token').value = ''; }
  catch (err) { $('login-error').textContent = err.message; }
});

// ---- Tabs ----------------------------------------------------------------

let pollTimer = null;
const stopPolling = () => { clearInterval(pollTimer); pollTimer = null; };

function showTab(name) {
  document.querySelectorAll('.view').forEach((v) => { v.hidden = v.id !== `view-${name}`; });
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  stopPolling();
  if (name === 'overview') { loadNodeList(); refresh(); pollTimer = setInterval(refresh, 1500); }
  if (name === 'settings') loadSettings().catch(handleError);
  if (name === 'preflight') loadPreflight().catch(handleError);
}

$('tabs').addEventListener('click', (e) => { if (e.target.dataset.tab) showTab(e.target.dataset.tab); });

function handleError(err) {
  if (err instanceof AuthError) showLogin();
  else console.error(err);
}

// ---- Overview ------------------------------------------------------------

const mark = (status) => ({ ok: '✓', fail: '✕', warn: '!', pending: '…' }[status]);

function checkRow(status, label, detail) {
  return `<li><span class="mark ${status}" aria-label="${status}">${mark(status)}</span><span>${esc(label)}</span><span class="detail">${esc(detail)}</span></li>`;
}

function renderProtection(p, guard) {
  $('protection').className = `status-card ${p.state}`;
  $('protection-title').textContent = {
    protected: '全机防护生效中',
    exposed: '全机防护未生效',
    unknown: '全机防护状态未知',
  }[p.state];
  $('protection-detail').textContent = p.detail;
  $('guard-detail').textContent = guard.active
    ? `连接守卫运行中，已断开 ${guard.killed} 条走错节点的连接${guard.recent[0] ? `（最近：${guard.recent[0].host} 经 ${guard.recent[0].via}）` : ''}`
    : `连接守卫未运行：${guard.error}`;
  $('rules-alert').hidden = !guard.rulesChanged;
}

function renderGates({ locked, nodes }) {
  $('lock-btn').textContent = locked ? '解除锁定' : '断开所有实例';
  $('lock-btn').dataset.locked = locked ? '1' : '';
  const entries = Object.entries(nodes);
  if (!entries.length) {
    $('gates').innerHTML = '<div class="empty">新建经节点联网的实例后，这里会显示对应节点的状态。</div>';
    return;
  }
  $('gates').innerHTML = entries.map(([node, g]) => {
    const waiting = !g.open && !g.locked && g.stableElapsedSec > 0 ? `（已稳定 ${g.stableElapsedSec}/${g.stableSec} 秒）` : '';
    const badge = g.open ? '<span class="badge run">已放行</span>' : '<span class="badge closed">已断开</span>';
    const checks = g.checks.map((c) => checkRow(c.pending ? 'pending' : c.ok ? 'ok' : 'fail', c.label, c.detail)).join('');
    return `<div class="gate">
      <div class="gate-name">${esc(node)} ${badge}</div>
      <div class="muted">${esc((g.open ? `已放行 ${duration(Date.now() - g.since)}` : g.reason) + waiting)}</div>
      <ul class="checks">${checks}</ul>
    </div>`;
  }).join('');
}

function duration(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s} 秒`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟`;
  return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分钟`;
}

function bytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

let appsById = new Map();

function renderApps(apps) {
  appsById = new Map(apps.map((a) => [a.id, a]));
  if (!apps.length) {
    $('apps').innerHTML = '<div class="empty">还没有实例。新建一个，再用「泄漏自检」确认沙盒有效。</div>';
    return;
  }
  $('apps').innerHTML = apps.map((a) => {
    const net = a.network === 'gate'
      ? `闸门端口 ${a.port} · ${a.conns} 个连接 · ↑${bytes(a.stats.up)} ↓${bytes(a.stats.down)} · 拒绝 ${a.stats.refused}`
      : '完全禁网';
    const exit = !a.running && a.lastExit ? ` · 上次退出码 ${a.lastExit.code ?? a.lastExit.signal}` : '';
    const node = a.network === 'gate'
      ? `<span class="badge ${a.gateOpen ? 'run' : 'closed'}">${esc(a.node)}</span>`
      : '';
    return `<div class="app">
      <div class="app-main">
        <div class="app-name">${esc(a.name)} <span class="badge ${a.running ? 'run' : ''}">${a.running ? `运行中 ${a.pid}` : '已停止'}</span> ${node}</div>
        <div class="muted mono">${esc([a.command, ...a.args].join(' '))}</div>
        <div class="muted">${esc(net + exit)}</div>
      </div>
      <div class="actions">
        <button class="btn ${a.running ? '' : 'primary'}" data-act="${a.running ? 'stop' : 'start'}" data-id="${a.id}">${a.running ? '停止' : '启动'}</button>
        <button class="btn" data-act="duplicate" data-id="${a.id}">再开一个</button>
        <button class="btn" data-act="verify" data-id="${a.id}">泄漏自检</button>
        <button class="btn" data-act="logs" data-id="${a.id}">日志</button>
        <button class="btn" data-act="profile" data-id="${a.id}">沙盒配置</button>
        <button class="btn" data-act="edit" data-id="${a.id}">编辑</button>
        <button class="btn" data-act="delete" data-id="${a.id}" ${a.running ? 'disabled' : ''}>删除</button>
      </div>
    </div>`;
  }).join('');
}

let refreshing = false;
let actionInFlight = false;

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const s = await api('state');
    renderProtection(s.protection, s.guard);
    renderGates(s.gates);
    if (!actionInFlight) renderApps(s.apps);
  } catch (err) {
    handleError(err);
    if (!(err instanceof AuthError)) {
      $('protection').className = 'status-card unknown';
      $('protection-title').textContent = '无法连接 SandGate';
      $('protection-detail').textContent = '守护进程不可达。沙盒实例已断网，pf 防护如已安装则不受影响。';
      $('guard-detail').textContent = '';
    }
  } finally {
    refreshing = false;
  }
}

$('lock-btn').addEventListener('click', async () => {
  try { renderGates(await api('gate/lock', { method: 'POST', body: { locked: !$('lock-btn').dataset.locked } })); }
  catch (err) { handleError(err); }
});

$('accept-rules').addEventListener('click', async () => {
  try { await api('guard/accept-rules', { method: 'POST' }); refresh(); }
  catch (err) { handleError(err); }
});

// Two-step delete: native confirm() dialogs block the whole page.
const armedDelete = { id: null, timer: null };

$('apps').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const { act, id } = btn.dataset;
  const app = appsById.get(id);
  try {
    if (act === 'edit') return openAppDialog(app);
    if (act === 'duplicate') return openAppDialog(app, { duplicate: true });
    if (act === 'delete') {
      if (armedDelete.id !== id) {
        clearTimeout(armedDelete.timer);
        armedDelete.id = id;
        actionInFlight = true;
        btn.textContent = '确认删除';
        armedDelete.timer = setTimeout(() => { armedDelete.id = null; actionInFlight = false; refresh(); }, 3000);
        return;
      }
      clearTimeout(armedDelete.timer);
      armedDelete.id = null;
      actionInFlight = false;
      await api(`apps/${id}`, { method: 'DELETE', body: {} });
    } else if (act === 'logs') {
      const { text } = await api(`apps/${id}/logs`);
      return showOutput(`日志：${app.name}`, text || '（暂无日志）');
    } else if (act === 'profile') {
      const { text } = await api(`apps/${id}/profile`);
      return showOutput(`沙盒配置：${app.name}`, text);
    } else if (act === 'verify') {
      btn.disabled = true;
      btn.textContent = '检查中…';
      actionInFlight = true;
      const r = await api(`apps/${id}/verify`, { method: 'POST' });
      return showVerify(app, r);
    } else {
      btn.disabled = true;
      await api(`apps/${id}/${act}`, { method: 'POST' });
    }
  } catch (err) {
    if (err instanceof AuthError) return showLogin();
    showOutput('操作失败', err.message);
  } finally {
    if (act === 'verify') actionInFlight = false;
    refresh();
  }
});

function showOutput(title, text) {
  $('output-title').textContent = title;
  $('output-list').innerHTML = '';
  $('output-list').hidden = true;
  $('output-text').hidden = false;
  $('output-text').textContent = text;
  $('output-dialog').showModal();
}

function showVerify(app, r) {
  const state = r.gateOpen ? '闸门开启' : '闸门关闭';
  $('output-title').textContent = `泄漏自检：${app.name}（${state}）${r.ok ? '全部通过' : '发现问题'}`;
  $('output-list').hidden = false;
  $('output-list').innerHTML = r.results.map((x) => checkRow(x.ok ? 'ok' : 'fail', x.label, x.detail)).join('');
  $('output-text').hidden = true;
  $('output-dialog').showModal();
}

$('output-close').addEventListener('click', () => $('output-dialog').close());

// ---- App dialog ----------------------------------------------------------

const PRESETS = {
  cli: {
    note: '程序需读取 HTTP_PROXY / ALL_PROXY。不读取的程序会一直断网，不会泄漏。',
    apply(f) { f.blockBrokers.checked = true; f.allowUnixSockets.checked = false; },
  },
  chromium: {
    note: '已加入 --proxy-server 和独立的 --user-data-dir，可以多开。Chromium 自带沙盒不能嵌套，需要 --no-sandbox，渲染进程的隔离会减弱。',
    apply(f) {
      f.blockBrokers.checked = false;
      f.allowUnixSockets.checked = true;
      if (!f.args.value.trim()) f.args.value = '--proxy-server=socks5://127.0.0.1:{port}\n--user-data-dir={home}/profile\n--no-sandbox';
    },
  },
};

let editingId = null;

function syncNetworkField() {
  const f = $('app-form');
  $('node-field').hidden = f.network.value !== 'gate';
  f.node.required = f.network.value === 'gate';
}

function fillAppForm(f, app) {
  f.name.value = app.name;
  f.command.value = app.command;
  f.args.value = app.args.join('\n');
  f.cwd.value = app.cwd;
  f.env.value = Object.entries(app.env).map(([k, v]) => `${k}=${v}`).join('\n');
  f.network.value = app.network;
  f.node.value = app.node;
  f.isolateHome.checked = app.isolateHome;
  f.blockBrokers.checked = app.blockBrokers;
  f.allowUnixSockets.checked = app.allowUnixSockets;
  f.restrictWrites.checked = app.restrictWrites;
  f.writable.value = app.writable.join('\n');
  f.protected.value = app.protected.join('\n');
}

function openAppDialog(app, { duplicate = false } = {}) {
  editingId = app && !duplicate ? app.id : null;
  const f = $('app-form');
  f.reset();
  $('app-error').textContent = '';
  $('preset-field').hidden = Boolean(app);
  $('preset-note').textContent = '';
  if (app) {
    fillAppForm(f, app);
    if (duplicate) {
      // A second copy must not share a data directory, and usually wants another node.
      f.name.value = `${app.name} 2`;
      f.node.value = '';
      f.isolateHome.checked = true;
      $('app-dialog-title').textContent = `再开一个：${app.name}`;
    } else {
      $('app-dialog-title').textContent = `编辑：${app.name}${app.running ? '（重启后生效）' : ''}`;
    }
  } else {
    $('app-dialog-title').textContent = '新建实例';
    f.isolateHome.checked = true;
    applyPreset();
  }
  syncNetworkField();
  $('app-dialog').showModal();
}

function applyPreset() {
  const f = $('app-form');
  const p = PRESETS[f.preset.value];
  p.apply(f);
  $('preset-note').textContent = p.note;
}

$('app-form').preset.addEventListener('change', applyPreset);
$('app-form').network.addEventListener('change', syncNetworkField);
$('add-app').addEventListener('click', () => openAppDialog());
$('app-cancel').addEventListener('click', () => $('app-dialog').close());

$('app-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const env = {};
  for (const l of lines(f.env.value)) {
    const i = l.indexOf('=');
    if (i < 1) { $('app-error').textContent = `环境变量格式错误: ${l}`; return; }
    env[l.slice(0, i)] = l.slice(i + 1);
  }
  const body = {
    name: f.name.value,
    command: f.command.value,
    args: lines(f.args.value),
    cwd: f.cwd.value.trim(),
    env,
    network: f.network.value,
    node: f.node.value,
    isolateHome: f.isolateHome.checked,
    blockBrokers: f.blockBrokers.checked,
    allowUnixSockets: f.allowUnixSockets.checked,
    restrictWrites: f.restrictWrites.checked,
    writable: lines(f.writable.value),
    protected: lines(f.protected.value),
  };
  try {
    if (editingId) await api(`apps/${editingId}`, { method: 'PUT', body });
    else await api('apps', { method: 'POST', body });
    $('app-dialog').close();
    refresh();
  } catch (err) {
    if (err instanceof AuthError) return showLogin();
    $('app-error').textContent = err.message;
  }
});

// ---- Settings ------------------------------------------------------------

/** Fills the shared node suggestions. Nodes can still be typed if Clash is unreachable. */
async function loadNodeList() {
  try {
    const { nodes } = await api('clash/proxies');
    $('node-list').innerHTML = nodes.map((n) => `<option value="${esc(n.name)}"></option>`).join('');
    return null;
  } catch (err) {
    if (err instanceof AuthError) { showLogin(); return null; }
    return err.message;
  }
}

function renderExitIps(g) {
  const nodes = Object.keys(g.listeners);
  $('exit-ips').innerHTML = nodes.length
    ? `<div class="muted">期望出口 IP（留空不检查；填写后会定期请求下方的查询地址）</div>${nodes.map((n) => `
      <div class="exit-row">
        <span>${esc(n)}</span>
        <input data-exit-node="${esc(n)}" value="${esc(g.exitIps[n] ?? '')}" spellcheck="false" aria-label="${esc(n)} 的期望出口 IP">
        <button type="button" class="btn small" data-read-exit="${esc(n)}">读取当前</button>
      </div>`).join('')}`
    : '';
}

function fillSettings({ gate: g, listenerSnippet, pfScript }) {
  const f = $('settings-form');
  f.ctype.value = g.controller.type;
  f.cport.value = g.controller.port;
  f.csock.value = g.controller.socketPath;
  f.csecret.value = '';
  f.csecret.placeholder = g.controller.hasSecret ? '已保存，留空保持不变' : '未设置';
  f.defaultNode.value = g.defaultNode;
  f.probeIface.value = g.probeInterface;
  f.pfTargets.value = g.pfTargets.join('\n');
  f.pfExtra.value = g.pfExtra.join('\n');
  f.pfCnList.value = g.pfCnList;
  f.stable.value = g.stableSec;
  f.requireTun.checked = g.requireTun;
  f.requireNode.checked = g.requireNode;
  f.requirePin.checked = g.requirePin;
  f.delayInt.value = g.delayIntervalSec;
  f.pinInt.value = g.pinIntervalSec;
  f.exitInt.value = g.exitIntervalSec;
  f.delayTo.value = g.delayTimeoutMs;
  f.probeUrl.value = g.probeUrl;
  f.exitUrl.value = g.exitIpUrl;
  $('snippet').textContent = listenerSnippet;
  $('pf-commands').textContent = [
    '# 安装：立即生效，之后每次开机自动加载',
    `sudo bash "${pfScript}" install`,
    '# 撤销，也是紧急恢复。安装后重启不会清除规则',
    `sudo bash "${pfScript}" uninstall`,
    '# 查看状态',
    `sudo bash "${pfScript}" status`,
    '# 只想临时试用：到时自动撤销，最长 86400 秒。已安装时要先撤销',
    `sudo bash "${pfScript}" trial 1800`,
  ].join('\n');
  renderExitIps(g);
}

function renderPfPlan(p) {
  if (!p) return;
  const rows = [];
  if (p.nodes?.length) rows.push(checkRow('ok', '涉及的节点', p.nodes.join('、')));
  if (p.updatedAt) rows.push(checkRow(p.ready ? 'ok' : 'fail', '放行列表', `节点 IP ${p.counts.ips ?? 0} 个，DNS ${p.counts.dns ?? 0} 个，国内网段 ${p.counts.cn ?? 0} 条，额外 ${p.counts.extra ?? 0} 条`));
  for (const w of p.warnings ?? []) rows.push(checkRow('warn', '注意', w));
  $('pf-plan').innerHTML = rows.join('');
}

async function loadSettings() {
  fillSettings(await api('settings'));
  renderPfPlan((await api('state')).pf);
  const problem = await loadNodeList();
  $('detect-note').textContent = problem ? `读取节点失败：${problem}` : '';
}

$('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const controller = { type: f.ctype.value, port: f.cport.value, socketPath: f.csock.value.trim() };
  if (f.csecret.value) controller.secret = f.csecret.value;
  const exitIps = {};
  document.querySelectorAll('[data-exit-node]').forEach((i) => { exitIps[i.dataset.exitNode] = i.value; });
  const gate = {
    controller,
    defaultNode: f.defaultNode.value.trim(),
    probeInterface: f.probeIface.value.trim(),
    pfTargets: lines(f.pfTargets.value),
    pfExtra: lines(f.pfExtra.value),
    pfCnList: f.pfCnList.value.trim(),
    exitIps,
    stableSec: f.stable.value,
    requireTun: f.requireTun.checked,
    requireNode: f.requireNode.checked,
    requirePin: f.requirePin.checked,
    delayIntervalSec: f.delayInt.value,
    pinIntervalSec: f.pinInt.value,
    exitIntervalSec: f.exitInt.value,
    delayTimeoutMs: f.delayTo.value,
    probeUrl: f.probeUrl.value,
    exitIpUrl: f.exitUrl.value,
  };
  try {
    const saved = await api('settings', { method: 'PUT', body: { gate } });
    fillSettings(saved);
    renderPfPlan(saved.pf);
    const problem = await loadNodeList();
    $('detect-note').textContent = problem ? `读取节点失败：${problem}` : '';
    $('settings-msg').textContent = '已保存';
  } catch (err) {
    if (err instanceof AuthError) return showLogin();
    $('settings-msg').textContent = err.message;
  }
});

$('detect').addEventListener('click', async () => {
  try {
    const r = await api('settings/detect', { method: 'POST' });
    fillSettings(r);
    const problem = await loadNodeList();
    const d = r.detected;
    const parts = [`已读取，通用端口 ${d.mixedPort ?? '未知'}`];
    if (d.type === 'unix' && !d.socketExists) parts.push('配置中的 socket 不存在，请在 Clash Verge 中开启外部控制后重新读取');
    if (problem) parts.push(`读取节点失败：${problem}`);
    $('detect-note').textContent = parts.join('。');
  } catch (err) {
    if (err instanceof AuthError) return showLogin();
    $('detect-note').textContent = err.message;
  }
});

$('exit-ips').addEventListener('click', async (e) => {
  const node = e.target.dataset.readExit;
  if (!node) return;
  const input = [...document.querySelectorAll('[data-exit-node]')].find((i) => i.dataset.exitNode === node);
  try {
    input.value = (await api('gate/exit-ip', { method: 'POST', body: { node } })).ip;
  } catch (err) {
    if (err instanceof AuthError) return showLogin();
    $('settings-msg').textContent = `读取失败：${err.message}`;
  }
});

$('copy-snippet').addEventListener('click', async (e) => {
  await navigator.clipboard.writeText($('snippet').textContent);
  e.target.textContent = '已复制';
  setTimeout(() => { e.target.textContent = '复制'; }, 1500);
});

// ---- Preflight -----------------------------------------------------------

async function loadPreflight() {
  $('preflight').innerHTML = '<li class="muted">检查中…</li>';
  const { items } = await api('preflight');
  $('preflight').innerHTML = items.map((i) => checkRow(i.status, i.label, i.detail)).join('');
}

$('rerun-preflight').addEventListener('click', () => loadPreflight().catch(handleError));

// ---- Boot ----------------------------------------------------------------

(async () => {
  const hash = new URLSearchParams(location.hash.slice(1));
  const token = hash.get('token');
  // Remove the token from the address bar and history straight away.
  if (token) history.replaceState(null, '', location.pathname);
  try {
    if (token) await login(token);
    else { await api('state'); showTab('overview'); }
  } catch {
    showLogin();
  }
})();
