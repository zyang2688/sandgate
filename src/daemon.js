import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { AppManager } from './apps.js';
import { ClashClient, ClashError, detectVerge } from './clash.js';
import { Store, ValidationError, mergeGateSettings, validateApp } from './config.js';
import { GateManager, defaultRouteInterface, fetchExitIp, tcpProbe } from './gate.js';
import { ConnectionGuard, ProtectionProbe, ipv6Check, modeWarning } from './guard.js';
import { ClashSync, FOLLOW, NO_NETWORK, isRuleKey, ruleKey, validateNetProfile } from './netprofile.js';
import { PfPlanner } from './pfplan.js';

const exec = promisify(execFile);
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC = path.join(ROOT, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const COOKIE = 'sandgate_session';
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

class HttpError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

export class Sandgate {
  /** `background: false` skips the guard and the direct-network probe, for tests. */
  constructor({ dir, port, background = true } = {}) {
    this.store = new Store(dir);
    this.portOverride = port;
    this.background = background;
    const getSettings = () => this.store.data.gate;
    this.client = new ClashClient(getSettings().controller);
    this.gates = new GateManager({ getSettings, client: this.client, locked: this.store.data.locked });
    this.apps = new AppManager({
      store: this.store,
      gates: this.gates,
      controllerSocket: () => (getSettings().controller.type === 'unix' ? getSettings().controller.socketPath : ''),
    });
    this.guard = new ConnectionGuard({
      client: this.client,
      getSettings,
      saveRulesHash: (hash) => {
        getSettings().rulesHash = hash;
        this.store.save();
      },
    });
    this.protection = new ProtectionProbe({ getSettings });
    this.pfPlanner = new PfPlanner({ store: this.store, getSettings });
    this.clashSync = new ClashSync({ store: this.store, client: this.client, enabled: background });
    this.session = crypto.randomBytes(24).toString('base64url');
    this.server = http.createServer((req, res) => this.#handle(req, res));
  }

  async start() {
    const port = this.portOverride ?? this.store.data.uiPort;
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(port, '127.0.0.1', resolve);
    });
    this.port = this.server.address().port;
    this.gates.sync(this.store.usedNodes());
    this.gates.start();
    await this.apps.adopt();
    if (this.background) {
      const stamp = () => new Date().toLocaleString('zh-CN', { hour12: false });
      this.gates.on('close', (node, reason) => console.log(`${stamp()} 闸门关闭 ${node}: ${reason}`));
      this.gates.on('open', (node) => console.log(`${stamp()} 闸门打开 ${node}`));
      this.guard.start();
      this.protection.start();
      this.pfPlanner.start();
      this.#syncOnStart();
    }
    return { url: `http://127.0.0.1:${this.port}/#token=${this.store.token}` };
  }

  /** `keepInstances` leaves them running for the next start to adopt. */
  async stop({ keepInstances = false } = {}) {
    this.guard.stop();
    this.protection.stop();
    this.pfPlanner.stop();
    this.gates.stop();
    if (keepInstances) await this.apps.release();
    else await this.apps.stopAll();
    this.server.closeAllConnections();
    await new Promise((resolve) => this.server.close(resolve));
  }

  /** Listeners can be missing after a profile switch in Clash Verge, so check on every start. */
  async #syncOnStart() {
    const ports = Object.keys(this.store.data.gate.listeners).length ? Object.values(this.store.data.gate.listeners) : [];
    const open = await Promise.all(ports.map((p) => tcpProbe(p).then(() => true, () => false)));
    if (open.includes(false)) return this.clashSync.apply();
    // Clash Verge may have rebuilt its config from a profile without the guard.
    if (this.store.data.gate.foreignDirectVia) {
      const live = await this.client.rules().catch(() => null);
      const guarded = live?.rules?.some((r) => String(r.payload).includes('sandgate-cn'));
      if (live && !guarded) return this.clashSync.apply();
    }
    try {
      this.clashSync.writeScript();
      this.clashSync.status = { state: 'ok', message: '已同步到 Clash', at: Date.now() };
    } catch (e) {
      this.clashSync.status = { state: 'warn', message: `脚本扩展没有更新：${e.message}`, at: Date.now() };
    }
    return this.clashSync.status;
  }

  #applyGateSettings() {
    this.client.cfg = this.store.data.gate.controller;
    this.gates.reconfigure();
  }

  // ---- HTTP plumbing ----------------------------------------------------

  /** A rebinding page reaches us with a foreign Host; a cross-site POST with a foreign Origin. */
  #checkOrigin(req) {
    const allowed = new Set([`127.0.0.1:${this.port}`, `localhost:${this.port}`]);
    if (!allowed.has(req.headers.host)) throw new HttpError(403, '不允许的 Host');
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const { origin } = req.headers;
      if (origin && ![...allowed].some((h) => origin === `http://${h}`)) throw new HttpError(403, '不允许的 Origin');
      if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) throw new HttpError(415, '需要 JSON 请求');
    }
  }

  #authed(req) {
    const cookies = String(req.headers.cookie ?? '').split(';').map((c) => c.trim());
    const value = cookies.find((c) => c.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
    return value !== undefined && safeEqual(value, this.session);
  }

  async #body(req) {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > 1024 * 1024) throw new HttpError(413, '请求过大');
      chunks.push(c);
    }
    if (!chunks.length) return {};
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
      return parsed;
    } catch {
      throw new HttpError(400, 'JSON 格式错误');
    }
  }

  #json(res, status, data, extra = {}) {
    res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...extra });
    res.end(JSON.stringify(data));
  }

  #static(url, res) {
    const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const ext = path.extname(rel);
    if (!MIME[ext] || rel.includes('/') || rel.includes('..')) throw new HttpError(404, '未找到');
    const file = path.join(PUBLIC, rel);
    if (!fs.existsSync(file)) throw new HttpError(404, '未找到');
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[ext] });
    res.end(fs.readFileSync(file));
  }

  async #handle(req, res) {
    try {
      this.#checkOrigin(req);
      const url = new URL(req.url, `http://127.0.0.1:${this.port}`);
      if (!url.pathname.startsWith('/api/')) {
        if (req.method !== 'GET') throw new HttpError(405, '方法不允许');
        return this.#static(url, res);
      }
      if (url.pathname === '/api/login' && req.method === 'POST') {
        const { token } = await this.#body(req);
        if (!token || !safeEqual(token, this.store.token)) throw new HttpError(401, '令牌错误');
        return this.#json(res, 200, { ok: true }, {
          'Set-Cookie': `${COOKIE}=${this.session}; HttpOnly; SameSite=Strict; Path=/`,
        });
      }
      if (!this.#authed(req)) throw new HttpError(401, '未登录');
      const result = await this.#route(req, url);
      this.#json(res, 200, result ?? { ok: true });
    } catch (e) {
      const status = e instanceof HttpError ? e.status : e instanceof ValidationError ? 400 : e instanceof ClashError ? 502 : 500;
      if (status === 500) console.error(e);
      if (!res.headersSent) this.#json(res, status, { error: e.message });
      else res.end();
    }
  }

  // ---- Routes -----------------------------------------------------------

  async #route(req, url) {
    const route = `${req.method} ${url.pathname}`;
    switch (route) {
      case 'GET /api/state': return this.#state();
      case 'GET /api/settings': return this.#publicSettings();
      case 'PUT /api/settings': return this.#putSettings(await this.#body(req));
      case 'POST /api/settings/detect': return this.#detect();
      case 'GET /api/clash/proxies': return this.client.proxies();
      case 'GET /api/preflight': return this.#preflight();
      case 'POST /api/gate/lock': return this.#lock(await this.#body(req));
      case 'POST /api/gate/exit-ip': return this.#exitIp(await this.#body(req));
      case 'POST /api/guard/accept-rules': this.guard.acceptRules(); return this.guard.status;
      case 'POST /api/apps': return this.#createApp(await this.#body(req));
      case 'GET /api/netprofiles/options': return this.#netOptions();
      case 'POST /api/netprofiles': return this.#createNetProfile(await this.#body(req));
      case 'POST /api/netprofiles/sync': return this.clashSync.apply();
    }
    const np = url.pathname.match(/^\/api\/netprofiles\/([0-9a-f]+)$/);
    if (np) {
      const profile = this.store.data.netProfiles.find((p) => p.id === np[1]);
      if (!profile) throw new HttpError(404, '配置不存在');
      if (req.method === 'PUT') return this.#updateNetProfile(profile, await this.#body(req));
      if (req.method === 'DELETE') return this.#deleteNetProfile(profile);
      throw new HttpError(405, '方法不允许');
    }
    const m = url.pathname.match(/^\/api\/apps\/([0-9a-f]+)(?:\/(start|stop|verify|logs|profile|clear-data))?$/);
    if (!m) throw new HttpError(404, '未找到');
    const [, id, action] = m;
    const app = this.apps.find(id);
    if (!app) throw new HttpError(404, '应用不存在');
    const key = `${req.method} ${action ?? ''}`;
    switch (key) {
      case 'PUT ': return this.#updateApp(app, await this.#body(req));
      case 'DELETE ': {
        await this.apps.remove(id);
        this.gates.sync(this.store.usedNodes());
        return undefined;
      }
      case 'POST start': return this.apps.start(id);
      case 'POST stop': return this.apps.stop(id);
      case 'POST clear-data': return this.apps.clearData(id);
      case 'POST verify': return this.apps.verify(id);
      case 'GET logs': return { text: this.apps.tail(id) };
      case 'GET profile': return { text: this.apps.profileFor(app) };
    }
    throw new HttpError(405, '方法不允许');
  }

  #state() {
    return {
      gates: this.gates.snapshot(),
      guard: this.guard.status,
      protection: this.protection.status,
      pf: this.pfPlanner.status,
      netProfiles: this.store.data.netProfiles,
      sync: this.clashSync.status,
      apps: this.store.data.apps.map((a) => this.apps.snapshot(a)),
    };
  }

  #activeListeners() {
    const { listeners } = this.store.data.gate;
    return Object.fromEntries(this.store.usedNodes().map((n) => [n, listeners[n]]));
  }

  #publicSettings() {
    const { secret, ...controller } = this.store.data.gate.controller;
    const { rulesHash: _hash, ...rest } = this.store.data.gate;
    const gate = { ...rest, controller: { ...controller, hasSecret: Boolean(secret) } };
    return {
      gate,
      pfScript: path.join(ROOT, 'scripts/sandgate-pf.sh'),
    };
  }

  async #putSettings(body) {
    const guardOf = (g) => JSON.stringify([g.foreignDirectVia, g.pfCnList, g.pfExtra]);
    const before = guardOf(this.store.data.gate);
    this.store.data.gate = mergeGateSettings(this.store.data.gate, body.gate ?? {});
    this.store.save();
    this.#applyGateSettings();
    if (this.background) this.pfPlanner.tick();
    // The guard lives in Clash's rules, so a change there needs a sync like a profile change.
    const sync = guardOf(this.store.data.gate) !== before ? await this.clashSync.apply() : undefined;
    return { ...this.#publicSettings(), pf: this.pfPlanner.status, ...(sync ? { sync } : {}) };
  }

  #detect() {
    const found = detectVerge();
    if (!found) throw new HttpError(404, '未找到 Clash Verge 配置');
    this.store.data.gate = mergeGateSettings(this.store.data.gate, { controller: found.controller });
    this.store.save();
    this.#applyGateSettings();
    return { ...this.#publicSettings(), detected: { mixedPort: found.mixedPort, socketExists: found.socketExists, type: found.controller.type } };
  }

  #lock({ locked }) {
    this.store.data.locked = Boolean(locked);
    this.store.save();
    this.gates.setLocked(locked);
    return this.gates.snapshot();
  }

  async #exitIp({ node }) {
    const port = this.store.data.gate.listeners[node];
    if (!port) throw new HttpError(404, '该节点没有 listener');
    return { ip: await fetchExitIp(port, this.store.data.gate.exitIpUrl) };
  }

  /** Assigns ports for a validated instance; its listener must exist before saving. */
  #assignPorts(app) {
    if (['gate', 'rules'].includes(app.network)) {
      app.port ??= this.store.allocatePort();
      this.store.listenerPort(app.node);
    } else {
      app.port = null;
    }
  }

  /** Derives an instance's network from its profile. A whole-node profile is made on first use. */
  #netFields(body, existing) {
    const legacy = body.network !== undefined || body.node !== undefined;
    const id = body.netProfile ?? (legacy ? undefined : existing?.netProfile);
    if (id === NO_NETWORK || (id === undefined && body.network === 'none')) return { netProfile: NO_NETWORK, network: 'none', node: '' };
    if (id === FOLLOW) return { netProfile: FOLLOW, network: 'open', node: '' };
    if (id === undefined || id === '') {
      const node = String(body.node ?? '').trim();
      if (!node) throw new ValidationError('请选择网络配置');
      const profile = this.store.nodeProfile(node);
      this.store.listenerPort(node);
      return { netProfile: profile.id, network: 'gate', node };
    }
    const profile = this.store.data.netProfiles.find((p) => p.id === id);
    if (!profile) throw new ValidationError('网络配置不存在');
    return profile.mode === 'node'
      ? { netProfile: id, network: 'gate', node: profile.node }
      : { netProfile: id, network: 'rules', node: ruleKey(id) };
  }

  /** A listener not yet in Clash means a sync. An existing profile's instances need none. */
  async #syncIfNewListener(before) {
    if (Object.keys(this.store.data.gate.listeners).length !== before) await this.clashSync.apply();
  }

  async #createApp(body) {
    const before = Object.keys(this.store.data.gate.listeners).length;
    const app = validateApp({ ...body, ...this.#netFields(body) });
    this.store.data.apps.push(app);
    this.#assignPorts(app);
    this.store.save();
    this.gates.sync(this.store.usedNodes());
    await this.#syncIfNewListener(before);
    return this.apps.snapshot(app);
  }

  async #netOptions() {
    const { nodes, groups } = await this.client.proxies();
    const builtin = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL']);
    const counts = new Map();
    for (const r of (await this.client.rules()).rules ?? []) {
      if (!builtin.has(r.proxy)) counts.set(r.proxy, (counts.get(r.proxy) ?? 0) + 1);
    }
    const policies = [...counts].map(([name, count]) => ({ name, count }));
    return { policies, targets: [...groups.map((g) => g.name), ...nodes.map((n) => n.name)] };
  }

  /** Gives a profile its listener now, so later instances never need a Clash reload. */
  #claimListener(profile) {
    this.store.listenerPort(profile.mode === 'node' ? profile.node : ruleKey(profile.id));
  }

  #profileApps(id) {
    return this.store.data.apps.filter((a) => a.netProfile === id);
  }

  async #createNetProfile(body) {
    const profile = validateNetProfile(body);
    if (profile.mode === 'node' && this.store.data.netProfiles.some((p) => p.mode === 'node' && p.node === profile.node)) {
      throw new HttpError(409, '这个节点已经有配置了');
    }
    this.store.data.netProfiles.push(profile);
    this.#claimListener(profile);
    this.store.save();
    return { profile, sync: await this.clashSync.apply() };
  }

  async #updateNetProfile(profile, body) {
    const next = validateNetProfile(body, profile);
    const users = this.#profileApps(profile.id);
    if (next.mode !== profile.mode && users.some((a) => this.apps.isRunning(a.id))) {
      throw new HttpError(409, '请先停止用这个配置的实例，再改模式');
    }
    if (next.mode === 'node' && this.store.data.netProfiles.some((p) => p !== profile && p.mode === 'node' && p.node === next.node)) {
      throw new HttpError(409, '这个节点已经有配置了');
    }
    const oldKey = profile.mode === 'node' ? profile.node : ruleKey(profile.id);
    Object.assign(profile, next);
    this.#claimListener(profile);
    const fields = this.#netFields({ netProfile: profile.id });
    for (const a of users) {
      Object.assign(a, fields);
      this.#assignPorts(a);
    }
    this.#releaseListener(oldKey);
    this.store.save();
    this.gates.sync(this.store.usedNodes());
    const sync = await this.clashSync.apply();
    // Connections keep the exit they started with, so end them for the new rules to apply.
    for (const a of users) this.apps.dropConnections(a.id);
    return { profile, sync, dropped: users.length };
  }

  async #deleteNetProfile(profile) {
    const users = this.#profileApps(profile.id);
    if (users.length) throw new HttpError(409, `还有实例在用这个配置：${users.map((a) => a.name).join('、')}`);
    this.store.data.netProfiles.splice(this.store.data.netProfiles.indexOf(profile), 1);
    this.#releaseListener(profile.mode === 'node' ? profile.node : ruleKey(profile.id));
    this.store.save();
    return { sync: await this.clashSync.apply() };
  }

  /** Frees a listener nothing uses any more. */
  #releaseListener(key) {
    const inUse = this.store.data.netProfiles.some((p) => (p.mode === 'node' ? p.node : ruleKey(p.id)) === key);
    if (!inUse) delete this.store.data.gate.listeners[key];
  }

  async #updateApp(app, body) {
    const before = Object.keys(this.store.data.gate.listeners).length;
    const next = validateApp({ ...body, ...this.#netFields(body, app) }, app);
    const networkChanged = next.network !== app.network || next.node !== app.node;
    if (networkChanged && this.apps.isRunning(app.id)) throw new HttpError(409, '请先停止应用再改节点或网络模式');
    if (!['gate', 'rules'].includes(next.network)) await this.apps.releasePort(app.id);
    Object.assign(app, next);
    this.#assignPorts(app);
    this.store.save();
    this.gates.sync(this.store.usedNodes());
    await this.#syncIfNewListener(before);
    return this.apps.snapshot(app);
  }

  async #preflight() {
    const { gate } = this.store.data;
    const items = [];
    const add = (id, label, status, detail) => items.push({ id, label, status, detail });

    try {
      await exec('/usr/bin/sandbox-exec', ['-p', '(version 1)(allow default)', '/usr/bin/true'], { timeout: 4000 });
      add('sandbox', 'sandbox-exec 可用', 'ok', '能加载配置');
    } catch (e) {
      add('sandbox', 'sandbox-exec 可用', 'fail', e.code === 71
        ? 'SandGate 本身运行在另一层沙盒里，无法嵌套。请从普通终端启动。'
        : e.message);
    }

    try {
      const iface = await defaultRouteInterface();
      add('route', '默认路由', iface.startsWith('utun') ? 'ok' : 'warn', iface || '无');
    } catch (e) { add('route', '默认路由', 'fail', e.message); }

    let cfg = null;
    try {
      const { version } = await this.client.version();
      cfg = await this.client.configs();
      add('controller', 'Clash 控制接口', 'ok', `${version}，${cfg.mode} 模式，TUN ${cfg.tun?.enable ? '已开启' : '未开启'}`);
      const warning = modeWarning(cfg.mode);
      add('mode', 'Clash 模式', warning ? 'warn' : 'ok', warning || 'rule 模式，按规则分流');
      const ipv6 = ipv6Check(this.protection.status.state, Boolean(cfg.ipv6));
      add('ipv6', 'IPv6', ipv6.status, ipv6.detail);
    } catch (e) {
      add('controller', 'Clash 控制接口', 'fail', `${e.message}。可在 Clash Verge 的设置中开启外部控制，再点「从 Clash Verge 读取」。`);
    }

    let knownNodes = null;
    if (cfg) {
      try { knownNodes = (await this.client.proxies()).nodes.map((n) => n.name); }
      catch (e) { add('nodes', '节点列表', 'fail', e.message); }
    }
    if (gate.defaultNode && knownNodes) {
      add('default-node', '默认分流节点', knownNodes.includes(gate.defaultNode) ? 'ok' : 'fail', gate.defaultNode);
    }

    for (const [node, port] of Object.entries(this.#activeListeners())) {
      const rules = isRuleKey(node);
      const profile = rules ? this.store.data.netProfiles.find((p) => ruleKey(p.id) === node) : null;
      const label = rules ? `网络配置「${profile?.name ?? node}」` : `实例节点「${node}」`;
      if (!rules && knownNodes && !knownNodes.includes(node)) {
        add(`node-${port}`, label, 'fail', 'Clash 中没有这个节点');
        continue;
      }
      try {
        await tcpProbe(port);
        add(`node-${port}`, label, 'ok', `listener ${port} 可连接`);
      } catch {
        add(`node-${port}`, label, 'fail', `端口 ${port} 未监听。到「网络配置」页点“同步到 Clash”。`);
      }
    }
    if (this.background) {
      try {
        const { state, generatedAt } = this.clashSync.generatedStatus();
        const when = new Date(generatedAt).toLocaleString('zh-CN', { hour12: false });
        const [status, detail] = {
          ok: ['ok', `${when} 生成的配置已包含 SandGate 的内容，脚本扩展有效。`],
          pending: ['ok', `网络配置已生效，并已写入脚本扩展。Clash Verge 上次生成配置是 ${when}，下次生成时会带上。`],
          'no-script': ['warn', '脚本扩展里没有当前的网络配置，Clash Verge 下次生成配置后它们会失效。到「网络配置」页点“同步到 Clash”。'],
          broken: ['warn', `Clash Verge 在 ${when} 用当前脚本扩展生成了配置，里面却没有 SandGate 的内容，脚本扩展可能没有生效。`],
        }[state];
        add('clash-generated', 'Clash Verge 生成的配置', status, detail);
      } catch (e) {
        add('clash-generated', 'Clash Verge 生成的配置', 'warn', `无法读取：${e.message}`);
      }
    }
    const { state, message } = this.clashSync.status;
    add('clash-sync', '网络配置同步', { ok: 'ok', warn: 'warn', fail: 'fail' }[state] ?? 'warn', message);
    return { items };
  }
}
