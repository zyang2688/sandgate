import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { AppManager } from './apps.js';
import { ClashClient, ClashError, detectVerge, listenerSnippet } from './clash.js';
import { Store, ValidationError, mergeGateSettings, validateApp } from './config.js';
import { GateManager, defaultRouteInterface, fetchExitIp, tcpProbe } from './gate.js';
import { ConnectionGuard, ProtectionProbe } from './guard.js';
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
    if (this.background) {
      const stamp = () => new Date().toLocaleString('zh-CN', { hour12: false });
      this.gates.on('close', (node, reason) => console.log(`${stamp()} 闸门关闭 ${node}: ${reason}`));
      this.gates.on('open', (node) => console.log(`${stamp()} 闸门打开 ${node}`));
      this.guard.start();
      this.protection.start();
      this.pfPlanner.start();
    }
    return { url: `http://127.0.0.1:${this.port}/#token=${this.store.token}` };
  }

  async stop() {
    this.guard.stop();
    this.protection.stop();
    this.pfPlanner.stop();
    this.gates.stop();
    await this.apps.stopAll();
    this.server.closeAllConnections();
    await new Promise((resolve) => this.server.close(resolve));
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
    }
    const m = url.pathname.match(/^\/api\/apps\/([0-9a-f]+)(?:\/(start|stop|verify|logs|profile))?$/);
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
      apps: this.store.data.apps.map((a) => this.apps.snapshot(a)),
    };
  }

  /** The snippet covers nodes in use, since a listener can only be added by the user. */
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
      listenerSnippet: listenerSnippet(this.#activeListeners()),
      pfScript: path.join(ROOT, 'scripts/sandgate-pf.sh'),
    };
  }

  #putSettings(body) {
    this.store.data.gate = mergeGateSettings(this.store.data.gate, body.gate ?? {});
    this.store.save();
    this.#applyGateSettings();
    if (this.background) this.pfPlanner.tick();
    return { ...this.#publicSettings(), pf: this.pfPlanner.status };
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
    if (app.network === 'gate') {
      app.port ??= this.store.allocatePort();
      this.store.listenerPort(app.node);
    } else {
      app.port = null;
    }
  }

  #createApp(body) {
    const app = validateApp(body);
    this.store.data.apps.push(app);
    this.#assignPorts(app);
    this.store.save();
    this.gates.sync(this.store.usedNodes());
    return this.apps.snapshot(app);
  }

  async #updateApp(app, body) {
    const next = validateApp(body, app);
    const networkChanged = next.network !== app.network || next.node !== app.node;
    if (networkChanged && this.apps.isRunning(app.id)) throw new HttpError(409, '请先停止应用再改节点或网络模式');
    if (next.network !== 'gate') await this.apps.releasePort(app.id);
    Object.assign(app, next);
    this.#assignPorts(app);
    this.store.save();
    this.gates.sync(this.store.usedNodes());
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
      const label = `实例节点「${node}」`;
      if (knownNodes && !knownNodes.includes(node)) {
        add(`node-${port}`, label, 'fail', 'Clash 中没有这个节点');
        continue;
      }
      try {
        await tcpProbe(port);
        add(`node-${port}`, label, 'ok', `listener ${port} 可连接`);
      } catch {
        add(`node-${port}`, label, 'fail', `listener ${port} 未监听。把「网关配置」页生成的 listeners 配置加入 Clash Verge 的 Merge 配置并重载。`);
      }
    }
    return { items };
  }
}
