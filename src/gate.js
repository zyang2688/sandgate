import { execFile } from 'node:child_process';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import { promisify } from 'node:util';

const exec = promisify(execFile);

/** The whole gate policy: close at once on any failure, reopen only after a stable run. */
export function decide(prev, { allOk, locked, now, stableMs }) {
  if (locked || !allOk) return { open: false, okSince: null };
  const okSince = prev.okSince ?? now;
  return { open: prev.open || now - okSince >= stableMs, okSince };
}

export function tcpProbe(port, timeout = 800) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: '127.0.0.1', port, timeout });
    s.once('connect', () => { s.destroy(); resolve(); });
    s.once('timeout', () => { s.destroy(); reject(new Error(`端口 ${port} 超时`)); });
    s.once('error', () => reject(new Error(`端口 ${port} 未监听`)));
  });
}

let routeCache = { at: 0, value: null };

/** Shared by every node's gate, so several nodes do not multiply `route` calls. */
export function defaultRouteInterface() {
  const now = Date.now();
  if (routeCache.value && now - routeCache.at < 500) return routeCache.value;
  const value = exec('/sbin/route', ['-n', 'get', '1.1.1.1'], { timeout: 1500 })
    .then(({ stdout }) => stdout.match(/interface:\s*(\S+)/)?.[1] ?? '');
  routeCache = { at: now, value };
  return value;
}

export async function fetchExitIp(upstreamPort, url) {
  // Generous: a TLS handshake through a node to this service has been seen taking 5.8 s.
  const { stdout } = await exec('/usr/bin/curl', ['-s', '--max-time', '12', '-x', `http://127.0.0.1:${upstreamPort}`, url], { timeout: 14000 });
  return stdout.trim();
}

/**
 * Opens a real tunnel through the listener and asks mihomo which proxy carries it.
 * This catches a mis-set listener or a port now serving a different node.
 */
export async function verifyPin({ upstreamPort, probeUrl, node, client }) {
  const { hostname, port, protocol } = new URL(probeUrl);
  const authority = `${hostname}:${port || (protocol === 'https:' ? 443 : 80)}`;
  const sock = net.connect({ host: '127.0.0.1', port: upstreamPort });
  try {
    await new Promise((resolve, reject) => {
      let buf = '';
      const timer = setTimeout(() => reject(new Error('隧道建立超时')), 5000);
      sock.once('error', (e) => { clearTimeout(timer); reject(e); });
      sock.once('close', () => { clearTimeout(timer); reject(new Error('上游关闭了隧道')); });
      sock.once('connect', () => sock.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`));
      sock.on('data', (d) => {
        buf += d.toString('latin1');
        if (!buf.includes('\r\n\r\n')) return;
        clearTimeout(timer);
        if (/^HTTP\/1\.[01] 200/.test(buf)) resolve();
        else reject(new Error(`上游拒绝隧道: ${buf.split('\r\n')[0]}`));
      });
    });
    const localPort = String(sock.localPort);
    for (let attempt = 0; attempt < 3; attempt++) {
      const { connections = [] } = await client.connections();
      const conn = connections.find((c) => String(c.metadata?.sourcePort) === localPort);
      if (conn) {
        const via = conn.chains?.[0];
        if (via !== node) throw new Error(`流量走了「${via ?? '未知'}」，不是「${node}」`);
        return `经 ${via}`;
      }
      await new Promise((r) => setTimeout(r, 150));
    }
    throw new Error('在连接表中找不到探测连接');
  } finally {
    sock.destroy();
  }
}

/** Health checks for one node's gate. Each `run` returns a detail or throws why it failed. */
export function buildChecks(settings, client, node) {
  const g = settings;
  const port = g.listeners[node];
  let lastIface = null;
  const checks = [
    {
      id: 'upstream', label: `节点 listener${port ? ` ${port}` : ''}`, intervalMs: 1000, timeoutMs: 1000,
      run: async () => {
        if (!port) throw new Error('未分配端口');
        try { await tcpProbe(port); } catch { throw new Error(`端口 ${port} 未监听，请把 listeners 配置加入 Clash Verge`); }
        return '可连接';
      },
    },
  ];
  if (g.requireTun) {
    checks.push({
      id: 'route', label: 'TUN 默认路由', intervalMs: 1000, timeoutMs: 2000,
      run: async () => {
        const iface = await defaultRouteInterface();
        if (!iface.startsWith('utun')) { lastIface = null; throw new Error(`默认路由走 ${iface || '无'}，不是 TUN`); }
        const rebuilt = lastIface !== null && iface !== lastIface;
        lastIface = iface;
        if (rebuilt) throw new Error(`TUN 接口变为 ${iface}，重新评估`);
        return iface;
      },
    });
    checks.push({
      id: 'tun', label: 'Clash TUN 开关', intervalMs: 2000, timeoutMs: 3000,
      run: async () => {
        const c = await client.configs();
        if (!c.tun?.enable) throw new Error('Clash 未启用 TUN');
        return `${c.tun.stack ?? 'tun'} / ${c.mode}`;
      },
    });
  }
  if (g.requireNode) {
    checks.push({
      id: 'node', label: '节点可用', intervalMs: g.delayIntervalSec * 1000, timeoutMs: g.delayTimeoutMs + 2000,
      run: async () => {
        const r = await client.delay(node, g.probeUrl, g.delayTimeoutMs);
        if (typeof r.delay !== 'number' || r.delay <= 0) throw new Error('延迟测试失败');
        return `${r.delay} ms`;
      },
    });
  }
  if (g.requirePin) {
    checks.push({
      id: 'pin', label: '流量钉死在该节点', intervalMs: g.pinIntervalSec * 1000, timeoutMs: 9000,
      run: () => verifyPin({ upstreamPort: port, probeUrl: g.probeUrl, node, client }),
    });
  }
  const expected = g.exitIps?.[node];
  if (expected) {
    checks.push({
      id: 'exit', label: '出口 IP', intervalMs: g.exitIntervalSec * 1000, timeoutMs: 15000,
      run: async () => {
        const ip = await fetchExitIp(port, g.exitIpUrl);
        if (ip !== expected) throw new Error(`实际 ${ip || '无响应'}，应为 ${expected}`);
        return ip;
      },
    });
  }
  return checks;
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('检查超时')), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Runs checks on their own schedules and emits 'close'/'open'. Starts closed. */
export class GateMonitor extends EventEmitter {
  constructor({ checks = [], stableMs = 6000, locked = false, tickMs = 500, now = Date.now } = {}) {
    super();
    this.tickMs = tickMs;
    this.now = now;
    this.locked = locked;
    this.state = { open: false, okSince: null };
    this.since = now();
    this.lastReason = '启动中';
    this.configure(checks, stableMs);
  }

  get open() { return this.state.open; }

  /** New settings invalidate every earlier result, so this also closes the gate. */
  configure(checks, stableMs) {
    this.stableMs = stableMs;
    this.generation = (this.generation ?? 0) + 1;
    this.checks = checks.map((c) => ({ ...c, result: null, nextRun: 0, running: false }));
    this.#apply(false, '配置已更新');
  }

  setLocked(locked) {
    this.locked = Boolean(locked);
    this.evaluate();
  }

  start() {
    this.timer ??= setInterval(() => this.tick(), this.tickMs);
    this.tick();
  }

  stop() {
    clearInterval(this.timer);
    this.timer = null;
    this.#apply(false, '已停止');
  }

  tick() {
    const t = this.now();
    for (const c of this.checks) {
      if (!c.running && t >= c.nextRun) this.#runCheck(c);
    }
    this.evaluate();
  }

  #runCheck(c) {
    const generation = this.generation;
    c.running = true;
    withTimeout(Promise.resolve().then(c.run), c.timeoutMs)
      .then((detail) => ({ ok: true, detail: String(detail ?? '') }))
      .catch((e) => ({ ok: false, detail: e?.message ?? String(e) }))
      .then((r) => {
        if (generation !== this.generation) return;
        c.running = false;
        c.result = { ...r, at: this.now() };
        c.nextRun = this.now() + c.intervalMs;
        this.evaluate();
      });
  }

  /** A result older than two intervals counts as failed: a hung check must not hold the gate open. */
  #healthy(c, t) {
    return Boolean(c.result?.ok) && t - c.result.at <= c.intervalMs * 2 + c.timeoutMs;
  }

  evaluate() {
    const t = this.now();
    const failing = this.checks.filter((c) => !this.#healthy(c, t));
    const allOk = this.checks.length > 0 && failing.length === 0;
    const next = decide(this.state, { allOk, locked: this.locked, now: t, stableMs: this.stableMs });
    if (next.open !== this.state.open) {
      if (next.open) {
        this.state = next;
        this.since = t;
        this.lastReason = '全部检查通过';
        this.emit('open');
      } else {
        const c = failing[0];
        this.#apply(false, this.locked ? '手动锁定' : c ? `${c.label}: ${c.result?.detail ?? '等待结果'}` : '无检查项');
      }
      return;
    }
    this.state = next;
    if (!next.open && this.locked) {
      this.lastReason = '手动锁定';
    } else if (!next.open && failing.length) {
      const c = failing[0];
      this.lastReason = `${c.label}: ${c.result?.detail ?? '等待结果'}`;
    } else if (!next.open) {
      this.lastReason = '检查已通过，稳定观察中';
    }
  }

  /**
   * Every close drops all results: reopening needs a fresh pass from every check,
   * not just the one that failed. Failures also re-run immediately.
   */
  #apply(open, reason) {
    const wasOpen = this.state?.open;
    this.state = { open, okSince: null };
    this.lastReason = reason;
    if (wasOpen && !open) {
      this.since = this.now();
      this.generation++;
      for (const c of this.checks) Object.assign(c, { result: null, nextRun: 0, running: false });
      this.emit('close', reason);
    }
  }

  snapshot() {
    const t = this.now();
    return {
      open: this.open,
      locked: this.locked,
      since: this.since,
      reason: this.lastReason,
      stableSec: this.stableMs / 1000,
      stableElapsedSec: this.state.okSince ? Math.floor((t - this.state.okSince) / 1000) : 0,
      checks: this.checks.map((c) => ({
        id: c.id,
        label: c.label,
        ok: this.#healthy(c, t),
        pending: !c.result,
        detail: c.result?.detail ?? '等待结果',
        ageSec: c.result ? Math.round((t - c.result.at) / 1000) : null,
      })),
    };
  }
}

/** One independent gate per node: a dead node only stops the instances that use it. */
export class GateManager extends EventEmitter {
  constructor({ getSettings, client, locked = false }) {
    super();
    this.getSettings = getSettings;
    this.client = client;
    this.locked = locked;
    this.started = false;
    this.monitors = new Map();
  }

  #stableMs() { return this.getSettings().stableSec * 1000; }

  sync(nodes) {
    const wanted = new Set(nodes);
    for (const [node, mon] of this.monitors) {
      if (!wanted.has(node)) {
        mon.stop();
        this.monitors.delete(node);
      }
    }
    for (const node of wanted) {
      if (this.monitors.has(node)) continue;
      const mon = new GateMonitor({
        checks: buildChecks(this.getSettings(), this.client, node),
        stableMs: this.#stableMs(),
        locked: this.locked,
      });
      mon.on('close', (reason) => this.emit('close', node, reason));
      this.monitors.set(node, mon);
      if (this.started) mon.start();
    }
  }

  /** Rebuilds every gate from current settings, closing each until it re-passes. */
  reconfigure() {
    for (const [node, mon] of this.monitors) mon.configure(buildChecks(this.getSettings(), this.client, node), this.#stableMs());
  }

  isOpen(node) { return Boolean(this.monitors.get(node)?.open); }

  setLocked(locked) {
    this.locked = Boolean(locked);
    for (const mon of this.monitors.values()) mon.setLocked(locked);
  }

  start() {
    this.started = true;
    for (const mon of this.monitors.values()) mon.start();
  }

  stop() {
    this.started = false;
    for (const mon of this.monitors.values()) mon.stop();
  }

  snapshot() {
    return {
      locked: this.locked,
      nodes: Object.fromEntries([...this.monitors].map(([node, mon]) => [node, mon.snapshot()])),
    };
  }
}
