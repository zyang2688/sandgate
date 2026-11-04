import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

/** The controller refused or failed a request: expected in normal use, not a SandGate bug. */
export class ClashError extends Error {}

/** Minimal client for the mihomo external controller, over TCP or a unix socket. */
export class ClashClient {
  constructor(cfg) {
    this.cfg = cfg;
  }

  get configured() {
    return this.cfg.type === 'unix' ? Boolean(this.cfg.socketPath) : Boolean(this.cfg.port);
  }

  request(pathname, { timeout = 3000, method = 'GET' } = {}) {
    const { type, host, port, socketPath, secret } = this.cfg;
    const target = type === 'unix' ? { socketPath } : { host, port };
    return new Promise((resolve, reject) => {
      const req = http.request(
        { ...target, path: pathname, method, timeout, headers: secret ? { Authorization: `Bearer ${secret}` } : {} },
        (res) => {
          let body = '';
          res.setEncoding('utf8');
          res.on('data', (d) => { body += d; });
          res.on('end', () => {
            if (res.statusCode === 401) return reject(new ClashError('控制接口密钥错误'));
            if (res.statusCode >= 400) return reject(new ClashError(`控制接口返回 HTTP ${res.statusCode}`));
            if (res.statusCode === 204 || !body) return resolve({});
            try { resolve(JSON.parse(body)); } catch { reject(new ClashError('控制接口返回了非 JSON 内容')); }
          });
          res.on('error', (e) => reject(new ClashError(e.message)));
        },
      );
      req.on('timeout', () => req.destroy(new ClashError('控制接口超时')));
      req.on('error', (e) => reject(e instanceof ClashError ? e : new ClashError(e.message)));
      req.end();
    });
  }

  version() { return this.request('/version'); }
  configs() { return this.request('/configs'); }
  connections() { return this.request('/connections'); }
  rules() { return this.request('/rules'); }
  closeConnection(id) { return this.request(`/connections/${encodeURIComponent(id)}`, { method: 'DELETE' }); }

  /** Node and group names only; server addresses stay out of the UI. */
  async proxies() {
    const { proxies } = await this.request('/proxies');
    const builtin = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL']);
    const nodes = [];
    const groups = [];
    for (const [name, p] of Object.entries(proxies)) {
      if (builtin.has(name)) continue;
      if (Array.isArray(p.all)) groups.push({ name, type: p.type, now: p.now });
      else nodes.push({ name, type: p.type });
    }
    return { nodes, groups };
  }

  delay(node, url, timeoutMs) {
    const qs = new URLSearchParams({ url, timeout: String(timeoutMs) });
    return this.request(`/proxies/${encodeURIComponent(node)}/delay?${qs}`, { timeout: timeoutMs + 1000 });
  }
}

const VERGE_DIR = 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev';

function topLevelValue(yaml, key) {
  const m = yaml.match(new RegExp(`^${key}:[ \\t]*(.*)$`, 'm'));
  if (!m) return '';
  return m[1].replace(/\s+#.*$/, '').trim().replace(/^(['"])(.*)\1$/, '$2');
}

/** Reads controller details from Clash Verge's generated config, if present. */
export function detectVerge(home = os.homedir()) {
  const dir = path.join(home, VERGE_DIR);
  const candidates = ['clash-verge.yaml', 'config.yaml'].map((f) => path.join(dir, f));
  const file = candidates.find((f) => fs.existsSync(f));
  if (!file) return null;
  const yaml = fs.readFileSync(file, 'utf8');
  const external = topLevelValue(yaml, 'external-controller');
  const socketPath = topLevelValue(yaml, 'external-controller-unix');
  const secret = topLevelValue(yaml, 'secret');
  const mixedPort = Number(topLevelValue(yaml, 'mixed-port')) || null;
  const m = external.match(/^(127\.0\.0\.1|localhost):(\d+)$/);
  const controller = m
    ? { type: 'tcp', host: m[1], port: Number(m[2]), socketPath, secret }
    : { type: 'unix', host: '127.0.0.1', port: 9097, socketPath, secret };
  return { controller, mixedPort, socketExists: Boolean(socketPath) && fs.existsSync(socketPath) };
}

/** One listener per node: its traffic skips the rules and can only use that node. */
export function listenerSnippet(listeners) {
  const entries = Object.entries(listeners);
  if (!entries.length) return '# 添加一个经节点联网的沙盒应用后，这里会生成配置\n';
  const lines = ['listeners:'];
  for (const [node, port] of entries) {
    lines.push(`  - name: sandgate-${port}`, '    type: mixed', '    listen: 127.0.0.1', `    port: ${port}`, `    proxy: ${JSON.stringify(node)}`);
  }
  return lines.join('\n') + '\n';
}
