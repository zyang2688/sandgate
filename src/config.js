import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

export const DEFAULT_SETTINGS = Object.freeze({
  uiPort: 7878,
  gate: {
    controller: { type: 'tcp', host: '127.0.0.1', port: 9097, socketPath: '', secret: '' },
    defaultNode: '', // what Clash-routed traffic may use, besides DIRECT
    listeners: {}, // node name → dedicated listener port; managed by the server
    exitIps: {}, // node name → expected exit IP
    rulesHash: '', // accepted fingerprint of the Clash rules
    probeInterface: 'en0',
    pfTargets: [], // node or group names whose servers pf may reach
    pfExtra: [], // extra destinations for foreign DIRECT traffic
    pfCnList: 'ruleset/sukka/china-ip.txt', // relative to the Clash Verge directory
    foreignDirectVia: '', // where DIRECT traffic to a non-CN IP goes instead, so it matches pf; '' leaves rules alone
    requireTun: true,
    requireNode: false, // a dead node only fails its connections, so it need not close the gate
    requirePin: true,
    stableSec: 3,
    delayIntervalSec: 5,
    pinIntervalSec: 15,
    exitIntervalSec: 30,
    delayTimeoutMs: 6000, // a chained node's test takes about 2.5 s, sometimes over 3 s
    probeUrl: 'http://cp.cloudflare.com/generate_204',
    exitIpUrl: 'https://api.ipify.org',
  },
});

export class ValidationError extends Error {}

const fail = (msg) => { throw new ValidationError(msg); };
const hasControl = (s) => /[\x00-\x1f\x7f]/.test(s);

export function expandPath(p, home = os.homedir()) {
  if (typeof p !== 'string' || !p.trim() || hasControl(p)) fail(`路径无效: ${JSON.stringify(p)}`);
  const expanded = p === '~' ? home : p.startsWith('~/') ? path.join(home, p.slice(2)) : p;
  if (!path.isAbsolute(expanded)) fail(`必须是绝对路径: ${p}`);
  return path.normalize(expanded);
}

/** Paths under HOME a home-visible clone shares with you, such as `.claude/projects`. */
function homeRelativeList(v) {
  if (v === undefined) return [];
  if (!Array.isArray(v)) fail('共用路径必须是数组');
  const out = [];
  for (const raw of v) {
    const p = String(raw ?? '').trim().replace(/^~\//, '').replace(/\/+$/, '');
    if (!p || hasControl(p) || p.startsWith('/') || p.split('/').some((s) => s === '..' || s === '.' || s === '')) {
      fail(`共用路径需为用户目录下的相对路径，例如 .claude/projects: ${JSON.stringify(raw)}`);
    }
    if (!out.includes(p)) out.push(p);
  }
  return out;
}

const pathList = (v, label) => {
  if (v === undefined) return [];
  if (!Array.isArray(v)) fail(`${label} 必须是数组`);
  return v.map((p) => expandPath(p));
};

/** Normalises untrusted API input into a stored sandbox instance. */
export const DEFAULT_TIMEZONE = 'America/Los_Angeles';

/** Empty means the system time zone. Intl rejects any name the runtime cannot resolve. */
export function validTimezone(v) {
  const tz = String(v ?? '').trim();
  if (!tz) return '';
  try {
    new Intl.DateTimeFormat('en', { timeZone: tz });
  } catch {
    fail(`时区无效: ${tz}，例如 America/Los_Angeles`);
  }
  return tz;
}

/** A terminal command name. Empty means the instance has no command. */
export function validAlias(v) {
  const alias = String(v ?? '').trim();
  if (alias && !/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(alias)) fail(`终端命令名无效: ${alias}，只能用字母、数字、_ . -，且以字母或 _ 开头`);
  return alias;
}

export function validateApp(input, existing = {}) {
  const name = String(input.name ?? '').trim();
  if (!name || name.length > 64 || hasControl(name)) fail('名称需为 1-64 个字符');
  const typed = String(input.command ?? '').trim();
  if (!typed || hasControl(typed)) fail('命令不能为空');
  const command = typed === '~' || typed.startsWith('~/') ? expandPath(typed) : typed;
  const args = input.args ?? [];
  if (!Array.isArray(args) || args.some((a) => typeof a !== 'string' || a.includes('\0'))) fail('参数必须是字符串数组');
  const env = input.env ?? {};
  if (typeof env !== 'object' || Array.isArray(env)) fail('环境变量格式错误');
  for (const [k, v] of Object.entries(env)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || typeof v !== 'string' || v.includes('\0')) fail(`环境变量无效: ${k}`);
  }
  // gate: only its node, enforced by the sandbox. rules: its own sub-rules. open: Clash's rules.
  const network = input.network ?? 'gate';
  if (!['gate', 'rules', 'open', 'none'].includes(network)) fail('网络模式无效');
  const node = String(input.node ?? '').trim();
  if (hasControl(node)) fail('节点名无效');
  if (['gate', 'rules'].includes(network) && !node) fail('请选择节点');
  const unsandboxed = Boolean(input.unsandboxed ?? existing.unsandboxed);
  if (unsandboxed && network === 'none') fail('不套沙盒时无法禁止联网，请选其他网络配置');
  const alias = validAlias(input.alias ?? existing.alias);
  // Without a sandbox a moved HOME isolates nothing, and it would hide the keychain.
  const isolateHome = !unsandboxed && input.isolateHome !== false;
  return {
    id: existing.id ?? crypto.randomBytes(5).toString('hex'),
    name,
    command,
    args,
    cwd: input.cwd ? expandPath(input.cwd) : '',
    env,
    timezone: validTimezone(input.timezone ?? existing.timezone ?? DEFAULT_TIMEZONE),
    network,
    netProfile: String(input.netProfile ?? existing.netProfile ?? ''),
    node: ['gate', 'rules'].includes(network) ? node : '',
    port: existing.port ?? null,
    unsandboxed,
    isolateHome,
    // A clone whose HOME is its own while your files stay reachable: separate accounts, same projects.
    homeVisible: isolateHome && Boolean(input.homeVisible ?? existing.homeVisible),
    // Only an instance that sees your home can reach what the links point to.
    linkedPaths: !unsandboxed && (!isolateHome || Boolean(input.homeVisible ?? existing.homeVisible)) ? homeRelativeList(input.linkedPaths ?? existing.linkedPaths) : [],
    alias,
    allowUnixSockets: Boolean(input.allowUnixSockets),
    // An unsandboxed instance has the keychain anyway; this lets a sandboxed one use it.
    allowKeychain: !unsandboxed && Boolean(input.allowKeychain ?? existing.allowKeychain),
    allowSsh: !unsandboxed && Boolean(input.allowSsh ?? existing.allowSsh),
    blockBrokers: input.blockBrokers !== false,
    restrictWrites: Boolean(input.restrictWrites),
    writable: pathList(input.writable, '可写路径'),
    shared: pathList(input.shared, '共享文件夹'),
    protected: pathList(input.protected, '受保护路径'),
  };
}

function validPort(v, label) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 65535) fail(`${label} 端口无效`);
  return n;
}

function posNum(v, label, min = 1) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < min) fail(`${label} 需不小于 ${min}`);
  return n;
}

function httpUrl(v, label) {
  let u;
  try { u = new URL(String(v)); } catch { fail(`${label} 不是合法 URL`); }
  if (!['http:', 'https:'].includes(u.protocol)) fail(`${label} 必须是 http(s)`);
  return u.toString();
}

/** Merges a partial patch. An omitted secret is kept; server-managed fields are ignored. */
export function mergeGateSettings(current, patch = {}) {
  const { listeners: _listeners, rulesHash: _rulesHash, ...safe } = patch;
  const c = { ...current.controller, ...(patch.controller ?? {}) };
  if (!['tcp', 'unix'].includes(c.type)) fail('控制接口类型只能是 tcp 或 unix');
  if (c.type === 'unix' && c.socketPath) c.socketPath = expandPath(c.socketPath);
  c.port = validPort(c.port, '控制接口');
  if (c.host !== '127.0.0.1' && c.host !== 'localhost') fail('控制接口只允许本机地址');
  if (typeof c.secret !== 'string') fail('密钥格式错误');

  const g = { ...current, ...safe, controller: c };
  g.defaultNode = String(g.defaultNode ?? '');
  for (const k of ['requireTun', 'requireNode', 'requirePin']) g[k] = Boolean(g[k]);
  if (typeof g.exitIps !== 'object' || g.exitIps === null || Array.isArray(g.exitIps)) fail('出口 IP 格式错误');
  g.exitIps = Object.fromEntries(Object.entries(g.exitIps).map(([k, v]) => [k, String(v).trim()]).filter(([, v]) => v));
  if (!/^en[0-9]+$/.test(String(g.probeInterface))) fail('探测网卡名无效，例如 en0');
  if (!Array.isArray(g.pfTargets) || g.pfTargets.some((t) => typeof t !== 'string' || !t.trim() || hasControl(t))) fail('放行节点格式错误');
  g.pfTargets = [...new Set(g.pfTargets.map((t) => t.trim()))];
  if (!Array.isArray(g.pfExtra)) fail('额外放行格式错误');
  g.pfExtra = [...new Set(g.pfExtra.map((c) => String(c).trim()).filter(Boolean))];
  for (const c of g.pfExtra) {
    const m = c.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
    const prefix = m?.[5] === undefined ? 32 : Number(m[5]);
    const first = Number(m?.[1]);
    if (!m || m.slice(1, 5).some((o) => Number(o) > 255) || prefix < 8 || prefix > 32 || first === 0 || first === 127 || first >= 224) fail(`额外放行无效: ${c}（需为 IPv4，前缀至少 /8）`);
  }
  g.foreignDirectVia = String(g.foreignDirectVia ?? '').trim();
  if (hasControl(g.foreignDirectVia) || /[,()]/.test(g.foreignDirectVia) || g.foreignDirectVia === 'DIRECT') fail('国外直连改走的组无效');
  if (typeof g.pfCnList !== 'string' || !g.pfCnList.trim() || g.pfCnList.startsWith('/') || g.pfCnList.includes('..') || hasControl(g.pfCnList)) fail('国内 IP 列表路径无效');
  g.stableSec = posNum(g.stableSec, '稳定时长', 1);
  g.delayIntervalSec = posNum(g.delayIntervalSec, '延迟检查间隔', 1);
  g.pinIntervalSec = posNum(g.pinIntervalSec, '钉死检查间隔', 2);
  g.exitIntervalSec = posNum(g.exitIntervalSec, '出口检查间隔', 5);
  g.delayTimeoutMs = posNum(g.delayTimeoutMs, '延迟超时', 100);
  g.probeUrl = httpUrl(g.probeUrl, '探测地址');
  g.exitIpUrl = httpUrl(g.exitIpUrl, '出口 IP 地址');
  return g;
}

export class Store {
  constructor(dir = process.env.SANDGATE_HOME || path.join(os.homedir(), '.sandgate')) {
    this.dir = dir;
    this.path = path.join(dir, 'config.json');
    this.tokenPath = path.join(dir, 'token');
    this.logDir = path.join(dir, 'logs');
    this.profileDir = path.join(dir, 'profiles');
    // Outside `dir`: every sandbox is denied `dir`, but needs its own instance home.
    this.instancesDir = `${dir}-instances`;
    for (const d of [dir, this.logDir, this.profileDir, this.instancesDir]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    fs.chmodSync(this.instancesDir, 0o700);
    this.data = this.#load();
    this.token = this.#loadToken();
    if (this.migrated) this.save();
  }

  instanceHome(id) { return path.join(this.instancesDir, id); }

  #load() {
    const base = structuredClone({ ...DEFAULT_SETTINGS, apps: [], netProfiles: [], locked: false });
    if (!fs.existsSync(this.path)) return base;
    const raw = JSON.parse(fs.readFileSync(this.path, 'utf8'));
    const gate = { ...base.gate, ...raw.gate, controller: { ...base.gate.controller, ...raw.gate?.controller } };
    // Configs from before per-instance nodes had one global node and upstream port.
    const { node: oldNode, upstreamPort: oldPort, expectedExitIp: _old, ...cleanGate } = gate;
    if (oldNode) {
      cleanGate.defaultNode ||= oldNode;
      if (oldPort) cleanGate.listeners = { [oldNode]: oldPort, ...cleanGate.listeners };
    }
    const apps = (raw.apps ?? []).map((a) => ({ isolateHome: false, homeVisible: false, linkedPaths: [], allowKeychain: false, allowSsh: false, alias: '', unsandboxed: false, shared: [], timezone: '', ...a, node: a.node ?? (a.network === 'gate' ? oldNode ?? '' : '') }));
    // exitCheck was a periodic check that became an on-demand button.
    const netProfiles = (raw.netProfiles ?? []).map(({ exitCheck: _gone, ...p }) => p);
    // Instances from before network profiles: each node becomes a profile, with the same behavior.
    for (const a of apps) {
      if (a.netProfile) continue;
      if (a.network === 'none') { a.netProfile = 'none'; continue; }
      a.netProfile = Store.#nodeProfile(netProfiles, a.node).id;
      this.migrated = true;
    }
    return { ...base, ...raw, gate: cleanGate, apps, netProfiles };
  }

  static #nodeProfile(profiles, node) {
    let p = profiles.find((x) => x.mode === 'node' && x.node === node);
    if (!p) {
      p = { id: crypto.randomBytes(5).toString('hex'), name: `全部走 ${node}`, mode: 'node', node, exits: {}, extraRules: [], timezone: '' };
      profiles.push(p);
    }
    return p;
  }

  /** The profile for a whole-node instance, created on first use. */
  nodeProfile(node) {
    return Store.#nodeProfile(this.data.netProfiles, node);
  }

  #loadToken() {
    if (fs.existsSync(this.tokenPath)) return fs.readFileSync(this.tokenPath, 'utf8').trim();
    const token = crypto.randomBytes(24).toString('base64url');
    fs.writeFileSync(this.tokenPath, token + '\n', { mode: 0o600 });
    return token;
  }

  save() {
    const tmp = `${this.path}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.path);
  }

  /** Lowest port not used by any instance or listener; stable once assigned. */
  allocatePort() {
    const used = new Set([
      ...this.data.apps.map((a) => a.port),
      ...Object.values(this.data.gate.listeners),
      this.data.uiPort,
    ]);
    let p = 17890;
    while (used.has(p)) p++;
    return p;
  }

  /** Each node gets one listener, shared by every instance that uses it. */
  listenerPort(node) {
    const { listeners } = this.data.gate;
    listeners[node] ??= this.allocatePort();
    return listeners[node];
  }

  /** Gates are per listener: a node's name, or a profile's rule key. */
  usedNodes() {
    return [...new Set(this.data.apps.filter((a) => ['gate', 'rules'].includes(a.network) && a.node).map((a) => a.node))];
  }

  /** What instances can dial on the physical NIC, for pf's allow-list. */
  instanceTargets() {
    const out = new Set();
    for (const a of this.data.apps) {
      if (a.network === 'gate' && a.node) out.add(a.node);
      if (a.network !== 'rules') continue;
      const p = this.data.netProfiles.find((x) => x.id === a.netProfile);
      for (const t of Object.values(p?.exits ?? {})) out.add(t);
      for (const r of p?.extraRules ?? []) out.add(r.split(',')[2]?.trim());
    }
    out.delete(undefined);
    return [...out];
  }
}
