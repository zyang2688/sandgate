import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const VERGE_DIR = 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev';
const BUILTIN = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL']);
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const MIN_CN_ENTRIES = 1000;

export const isIpv4 = (s) => {
  const m = String(s).match(IPV4);
  return Boolean(m) && m.slice(1).every((o) => Number(o) <= 255);
};

export function isIpv4Cidr(s) {
  const [addr, prefix, extra] = String(s).split('/');
  if (extra !== undefined || !isIpv4(addr)) return false;
  return prefix === undefined || (/^\d+$/.test(prefix) && Number(prefix) <= 32);
}

export function unquote(raw) {
  const v = raw.trim();
  if (v.startsWith("'") && v.endsWith("'") && v.length >= 2) return v.slice(1, -1).replace(/''/g, "'");
  if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) {
    return v.slice(1, -1)
      .replace(/\\U([0-9a-fA-F]{8})/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/\\(["\\/])/g, '$1');
  }
  return v.replace(/\s+#.*$/, '');
}

const inlineList = (v) => v.slice(1, -1).split(',').map(unquote).filter(Boolean);

function setKey(item, key, value) {
  const v = value.trim();
  if (v.startsWith('[') && v.endsWith(']')) item[key] = inlineList(v);
  else item[key] = unquote(v);
}

function parseFlowItem(text) {
  const item = {};
  for (const key of ['name', 'type', 'server', 'dialer-proxy']) {
    const m = text.match(new RegExp(`(?:^|[{,\\s])${key}:\\s*("[^"]*"|'[^']*'|[^,}]+)`));
    if (m) item[key] = unquote(m[1]);
  }
  const list = text.match(/(?:^|[{,\s])proxies:\s*(\[[^\]]*\])/);
  if (list) item.proxies = inlineList(list[1]);
  return item;
}

export function sectionLines(yaml, key) {
  const lines = yaml.split(/\r?\n/);
  const start = lines.findIndex((l) => l.startsWith(`${key}:`));
  if (start < 0) return [];
  const out = [];
  for (const line of lines.slice(start + 1)) {
    if (/^[^\s#-]/.test(line)) break;
    out.push(line);
  }
  return out;
}

/** Reads the block-style list of mappings that Verge generates, keeping only top-level keys. */
function parseItems(lines) {
  const items = [];
  let base = null;
  let cur = null;
  let listKey = null;
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const indent = line.length - line.trimStart().length;
    const dash = line.match(/^\s*- (.*)$/);
    if (dash && (base === null || indent === base)) {
      base = indent;
      const rest = dash[1].trim();
      if (rest.startsWith('{')) {
        cur = parseFlowItem(rest);
        listKey = null;
      } else {
        cur = {};
        listKey = null;
        const kv = rest.match(/^([\w-]+):\s*(.*)$/);
        if (kv) {
          if (kv[2]) setKey(cur, kv[1], kv[2]);
          else { cur[kv[1]] = []; listKey = kv[1]; }
        }
      }
      items.push(cur);
    } else if (cur && dash && listKey) {
      cur[listKey].push(unquote(dash[1]));
    } else if (cur && indent === base + 2) {
      const kv = line.trim().match(/^([\w-]+):\s*(.*)$/);
      if (kv) {
        if (kv[2]) { setKey(cur, kv[1], kv[2]); listKey = null; }
        else { cur[kv[1]] = []; listKey = kv[1]; }
      }
    }
  }
  return items;
}

function bootstrapDns(yaml) {
  const out = [];
  let inList = false;
  for (const line of sectionLines(yaml, 'dns')) {
    if (/^\s+default-nameserver:\s*$/.test(line)) { inList = true; continue; }
    const inline = line.match(/^\s+default-nameserver:\s*(\[.*\])\s*$/);
    if (inline) { out.push(...inlineList(inline[1])); continue; }
    if (inList) {
      const m = line.match(/^\s*- (.*)$/);
      if (m) out.push(unquote(m[1]));
      else inList = false;
    }
  }
  return out.filter(isIpv4);
}

export function parseClashConfig(yaml) {
  return {
    proxies: parseItems(sectionLines(yaml, 'proxies')).filter((p) => p.name),
    groups: parseItems(sectionLines(yaml, 'proxy-groups')).filter((g) => g.name),
    dns: bootstrapDns(yaml),
  };
}

/**
 * Expands selected names into the IPs the Clash core dials on the physical NIC.
 * A group contributes its members. A node with `dialer-proxy` contributes its dialer
 * instead of itself: its own server is only ever reached through that dialer.
 */
export function resolveTargets(targets, { proxies, groups }) {
  const proxyByName = new Map(proxies.map((p) => [p.name, p]));
  const groupByName = new Map(groups.map((g) => [g.name, g]));
  const ips = new Set();
  const nodes = new Set();
  const warnings = [];
  const seen = new Set();

  const visit = (name, topLevel) => {
    if (BUILTIN.has(name) || seen.has(name)) return;
    seen.add(name);
    const group = groupByName.get(name);
    if (group) {
      if (group.use?.length) warnings.push(`组「${name}」使用了 proxy-provider，其中的节点未被放行`);
      for (const member of group.proxies ?? []) visit(member, false);
      return;
    }
    const proxy = proxyByName.get(name);
    if (!proxy) {
      if (topLevel) warnings.push(`配置中找不到「${name}」`);
      else warnings.push(`组成员「${name}」不存在`);
      return;
    }
    nodes.add(name);
    const dialer = proxy['dialer-proxy'];
    if (dialer) {
      visit(dialer, false);
    } else if (isIpv4(proxy.server)) {
      ips.add(proxy.server);
    } else {
      warnings.push(`节点「${name}」的服务器不是 IPv4 地址，未被放行，它将无法连接`);
    }
  };
  for (const t of targets) visit(t, true);
  return { ips: [...ips].sort(), nodes: [...nodes].sort(), warnings };
}

/** Accepts plain CIDR lines and `IP-CIDR,` rules, the two forms rule sets use. */
export function parseCidrList(text) {
  const out = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const value = line.startsWith('IP-CIDR,') ? line.split(',')[1] : line;
    if (value.includes('/') && isIpv4Cidr(value) && Number(value.split('/')[1]) >= 8) out.add(value);
  }
  return [...out].sort();
}

function writeIfChanged(file, lines) {
  const content = lines.length ? `${lines.join('\n')}\n` : '';
  try {
    if (fs.readFileSync(file, 'utf8') === content) return false;
  } catch { /* first write */ }
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  fs.renameSync(tmp, file);
  return true;
}

/**
 * Turns the Clash config into allow-list files for the root script. It never shrinks
 * the lists on a bad read: Verge rewrites its config in place, and the failure mode of
 * a stale list is an unreachable node, while an empty one would take the network down.
 */
export class PfPlanner {
  constructor({ store, getSettings, home = os.homedir(), intervalMs = 15000 }) {
    Object.assign(this, { store, getSettings, intervalMs });
    this.vergeDir = path.join(home, VERGE_DIR);
    this.dir = path.join(store.dir, 'pf');
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    this.status = { ready: false, nodes: [], counts: {}, warnings: ['尚未计算'], updatedAt: null };
  }

  start() {
    this.timer ??= setInterval(() => this.tick(), this.intervalMs);
    this.tick();
  }

  stop() {
    clearInterval(this.timer);
    this.timer = null;
  }

  tick() {
    const g = this.getSettings();
    const instanceNodes = this.store.instanceTargets();
    const targets = [...new Set([...g.pfTargets, ...instanceNodes])];
    const warnings = [];
    if (!targets.length) warnings.push('尚未选择放行的节点或组');

    let config;
    try {
      config = parseClashConfig(fs.readFileSync(path.join(this.vergeDir, 'clash-verge.yaml'), 'utf8'));
    } catch (e) {
      this.status = { ...this.status, ready: false, warnings: [`无法读取 Clash Verge 配置：${e.message}，继续使用上次的列表`] };
      return;
    }
    if (!config.proxies.length) {
      this.status = { ...this.status, ready: false, warnings: ['配置中没有解析到节点，继续使用上次的列表'] };
      return;
    }

    const { ips, nodes, warnings: w } = resolveTargets(targets, config);
    warnings.push(...w);
    const changed = [];
    // An empty result leaves the last good list in place rather than cutting every node.
    if (ips.length) {
      if (writeIfChanged(path.join(this.dir, 'nodes.txt'), ips)) changed.push('nodes');
    } else if (targets.length) {
      warnings.push('所选内容没有可放行的节点 IP，继续使用上次的列表');
    }
    if (writeIfChanged(path.join(this.dir, 'dns.txt'), config.dns)) changed.push('dns');
    if (writeIfChanged(path.join(this.dir, 'extra.txt'), g.pfExtra)) changed.push('extra');

    let cnCount = 0;
    try {
      const cn = parseCidrList(fs.readFileSync(path.join(this.vergeDir, g.pfCnList), 'utf8'));
      cnCount = cn.length;
      if (cn.length >= MIN_CN_ENTRIES) {
        if (writeIfChanged(path.join(this.dir, 'cn.txt'), cn)) changed.push('cn');
      } else {
        warnings.push(`国内 IP 列表只有 ${cn.length} 条，疑似损坏，继续使用上次的列表`);
      }
    } catch (e) {
      warnings.push(`无法读取国内 IP 列表：${e.message}`);
    }

    const hasNodes = fs.existsSync(path.join(this.dir, 'nodes.txt'));
    const hasCn = fs.existsSync(path.join(this.dir, 'cn.txt'));
    this.status = {
      ready: hasNodes && hasCn,
      nodes,
      counts: { ips: ips.length, dns: config.dns.length, cn: cnCount, extra: g.pfExtra.length },
      warnings,
      changed,
      updatedAt: Date.now(),
    };
  }
}
