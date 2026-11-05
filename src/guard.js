import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import os from 'node:os';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const ALWAYS_ALLOWED = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS']);
const LISTENER_NAME = /^sandgate-(\d+)$/;
const RECENT_LIMIT = 20;

/**
 * Connections using a proxy they should not. A sandgate listener may only use its
 * own node. Other traffic may use DIRECT or the default node; with no default node
 * configured there is nothing to enforce for it.
 */
export function findViolations(connections, { defaultNode, listeners }) {
  const nodeByPort = new Map(Object.entries(listeners).map(([node, port]) => [port, node]));
  return connections.filter((c) => {
    const via = c.chains?.[0];
    const m = String(c.metadata?.inboundName ?? '').match(LISTENER_NAME);
    if (m) return via !== nodeByPort.get(Number(m[1]));
    // A profile's listener follows its own rules, so no single node is correct for it.
    if (String(c.metadata?.inboundName ?? '').startsWith('sgp-')) return false;
    if (!defaultNode) return false;
    return via !== defaultNode && !ALWAYS_ALLOWED.has(via);
  });
}

const MODE_WARNINGS = {
  direct: 'Clash 是 direct 模式：所有流量都直连，国外网站会被 pf 拦住，国内网站看到的是真实 IP。',
  global: 'Clash 是 global 模式：不再按规则分流，所有流量都走 GLOBAL 组当前选的出口。',
};

/** Empty for rule mode, which is what the whole-Mac protection assumes. */
export function modeWarning(mode) {
  if (!mode || mode === 'rule') return '';
  return MODE_WARNINGS[mode] ?? `Clash 是 ${mode} 模式，不再按规则分流。`;
}

/**
 * pf's final rule on each physical NIC has no address family, so it also drops public
 * IPv6. Its effect is taken from the protection probe, which tests over IPv4.
 */
export function ipv6Check(protection, clashIpv6) {
  const clash = `Clash 的 IPv6 ${clashIpv6 ? '已开启' : '已关闭'}`;
  if (protection === 'protected') return { status: 'ok', detail: `物理网卡已拦截公网 IPv6。${clash}。` };
  if (protection === 'exposed') return { status: 'warn', detail: `pf 未生效，物理网卡没有拦截 IPv6。${clash}。` };
  return { status: 'warn', detail: `还不能确认物理网卡是否拦截了 IPv6，全机防护状态未知。${clash}。` };
}

const FINGERPRINT_VERSION = 'v2:';

/**
 * Covers what routes traffic, in order. The response also holds hit and miss counters
 * that change with every connection, so hashing all of it would alert constantly.
 */
export function rulesFingerprint({ rules = [] }) {
  const meaningful = rules.map((r) => [r.type, r.payload, r.proxy, Boolean(r.extra?.disabled)]);
  return FINGERPRINT_VERSION + crypto.createHash('sha256').update(JSON.stringify(meaningful)).digest('hex');
}

/**
 * pf cannot pin nodes once Clash also needs DIRECT, so this enforces it from the
 * Clash side. It reacts after the fact: a connection on the wrong node lives until
 * the next poll. Rule changes only raise an alert, since cutting traffic for them
 * would also take down direct access.
 */
export class ConnectionGuard {
  constructor({ client, getSettings, saveRulesHash, intervalMs = 2000 }) {
    Object.assign(this, { client, getSettings, saveRulesHash, intervalMs });
    this.status = { active: false, error: '尚未检查', killed: 0, recent: [], rulesChanged: false, modeWarning: '' };
  }

  start() {
    this.timer ??= setInterval(() => this.tick(), this.intervalMs);
    this.tick();
  }

  stop() {
    clearInterval(this.timer);
    this.timer = null;
  }

  async tick() {
    if (this.running) return;
    this.running = true;
    try {
      const g = this.getSettings();
      const { connections = [] } = await this.client.connections();
      for (const c of findViolations(connections, g)) {
        await this.client.closeConnection(c.id);
        this.status.killed++;
        this.status.recent.unshift({
          at: Date.now(),
          host: c.metadata?.host || c.metadata?.destinationIP || '',
          via: c.chains?.[0] ?? '未知',
        });
        this.status.recent.length = Math.min(this.status.recent.length, RECENT_LIMIT);
      }
      const hash = rulesFingerprint(await this.client.rules());
      this.currentHash = hash;
      // A baseline from an older fingerprint format says nothing about the current rules.
      if (!g.rulesHash?.startsWith(FINGERPRINT_VERSION)) this.saveRulesHash(hash);
      this.status.rulesChanged = g.rulesHash?.startsWith(FINGERPRINT_VERSION) === true && hash !== g.rulesHash;
      this.status.modeWarning = modeWarning((await this.client.configs()).mode);
      this.status.active = true;
      this.status.error = '';
    } catch (e) {
      this.status.active = false;
      this.status.modeWarning = '';
      this.status.error = e.message;
    } finally {
      this.running = false;
    }
  }

  acceptRules() {
    if (this.currentHash) this.saveRulesHash(this.currentHash);
    this.status.rulesChanged = false;
  }
}

/**
 * Tests the protection itself instead of trusting configuration: one TCP handshake out
 * the physical NIC to a foreign host pf should drop, and one to a domestic host it
 * should pass. The domestic control separates "blocked" from "the network is down".
 */
export class ProtectionProbe {
  constructor({ getSettings, foreign = '17.253.144.10', domestic = '223.5.5.5', port = 443, intervalMs = 60000 }) {
    Object.assign(this, { getSettings, foreign, domestic, port, intervalMs });
    this.status = { state: 'unknown', iface: '', detail: '尚未检查', at: null };
  }

  async #reachable(iface, host) {
    try {
      await exec('/usr/bin/nc', ['-z', '-G', '3', '-b', iface, host, String(this.port)], { timeout: 6000 });
      return true;
    } catch {
      return false;
    }
  }

  start() {
    this.timer ??= setInterval(() => this.tick(), this.intervalMs);
    this.tick();
  }

  stop() {
    clearInterval(this.timer);
    this.timer = null;
  }

  async tick() {
    const iface = this.getSettings().probeInterface;
    const hasV4 = (os.networkInterfaces()[iface] ?? []).some((a) => a.family === 'IPv4' && !a.internal);
    if (!hasV4) {
      this.status = { state: 'unknown', iface, detail: `${iface} 没有 IPv4 地址，无法检测`, at: Date.now() };
      return;
    }
    if (await this.#reachable(iface, this.foreign)) {
      this.status = { state: 'exposed', iface, detail: `程序能从 ${iface} 直连国外，Clash 中断时会暴露`, at: Date.now() };
    } else if (await this.#reachable(iface, this.domestic)) {
      this.status = { state: 'protected', iface, detail: `从 ${iface} 直连国外被拦截，国内可达`, at: Date.now() };
    } else {
      this.status = { state: 'unknown', iface, detail: `从 ${iface} 国内外都连不上，可能是网络本身不通`, at: Date.now() };
    }
  }
}
