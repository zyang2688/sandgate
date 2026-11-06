import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ValidationError, validTimezone } from './config.js';
import { parseClashConfig, sectionLines, unquote } from './pfplan.js';

const VERGE_DIR = 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev';
const BLOCK_START = '// >>> SandGate managed block: generated, edits are overwritten. Manage it on the SandGate page.';
const BLOCK_END = '// <<< SandGate managed block';

export const FOLLOW = 'follow';
export const NO_NETWORK = 'none';

const fail = (msg) => { throw new ValidationError(msg); };
const hasControl = (s) => /[\x00-\x1f\x7f]/.test(s);

export const ruleKey = (id) => `sgp-${id}`;
export const isRuleKey = (key) => String(key).startsWith('sgp-');

/** The extra rule shape mihomo accepts in a sub-rule. MATCH would hide every rule after it. */
function validRule(line) {
  const rule = String(line).trim();
  const parts = rule.split(',').map((p) => p.trim());
  if (hasControl(rule) || parts.length < 3 || parts.length > 4 || !/^[A-Z][A-Z0-9-]*$/.test(parts[0]) || parts.some((p) => !p)) {
    fail(`规则格式错误: ${rule}，例如 DOMAIN-SUFFIX,example.com,DIRECT`);
  }
  if (['MATCH', 'SUB-RULE', 'AND', 'OR', 'NOT'].includes(parts[0])) fail(`额外规则不支持 ${parts[0]}`);
  return rule;
}

export function validateNetProfile(input, existing = {}) {
  const name = String(input.name ?? '').trim();
  if (!name || name.length > 64 || hasControl(name)) fail('配置名称需为 1-64 个字符');
  const mode = input.mode ?? existing.mode;
  if (!['custom', 'node'].includes(mode)) fail('配置模式只能是 custom 或 node');
  const timezone = validTimezone(input.timezone ?? existing.timezone ?? '');
  const base = { id: existing.id ?? crypto.randomBytes(5).toString('hex'), name, mode, timezone };
  if (mode === 'node') {
    const node = String(input.node ?? '').trim();
    if (!node || hasControl(node)) fail('请选择节点');
    return { ...base, node, exits: {}, extraRules: [] };
  }
  const rawExits = input.exits ?? {};
  if (typeof rawExits !== 'object' || Array.isArray(rawExits)) fail('出口替换格式错误');
  const exits = {};
  for (const [group, target] of Object.entries(rawExits)) {
    const t = String(target ?? '').trim();
    if (hasControl(group) || hasControl(t)) fail('出口替换里有非法字符');
    if (t) exits[group] = t;
  }
  if (!Array.isArray(input.extraRules ?? [])) fail('额外规则必须是数组');
  const extraRules = (input.extraRules ?? []).map(validRule);
  if (!Object.keys(exits).length && !extraRules.length) fail('至少替换一个出口，或加一条额外规则');
  return { ...base, node: '', exits, extraRules };
}

/** The Clash side of the profiles. Every profile keeps a listener, so instances can come and go freely. */
export function buildSpec(data) {
  const listeners = new Map();
  const subRules = {};
  for (const p of data.netProfiles ?? []) {
    const key = p.mode === 'node' ? p.node : ruleKey(p.id);
    const port = data.gate.listeners[key];
    if (!port) continue;
    const common = { type: 'mixed', listen: '127.0.0.1', port };
    if (p.mode === 'node') {
      listeners.set(`sandgate-${port}`, { name: `sandgate-${port}`, ...common, proxy: p.node });
    } else {
      listeners.set(key, { name: key, ...common, rule: key });
      subRules[key] = { exits: p.exits, extra: p.extraRules };
    }
  }
  return { listeners: [...listeners.values()], subRules, guard: buildGuard(data.gate) };
}

/** Addresses pf passes on the NIC besides the Mainland list: the local network, then pf's extras. */
export const GUARD_LOCAL = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '224.0.0.0/4', '255.255.255.255/32', '::1/128', 'fe80::/10', 'ff00::/8'];

function buildGuard(gate = {}) {
  if (!gate.foreignDirectVia) return null;
  return { via: gate.foreignDirectVia, cnPath: `./${gate.pfCnList}`, allow: [...GUARD_LOCAL, ...(gate.pfExtra ?? [])] };
}

/**
 * Runs both here and inside Clash Verge's script engine, so it stays plain ES5 with no
 * outside references. mihomo rejects the whole config over one unknown policy, and a
 * subscription can drop a node at any time, so an unknown target becomes REJECT: the
 * connection fails visibly instead of taking the network down or using the wrong exit.
 */
function applySandgateSpec(config, spec) {
  var builtin = { DIRECT: 1, REJECT: 1, 'REJECT-DROP': 1, PASS: 1, COMPATIBLE: 1, GLOBAL: 1 };
  var known = {};
  (config.proxies || []).forEach(function (p) { known[p.name] = 1; });
  (config['proxy-groups'] || []).forEach(function (g) { known[g.name] = 1; });
  var usable = function (name) { return builtin[name] || known[name] ? name : 'REJECT'; };
  var managed = function (name) { return String(name).indexOf('sandgate-') === 0 || String(name).indexOf('sgp-') === 0; };

  config.listeners = (config.listeners || []).filter(function (l) { return !managed(l && l.name); }).concat(spec.listeners);

  // The config may already carry an earlier run's output (Clash Verge's generated file), so
  // the guard is first undone, then applied again from the current settings.
  var GUARD_SET = '(RULE-SET,sandgate-cn)';
  var DNS_MARK = '&sandgate=1';
  var rules = Array.isArray(config.rules) ? config.rules : [];
  var plain = [];
  for (var i = 0; i < rules.length; i++) {
    var r = String(rules[i]);
    if (r.indexOf(GUARD_SET) < 0) { plain.push(rules[i]); continue; }
    // A guard pair: the AND rule, then the same rule pointed at the guard's group.
    var next = String(rules[i + 1] || '').split(',');
    if (r.indexOf('OR,(') === 0) plain.push('MATCH,DIRECT');
    else { next[next[0].trim() === 'MATCH' ? 1 : 2] = 'DIRECT'; plain.push(next.join(',')); }
    i++;
  }
  var providers = config['rule-providers'] || {};
  delete providers['sandgate-cn'];
  var dns = config.dns || {};
  if (Array.isArray(dns.fallback)) {
    dns.fallback = dns.fallback.map(function (s) {
      s = String(s);
      return s.slice(-DNS_MARK.length) === DNS_MARK ? s.slice(0, s.indexOf('#')) : s;
    });
  }

  // DIRECT is only kept where pf lets it through: Mainland IPs (the same file pf loads), the
  // local network and pf's extra list. Anything else matched by a DIRECT rule takes the
  // guard's group, instead of failing on the NIC. The fallback DNS servers are only queried
  // for non-Mainland answers, and dialing them directly fails the same way.
  var g = spec.guard;
  if (g) {
    var via = usable(g.via);
    var allowed = [GUARD_SET].concat(g.allow.map(function (c) {
      return '(' + (c.indexOf(':') >= 0 ? 'IP-CIDR6' : 'IP-CIDR') + ',' + c + ')';
    }));
    var inSet = '(OR,(' + allowed.join(',') + '))';
    var guarded = [];
    plain.forEach(function (rule) {
      var parts = String(rule).split(',');
      var type = parts[0].trim();
      if (type === 'MATCH' && parts[1] && parts[1].trim() === 'DIRECT') {
        guarded.push('OR,(' + allowed.join(',') + '),DIRECT', 'MATCH,' + via);
        return;
      }
      // Logic rules and payloads with brackets cannot be nested safely, so they stay as they are.
      if (type === 'AND' || type === 'OR' || type === 'NOT' || type === 'SUB-RULE' || type === 'MATCH'
        || parts.length < 3 || parts[2].trim() !== 'DIRECT' || /[()]/.test(rule)) {
        guarded.push(rule);
        return;
      }
      var inner = [parts[0], parts[1]].concat(parts.slice(3)).join(',');
      parts[2] = via;
      guarded.push('AND,((' + inner + '),' + inSet + '),DIRECT', parts.join(','));
    });
    plain = guarded;
    providers['sandgate-cn'] = { type: 'file', behavior: 'ipcidr', format: 'text', path: g.cnPath, interval: 3600 };
    if (Array.isArray(dns.fallback)) {
      dns.fallback = dns.fallback.map(function (s) {
        return s.indexOf('#') >= 0 ? s : s + '#' + encodeURIComponent(via) + DNS_MARK;
      });
    }
  }
  config.rules = plain;
  if (Object.keys(providers).length) config['rule-providers'] = providers;
  if (config.dns) config.dns = dns;

  var base = plain;
  var subs = {};
  Object.keys(config['sub-rules'] || {}).forEach(function (k) { if (!managed(k)) subs[k] = config['sub-rules'][k]; });
  Object.keys(spec.subRules).forEach(function (name) {
    var s = spec.subRules[name];
    var extra = s.extra.map(function (rule) {
      var parts = String(rule).split(',');
      parts[2] = usable(parts[2].trim());
      return parts.join(',');
    });
    subs[name] = extra.concat(base.map(function (rule) {
      var parts = String(rule).split(',');
      var type = parts[0].trim();
      if (type === 'AND' || type === 'OR' || type === 'NOT' || type === 'SUB-RULE') return rule;
      var at = type === 'MATCH' ? 1 : 2;
      var target = parts[at] && s.exits[parts[at].trim()];
      if (target) parts[at] = usable(target);
      return parts.join(',');
    }));
  });
  if (Object.keys(subs).length) config['sub-rules'] = subs;
  else delete config['sub-rules'];
  return config;
}

export function applySpec(config, spec) {
  return applySandgateSpec(config, spec);
}

/** Exits and policies the current config cannot satisfy; these instances get REJECT. */
export function missingTargets(spec, { proxies, groups }) {
  const known = new Set([...proxies, ...groups].map((p) => p.name));
  for (const b of ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL']) known.add(b);
  const missing = new Set();
  if (spec.guard && !known.has(spec.guard.via)) missing.add(spec.guard.via);
  for (const s of Object.values(spec.subRules)) {
    for (const t of Object.values(s.exits)) if (!known.has(t)) missing.add(t);
    for (const r of s.extra) {
      const policy = r.split(',')[2]?.trim();
      if (policy && !known.has(policy)) missing.add(policy);
    }
  }
  return [...missing];
}

/** Removes a top-level block. Verge writes block style, so a key starts at column 0. */
function removeSection(lines, key) {
  const start = lines.findIndex((l) => l.startsWith(`${key}:`));
  if (start < 0) return lines;
  let end = start + 1;
  while (end < lines.length && !/^[^\s#-]/.test(lines[end])) end++;
  return [...lines.slice(0, start), ...lines.slice(end)];
}

const nameOf = (chunk) => unquote(chunk.join('\n').match(/(?:^|[\s{,-])"?name"?:\s*("[^"]*"|'[^']*'|[^,}\n]+)/)?.[1] ?? '');

/** Splits a block list into its items as raw lines. */
function listItems(lines) {
  const first = lines.find((l) => /^\s*- /.test(l));
  if (!first) return { indent: '', items: [] };
  const indent = first.slice(0, first.indexOf('-'));
  const items = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    if (line.startsWith(`${indent}- `)) items.push([line]);
    else items.at(-1)?.push(line);
  }
  return { indent, items };
}

/** Splits a block map into its entries as raw lines. */
function mapEntries(lines) {
  const first = lines.find((l) => /^\s+\S/.test(l));
  if (!first) return { indent: '  ', entries: [] };
  const indent = first.slice(0, first.length - first.trimStart().length);
  const entries = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const isKey = line.startsWith(indent) && !/\s/.test(line[indent.length]) && line[indent.length] !== '-';
    if (isKey) entries.push({ key: unquote(line.trim().replace(/:.*$/, '')), lines: [line] });
    else entries.at(-1)?.lines.push(line);
  }
  return { indent, entries };
}

/**
 * Where `dns.fallback`'s items are in the file: a block list, which Verge writes at the
 * key's own indent, or an inline one. Null when there is no such key.
 */
function findFallback(lines) {
  const dns = lines.findIndex((l) => l.startsWith('dns:'));
  if (dns < 0) return null;
  for (let i = dns + 1; i < lines.length && !/^[^\s#-]/.test(lines[i]); i++) {
    const m = lines[i].match(/^(\s+)fallback:\s*(.*)$/);
    if (!m) continue;
    const indent = m[1];
    if (m[2].startsWith('[')) return { at: i, count: 0, indent, inline: true, values: m[2].replace(/\s+#.*$/, '').slice(1, -1).split(',').map(unquote).filter(Boolean) };
    let end = i + 1;
    while (end < lines.length && lines[end].startsWith(indent) && /^\s*- /.test(lines[end])) end++;
    return { at: i, count: end - i - 1, indent, inline: false, values: lines.slice(i + 1, end).map((l) => unquote(l.replace(/^\s*- /, ''))) };
  }
  return null;
}

/**
 * Applies the spec to Clash Verge's generated config as text, since this project has no
 * YAML library. Only `listeners`, `sub-rules`, `rules`, SandGate's rule provider and
 * `dns.fallback` are rewritten, each only when it changes, and YAML accepts the JSON used
 * for the managed entries.
 */
export function renderRuntimeYaml(text, spec) {
  const parsed = parseClashConfig(text);
  const rules = sectionLines(text, 'rules').map((l) => l.match(/^\s*- (.*)$/)?.[1]).filter(Boolean).map(unquote);
  let lines = text.split(/\r?\n/);
  const fallback = findFallback(lines);
  const config = { rules, proxies: parsed.proxies, 'proxy-groups': parsed.groups, listeners: [], 'sub-rules': {}, 'rule-providers': {} };
  if (fallback) config.dns = { fallback: [...fallback.values] };
  const result = applySpec(config, spec);

  const isManaged = (name) => name.startsWith('sandgate-') || name.startsWith('sgp-');
  const { indent: listIndent, items } = listItems(sectionLines(text, 'listeners'));
  const keptListeners = items.filter((i) => !isManaged(nameOf(i))).flat();
  const { indent: mapIndent, entries } = mapEntries(sectionLines(text, 'sub-rules'));
  const keptSubs = entries.filter((e) => !isManaged(e.key)).flatMap((e) => e.lines);
  const providerLines = sectionLines(text, 'rule-providers');
  const { indent: provIndent, entries: provEntries } = mapEntries(providerLines);
  const keptProviders = provEntries.filter((e) => !isManaged(e.key)).flatMap((e) => e.lines);
  const newProviders = Object.entries(result['rule-providers'] ?? {}).map(([k, v]) => `${provIndent}${JSON.stringify(k)}: ${JSON.stringify(v)}`);
  const providersChanged = JSON.stringify([...keptProviders, ...newProviders]) !== JSON.stringify(provEntries.flatMap((e) => e.lines));
  const rulesChanged = result.rules.length !== rules.length || result.rules.some((r, i) => r !== rules[i]);

  // In place first, so the line numbers found above still hold.
  const fb = result.dns?.fallback;
  if (fallback && fb.some((v, i) => v !== fallback.values[i])) {
    const key = `${fallback.indent}fallback:`;
    const replacement = fallback.inline ? [`${key} ${JSON.stringify(fb)}`] : [key, ...fb.map((v) => `${fallback.indent}- ${JSON.stringify(v)}`)];
    lines.splice(fallback.at, fallback.count + 1, ...replacement);
  }
  lines = removeSection(lines, 'listeners');
  lines = removeSection(lines, 'sub-rules');
  if (rulesChanged) lines = removeSection(lines, 'rules');
  if (providersChanged) lines = removeSection(lines, 'rule-providers');
  while (lines.length && !lines.at(-1).trim()) lines.pop();

  if (providersChanged && (keptProviders.length || newProviders.length)) lines.push('rule-providers:', ...keptProviders, ...newProviders);
  if (rulesChanged) lines.push('rules:', ...result.rules.map((r) => `- ${JSON.stringify(r)}`));
  const newListeners = result.listeners.map((l) => `${listIndent}- ${JSON.stringify(l)}`);
  if (keptListeners.length || newListeners.length) lines.push('listeners:', ...keptListeners, ...newListeners);
  const newSubs = Object.entries(result['sub-rules'] ?? {}).map(([k, v]) => `${mapIndent}${JSON.stringify(k)}: ${JSON.stringify(v)}`);
  if (keptSubs.length || newSubs.length) lines.push('sub-rules:', ...keptSubs, ...newSubs);
  return `${lines.join('\n')}\n`;
}

/** Finds the script extension of the profile Clash Verge is using. */
export function currentScriptFile(profilesYaml) {
  const current = profilesYaml.match(/^current:\s*(.+)$/m);
  if (!current) return null;
  const chunks = profilesYaml.split(/^\s*- uid:\s*/m).slice(1);
  const items = new Map(chunks.map((c) => [unquote(c.split('\n')[0]), c]));
  const scriptId = items.get(unquote(current[1]))?.match(/^\s+script:\s*(.+)$/m)?.[1];
  if (!scriptId) return null;
  return unquote(items.get(unquote(scriptId))?.match(/^\s+file:\s*(.+)$/m)?.[1] ?? '') || null;
}

/** Puts the managed block before the final `return config`, replacing any earlier one. */
export function withManagedBlock(source, spec) {
  const start = source.indexOf(BLOCK_START);
  let text = source;
  if (start >= 0) {
    const end = source.indexOf(BLOCK_END, start);
    if (end < 0) throw new Error('脚本扩展里的 SandGate 区块不完整');
    const lineStart = source.lastIndexOf('\n', start) + 1;
    const lineEnd = source.indexOf('\n', end);
    text = source.slice(0, lineStart) + source.slice(lineEnd < 0 ? source.length : lineEnd + 1);
  }
  if (!spec.listeners.length && !spec.guard) return text;
  const at = text.lastIndexOf('return config');
  if (at < 0) throw new Error('脚本扩展里找不到 return config');
  const lineStart = text.lastIndexOf('\n', at) + 1;
  const block = [
    `  ${BLOCK_START}`,
    `  config = (${applySandgateSpec.toString()})(config, ${JSON.stringify(spec)});`,
    `  ${BLOCK_END}`,
    '',
  ].join('\n');
  const result = text.slice(0, lineStart) + block + text.slice(lineStart);
  new Function(result); // a script with a syntax error would stop Clash Verge from building its config
  return result;
}

/**
 * Keeps Clash in step with the profiles, in two places: the script extension, so Clash
 * Verge rebuilds the same result, and the running core, so it applies right away.
 */
export class ClashSync {
  constructor({ store, client, home = os.homedir(), enabled = true }) {
    Object.assign(this, { store, client, enabled });
    this.vergeDir = path.join(home, VERGE_DIR);
    this.status = { state: 'idle', message: '尚未同步', at: null };
    this.queue = Promise.resolve();
  }

  #scriptPath() {
    const yaml = fs.readFileSync(path.join(this.vergeDir, 'profiles.yaml'), 'utf8');
    const file = currentScriptFile(yaml);
    if (!file) throw new Error('当前 Clash Verge 配置没有脚本扩展');
    return path.join(this.vergeDir, 'profiles', file);
  }

  /** Writes only on a real change. The first write keeps a backup of the user's script. */
  writeScript(spec = buildSpec(this.store.data)) {
    const file = this.#scriptPath();
    const before = fs.readFileSync(file, 'utf8');
    const after = withManagedBlock(before, spec);
    if (after === before) return false;
    const backups = path.join(this.store.dir, 'backups');
    fs.mkdirSync(backups, { recursive: true, mode: 0o700 });
    const backup = path.join(backups, `${path.basename(file)}.before-sandgate`);
    if (!fs.existsSync(backup)) fs.copyFileSync(file, backup);
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, after);
    fs.renameSync(tmp, file);
    return true;
  }

  /**
   * Whether Clash Verge's last generated config carries the managed entries. Only Clash
   * Verge can regenerate it, so this is how a broken script extension shows up. Entries
   * missing from a config older than the script are just waiting for the next generation.
   *   ok: present. pending: waiting. no-script: the script lacks them, so the next
   *   generation will drop them. broken: generated from this script and still missing.
   */
  generatedStatus(spec = buildSpec(this.store.data)) {
    const file = path.join(this.vergeDir, 'clash-verge.yaml');
    const { items } = listItems(sectionLines(fs.readFileSync(file, 'utf8'), 'listeners'));
    const names = new Set(items.map(nameOf));
    const missing = spec.listeners.map((l) => l.name).filter((n) => !names.has(n));
    const generatedAt = fs.statSync(file).mtimeMs;
    if (!missing.length) return { state: 'ok', missing, generatedAt };
    let script;
    try {
      script = this.#scriptPath();
      const text = fs.readFileSync(script, 'utf8');
      if (withManagedBlock(text, spec) !== text) return { state: 'no-script', missing, generatedAt };
    } catch {
      return { state: 'no-script', missing, generatedAt };
    }
    return { state: fs.statSync(script).mtimeMs > generatedAt ? 'pending' : 'broken', missing, generatedAt };
  }

  async #apply() {
    const spec = buildSpec(this.store.data);
    const problems = [];
    try {
      this.writeScript(spec);
    } catch (e) {
      problems.push(`脚本扩展没有更新，Clash Verge 重新生成配置后改动会丢失：${e.message}`);
    }
    const text = fs.readFileSync(path.join(this.vergeDir, 'clash-verge.yaml'), 'utf8');
    const missing = missingTargets(spec, parseClashConfig(text));
    if (missing.length) problems.push(`Clash 中找不到 ${missing.join('、')}，用到它们的流量会被拒绝`);
    await this.client.reload(renderRuntimeYaml(text, spec));
    return problems;
  }

  /** One at a time: each run reads the latest profiles, so overlapping saves still converge. */
  apply() {
    if (!this.enabled) return Promise.resolve(this.status);
    const run = this.queue.then(async () => {
      try {
        const problems = await this.#apply();
        this.status = { state: problems.length ? 'warn' : 'ok', message: problems.join('；') || '已同步到 Clash', at: Date.now() };
      } catch (e) {
        this.status = { state: 'fail', message: `同步失败，Clash 仍在使用原来的配置：${e.message}`, at: Date.now() };
      }
      return this.status;
    });
    this.queue = run;
    return run;
  }
}
