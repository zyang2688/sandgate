import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { instanceArgs } from './apps.js';
import { buildEnv, expandVars } from './profile.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
export const RUNNER = path.join(ROOT, 'bin/sandgate-run');
const BEGIN = '# >>> sandgate >>>';
const END = '# <<< sandgate <<<';

/** One shell word. Single quotes keep everything literal, newlines included. */
export const shellQuote = (s) => `'${String(s).replaceAll("'", "'\\''")}'`;

export const aliasFile = (store) => path.join(store.dir, 'aliases.zsh');
export const commandDir = (store) => path.join(store.dir, 'bin');
const SHIM_MARK = '# sandgate-command';

/**
 * One executable per terminal command, at a path that never changes. It names the command,
 * not an instance, so moving the command to another instance needs no edit anywhere, and
 * programs that take a path to claude (CLAUDE_CLI_PATH) can point here.
 */
export function shimText(alias, { runner = RUNNER, node = process.execPath } = {}) {
  // node is fixed here because the caller's PATH may not have the one SandGate runs with.
  return `#!/bin/sh\n${SHIM_MARK}\n# 由 SandGate 生成：运行终端命令 ${alias} 当前指向的实例。\nexport SANDGATE_NODE=${shellQuote(node)}\nexec ${shellQuote(runner)} ${shellQuote(alias)} "$@"\n`;
}

/** The alias lines for every terminal command; each calls its executable. */
export function renderAliases(apps, dir) {
  const lines = ['# 由 SandGate 生成，改别名请到设置页的实例里改，不要手动编辑。'];
  // The alias text is itself shell code, so the path is quoted inside it, then the whole.
  for (const a of apps.filter((x) => x.alias)) lines.push(`alias ${a.alias}=${shellQuote(shellQuote(path.join(dir, a.alias)))}`);
  return lines.join('\n') + '\n';
}

function writeAtomic(file, text, mode) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text, { mode });
  fs.chmodSync(tmp, mode);
  fs.renameSync(tmp, file);
}

export function writeAliases(store, opts) {
  const dir = commandDir(store);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const aliases = store.data.apps.filter((a) => a.alias).map((a) => a.alias);
  for (const alias of aliases) writeAtomic(path.join(dir, alias), shimText(alias, opts), 0o700);
  // Only files this code wrote are removed, so anything else put there is left alone.
  for (const f of fs.readdirSync(dir)) {
    const file = path.join(dir, f);
    if (aliases.includes(f)) continue;
    try {
      if (fs.readFileSync(file, 'utf8').split('\n')[1] === SHIM_MARK) fs.rmSync(file);
    } catch { /* not a file of ours */ }
  }
  const file = aliasFile(store);
  writeAtomic(file, renderAliases(store.data.apps, dir), 0o600);
  return file;
}

/** The block that loads the aliases. It goes last, so it wins over earlier aliases of the same name. */
export function zshrcBlock(file) {
  return `${BEGIN}\n[ -r ${shellQuote(file)} ] && source ${shellQuote(file)}\n${END}\n`;
}

export function withoutBlock(text) {
  const start = text.indexOf(BEGIN);
  if (start < 0) return text;
  const end = text.indexOf(END, start);
  if (end < 0) return text;
  return text.slice(0, start) + text.slice(end + END.length).replace(/^\n/, '');
}

export function withBlock(text, file) {
  const base = withoutBlock(text);
  return (base && !base.endsWith('\n') ? `${base}\n` : base) + zshrcBlock(file);
}

/** Earlier `alias name=` lines that the block will override, so the user knows. */
export function shadowedAliases(text, names) {
  const out = [];
  withoutBlock(text).split('\n').forEach((line, i) => {
    const m = line.match(/^\s*alias\s+([A-Za-z_][A-Za-z0-9_.-]*)=/);
    if (m && names.includes(m[1])) out.push({ line: i + 1, name: m[1], text: line.trim() });
  });
  return out;
}

export function installZshrc(store, zshrc = path.join(os.homedir(), '.zshrc')) {
  const file = writeAliases(store);
  const before = fs.existsSync(zshrc) ? fs.readFileSync(zshrc, 'utf8') : '';
  const after = withBlock(before, file);
  if (after !== before) {
    if (before) fs.copyFileSync(zshrc, `${zshrc}.sandgate-bak`);
    fs.writeFileSync(zshrc, after);
  }
  const names = store.data.apps.filter((a) => a.alias).map((a) => a.alias);
  return { file, zshrc, changed: after !== before, shadowed: shadowedAliases(before, names) };
}

export function uninstallZshrc(zshrc = path.join(os.homedir(), '.zshrc')) {
  if (!fs.existsSync(zshrc)) return false;
  const before = fs.readFileSync(zshrc, 'utf8');
  const after = withoutBlock(before);
  if (after === before) return false;
  fs.copyFileSync(zshrc, `${zshrc}.sandgate-bak`);
  fs.writeFileSync(zshrc, after);
  return true;
}

/** Exact ID or name first, then a name containing the text, which must be unique. */
export function findInstance(apps, text) {
  const exact = apps.find((a) => a.id === text || a.name === text);
  if (exact) return exact;
  const partial = apps.filter((a) => a.name.includes(text));
  if (partial.length === 1) return partial[0];
  throw new Error(partial.length ? `「${text}」对应多个实例：${partial.map((a) => a.name).join('、')}` : `没有名称包含「${text}」的实例`);
}

export function api(store, method, pathname, body) {
  const data = body === undefined ? '' : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: store.data.uiPort,
      method,
      path: pathname,
      timeout: 10000,
      headers: { Authorization: `Bearer ${store.token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let json = {};
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* not JSON */ }
        if (res.statusCode === 200) resolve(json);
        else reject(new Error(json.error || `HTTP ${res.statusCode}`));
      });
    });
    req.on('timeout', () => req.destroy(new Error('SandGate 没有响应')));
    req.on('error', (e) => reject(e.code === 'ECONNREFUSED' ? new Error('SandGate 没有在运行，实例不能启动。先启动 SandGate（node bin/sandgate.js service status 查看）。') : e));
    req.end(data);
  });
}

/**
 * The command a terminal runs in place of itself, as shell words. The environment is the
 * terminal's, changed the way a started instance's is, and nothing else is inherited.
 */
export function launchCommand(launch, env) {
  const { app, command, sandboxExec, profile, home, port } = launch;
  const vars = { port, home: app.isolateHome ? home : env.HOME, data: home };
  const args = instanceArgs(app).map((a) => expandVars(a, vars));
  const childEnv = buildEnv(app, port, env, home);
  delete childEnv.SANDGATE_NODE;
  const words = [
    '/usr/bin/env', '-i', ...Object.entries(childEnv).map(([k, v]) => `${k}=${v}`),
    ...(sandboxExec ? [sandboxExec, '-p', profile] : []),
    command, ...args,
  ];
  return words.map(shellQuote).join(' ');
}

export async function launchSpec(store, name, { cwd = process.cwd(), env = process.env } = {}) {
  const launch = await api(store, 'POST', '/api/terminal', { name, cwd });
  const warnings = [];
  for (const note of launch.linkNotes ?? []) warnings.push(`SandGate：${note}`);
  if (!launch.gateOpen) warnings.push(`SandGate：「${launch.app.name}」的闸门现在是关的，程序会启动，但闸门打开前连不上网。`);
  if (launch.app.isolateHome && !launch.app.homeVisible && !launch.cwdShared) {
    warnings.push(`SandGate：「${launch.app.name}」看不到你的用户目录，当前目录 ${cwd} 也没有放行。`);
  }
  return { command: launchCommand(launch, env), warnings };
}
