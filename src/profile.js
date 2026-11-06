import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Escapes a value for an SBPL string literal; a stray quote would inject rules. */
export function sbString(s) {
  if (typeof s !== 'string' || /[\x00-\x1f\x7f]/.test(s)) throw new Error(`invalid SBPL string: ${JSON.stringify(s)}`);
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Seatbelt matches resolved paths (/tmp is really /private/tmp). */
export function canonical(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    if (p === '/tmp' || p.startsWith('/tmp/')) return `/private${p}`;
    if (p === '/var' || p.startsWith('/var/')) return `/private${p}`;
    return p;
  }
}

export function defaultProtected(sandgateDir, home = os.homedir()) {
  return [
    sandgateDir, // holds the UI token and the profiles themselves
    path.join(home, '.ssh'),
    path.join(home, '.aws'),
    path.join(home, '.gnupg'),
    path.join(home, 'Library/Keychains'),
    path.join(home, 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'),
  ];
}

const isWithin = (parent, p) => p === parent || p.startsWith(`${parent}/`);

/** Directories from `root` down to `p`'s parent; empty when `p` is outside `root`. */
function parentsWithin(root, p) {
  if (!isWithin(root, p)) return [];
  const out = [];
  for (let d = path.dirname(p); isWithin(root, d); d = path.dirname(d)) out.push(d);
  return out;
}

// System daemons that do network I/O on a caller's behalf, outside its sandbox.
const BROKER_SERVICES = ['com.apple.nsurlsessiond', 'com.apple.coreservices.launchservicesd'];
const MDNS_SOCKET = '/private/var/run/mDNSResponder';
export const KEYCHAIN_TOOL = '/usr/bin/security';
/** Put first in a clone's PATH: a `security` that finds nothing, so logins go to files. */
export const NO_KEYCHAIN_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '../libexec/no-keychain');

/**
 * Builds the Seatbelt profile. SBPL is last-match-wins, so the order below is
 * load-bearing: broad denies first, narrow allows next, protected paths last.
 */
export function buildProfile(app, { port, sandgateDir, instancesDir = '', instanceHome = '', controllerSocket = '', home = os.homedir(), tempDir = os.tmpdir() }) {
  // Instances following rules reach the network through TUN like any program, so git and
  // ssh keep working. Their exit is chosen by Clash, not enforced here.
  const pinned = !['open', 'rules'].includes(app.network);
  const lines = ['(version 1)', '(allow default)'];
  if (pinned) lines.push('', ';; network: deny everything, including DNS', '(deny network*)');

  if (app.network === 'gate') {
    if (!Number.isInteger(port)) throw new Error('gate mode needs a port');
    lines.push(`(allow network-outbound (remote ip ${sbString(`localhost:${port}`)}))`);
  }

  if (!pinned && controllerSocket) {
    lines.push('', ';; the Clash controller stays blocked', `(deny network* (literal ${sbString(canonical(controllerSocket))}))`);
  }

  if (pinned && app.allowUnixSockets) {
    lines.push('', ';; unix sockets for local IPC; DNS and the Clash controller stay blocked');
    lines.push('(allow network* (local unix-socket))', '(allow network-outbound (remote unix-socket))');
    lines.push(`(deny network-outbound (literal ${sbString(MDNS_SOCKET)}))`);
    if (controllerSocket) lines.push(`(deny network* (literal ${sbString(canonical(controllerSocket))}))`);
  }

  if (app.blockBrokers) {
    lines.push('', ';; daemons that would make requests from outside this sandbox');
    for (const svc of BROKER_SERVICES) lines.push(`(deny mach-lookup (global-name ${sbString(svc)}))`);
    lines.push('(deny appleevent-send)');
  }

  if (app.restrictWrites) {
    const dirs = ['/private/tmp', '/private/var/folders', '/dev', ...(app.cwd ? [app.cwd] : []), ...(app.writable ?? [])];
    lines.push('', ';; writes only to listed paths', '(deny file-write*)');
    for (const d of dirs) lines.push(`(allow file-write* (subpath ${sbString(canonical(d))}))`);
  }

  if (instancesDir) {
    lines.push('', ';; instances cannot see each other\'s data');
    lines.push(`(deny file-read* file-write* (subpath ${sbString(canonical(instancesDir))}))`);
  }

  const clone = app.isolateHome && instanceHome;
  const keychainDir = path.join(home, 'Library/Keychains');
  if (app.allowKeychain) {
    // Chosen per instance, for git, gh and the like. Everything the keychain hands out
    // without asking is then readable here, as it is outside any sandbox.
    lines.push('', ';; the keychain is allowed for this instance');
  } else {
    // By default no sandboxed instance can use the keychain: its folder is protected. So the
    // real tool cannot run either; the stand-in first in PATH answers "not found", the one
    // answer that makes Claude Code keep its login in a file instead. A tool that runs but
    // cannot read the keychain, or cannot run at all, makes it give up saving.
    lines.push('', ';; the keychain tool cannot run; a stand-in that finds nothing is used instead');
    lines.push(`(deny process-exec (literal ${sbString(KEYCHAIN_TOOL)}))`);
  }
  if (clone && !app.homeVisible) {
    lines.push('', ';; clone: the real home folder is invisible, and the system temp directory cannot be listed');
    lines.push(`(deny file-read* file-write* (subpath ${sbString(canonical(home))}))`);
    // Chrome ignores TMPDIR for its singleton socket and exits with code 21 if the system
    // temp directory is closed, so only its listing is hidden. A clone can still open a
    // file there if it knows the name. Without TMPDIR, os.tmpdir() is the shared /tmp.
    if (canonical(tempDir) !== '/private/tmp') lines.push(`(deny file-read-data (literal ${sbString(canonical(tempDir))}))`);
  }

  // Paths this instance keeps. realpath() must stat each parent, or Chrome reports its
  // data directory as unusable, so parents get metadata access and nothing more.
  const readWrite = instanceHome ? [instanceHome] : [];
  const readOnly = [];
  if (clone) {
    readWrite.push(...(app.cwd ? [app.cwd] : []), ...(app.shared ?? []), ...(app.restrictWrites ? app.writable ?? [] : []));
    readOnly.push(app.command, NO_KEYCHAIN_DIR);
    if (app.allowKeychain) readWrite.push(keychainDir);
  }
  const kept = [...readWrite, ...readOnly].map(canonical);
  const parents = new Set(kept.flatMap((p) => parentsWithin(canonical(home), p)));
  if (instancesDir && instanceHome) parents.add(canonical(instancesDir));
  if (parents.size || kept.length) lines.push('', ';; what this instance keeps');
  for (const p of parents) lines.push(`(allow file-read-metadata (literal ${sbString(p)}))`);
  for (const p of readWrite) lines.push(`(allow file-read* file-write* (subpath ${sbString(canonical(p))}))`);
  for (const p of readOnly) {
    if (isWithin(canonical(home), canonical(p))) lines.push(`(allow file-read* (subpath ${sbString(canonical(p))}))`);
  }

  const protectedPaths = [...defaultProtected(sandgateDir, home), ...(app.protected ?? [])]
    .filter((p) => !app.allowKeychain || p !== keychainDir);
  lines.push('', ';; protected paths always win');
  for (const p of protectedPaths) lines.push(`(deny file-read* file-write* (subpath ${sbString(canonical(p))}))`);

  return lines.join('\n') + '\n';
}

export const expandVars = (s, { port, home, data }) => s
  .replaceAll('{port}', String(port ?? ''))
  .replaceAll('{home}', home ?? '')
  .replaceAll('{data}', data ?? '');

/**
 * Child environment. NO_PROXY is removed so nothing skips the gate. A clone also gets
 * its own HOME and temp directory; CFFIXED_USER_HOME is the Cocoa equivalent of HOME.
 */
export function buildEnv(app, port, base = process.env, instanceHome = '') {
  const env = { ...base };
  for (const k of Object.keys(env)) {
    if (/^(https?_proxy|all_proxy|ftp_proxy|no_proxy)$/i.test(k)) delete env[k];
  }
  if (['gate', 'rules'].includes(app.network)) {
    const http = `http://127.0.0.1:${port}`;
    const socks = `socks5h://127.0.0.1:${port}`;
    Object.assign(env, { HTTP_PROXY: http, HTTPS_PROXY: http, ALL_PROXY: socks, http_proxy: http, https_proxy: http, all_proxy: socks });
  }
  const home = app.isolateHome && instanceHome ? instanceHome : '';
  if (home) Object.assign(env, { HOME: home, CFFIXED_USER_HOME: home, TMPDIR: path.join(home, 'tmp') });
  if (!app.unsandboxed && !app.allowKeychain) env.PATH = [NO_KEYCHAIN_DIR, ...String(base.PATH ?? '/usr/bin:/bin:/usr/sbin:/sbin').split(':').filter((d) => d && d !== NO_KEYCHAIN_DIR)].join(':');
  // A clone that sees your files works on your repositories, so git keeps your identity.
  if (home && app.homeVisible) env.GIT_CONFIG_GLOBAL ??= path.join(os.homedir(), '.gitconfig');
  if (app.timezone) env.TZ = app.timezone; // set before app.env, so an explicit TZ there still wins
  for (const [k, v] of Object.entries(app.env ?? {})) env[k] = expandVars(v, { port, home: home || base.HOME, data: instanceHome });
  return env;
}
