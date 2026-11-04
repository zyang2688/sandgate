import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

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

// System daemons that do network I/O on a caller's behalf, outside its sandbox.
const BROKER_SERVICES = ['com.apple.nsurlsessiond', 'com.apple.coreservices.launchservicesd'];
const MDNS_SOCKET = '/private/var/run/mDNSResponder';

/**
 * Builds the Seatbelt profile. SBPL is last-match-wins, so the order below is
 * load-bearing: broad denies first, narrow allows next, protected paths last.
 */
export function buildProfile(app, { port, sandgateDir, instancesDir = '', instanceHome = '', controllerSocket = '', home = os.homedir() }) {
  const lines = ['(version 1)', '(allow default)', '', ';; network: deny everything, including DNS', '(deny network*)'];

  if (app.network === 'gate') {
    if (!Number.isInteger(port)) throw new Error('gate mode needs a port');
    lines.push(`(allow network-outbound (remote ip ${sbString(`localhost:${port}`)}))`);
  }

  if (app.allowUnixSockets) {
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
    if (app.isolateHome && instanceHome) lines.push(`(allow file-read* file-write* (subpath ${sbString(canonical(instanceHome))}))`);
  }

  const protectedPaths = [...defaultProtected(sandgateDir, home), ...(app.protected ?? [])];
  lines.push('', ';; protected paths always win');
  for (const p of protectedPaths) lines.push(`(deny file-read* file-write* (subpath ${sbString(canonical(p))}))`);

  return lines.join('\n') + '\n';
}

export const expandVars = (s, { port, home }) => s.replaceAll('{port}', String(port ?? '')).replaceAll('{home}', home ?? '');

/**
 * Child environment. NO_PROXY is removed so nothing skips the gate. An isolated
 * instance also gets its own HOME; CFFIXED_USER_HOME is the Cocoa equivalent.
 */
export function buildEnv(app, port, base = process.env, instanceHome = '') {
  const env = { ...base };
  for (const k of Object.keys(env)) {
    if (/^(https?_proxy|all_proxy|ftp_proxy|no_proxy)$/i.test(k)) delete env[k];
  }
  if (app.network === 'gate') {
    const http = `http://127.0.0.1:${port}`;
    const socks = `socks5h://127.0.0.1:${port}`;
    Object.assign(env, { HTTP_PROXY: http, HTTPS_PROXY: http, ALL_PROXY: socks, http_proxy: http, https_proxy: http, all_proxy: socks });
  }
  const home = app.isolateHome && instanceHome ? instanceHome : '';
  if (home) Object.assign(env, { HOME: home, CFFIXED_USER_HOME: home });
  for (const [k, v] of Object.entries(app.env ?? {})) env[k] = expandVars(v, { port, home: home || base.HOME });
  return env;
}
