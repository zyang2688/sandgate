import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { detectVerge, listenerSnippet, ClashClient } from '../src/clash.js';
import { Store, ValidationError, expandPath, mergeGateSettings, validateApp, DEFAULT_SETTINGS } from '../src/config.js';
import { Sandgate } from '../src/daemon.js';
import { GateManager, GateMonitor, decide, verifyPin } from '../src/gate.js';
import { GatePort } from '../src/gateport.js';
import { ConnectionGuard, findViolations, rulesFingerprint } from '../src/guard.js';
import { PfPlanner, parseCidrList, parseClashConfig, resolveTargets } from '../src/pfplan.js';
import { buildEnv, buildProfile, expandVars, sbString } from '../src/profile.js';
import { ServiceManager, buildPlist, startMessage } from '../src/service.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sandgate-test-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));

function roundTrip(port, payload = 'ping') {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    let got = '';
    s.on('connect', () => s.write(payload));
    s.on('data', (d) => { got += d; s.destroy(); });
    s.on('error', () => resolve(null));
    s.on('close', () => resolve(got || null));
  });
}

describe('gate policy', () => {
  const base = { locked: false, stableMs: 1000 };

  test('stays closed until the stable window has elapsed', () => {
    let s = decide({ open: false, okSince: null }, { ...base, allOk: true, now: 0 });
    assert.equal(s.open, false);
    s = decide(s, { ...base, allOk: true, now: 999 });
    assert.equal(s.open, false);
    s = decide(s, { ...base, allOk: true, now: 1000 });
    assert.equal(s.open, true);
  });

  test('a single failure closes and restarts the window', () => {
    let s = { open: true, okSince: 0 };
    s = decide(s, { ...base, allOk: false, now: 5000 });
    assert.deepEqual(s, { open: false, okSince: null });
    s = decide(s, { ...base, allOk: true, now: 5001 });
    assert.equal(s.open, false);
  });

  test('lock beats healthy checks', () => {
    assert.equal(decide({ open: true, okSince: 0 }, { ...base, allOk: true, locked: true, now: 9e9 }).open, false);
  });
});

describe('GateMonitor', () => {
  const check = (id, run, intervalMs = 1000) => ({ id, label: id, intervalMs, timeoutMs: 50, run });

  test('starts closed, opens after stable, closes on failure and needs a fresh pass from every check', async () => {
    let healthy = true;
    let otherRuns = 0;
    const mon = new GateMonitor({
      stableMs: 30,
      tickMs: 5,
      checks: [
        check('a', async () => { if (!healthy) throw new Error('down'); return 'up'; }, 10),
        check('b', async () => { otherRuns++; return 'up'; }, 100000),
      ],
    });
    assert.equal(mon.open, false);
    let closed = 0;
    mon.on('close', () => closed++);
    mon.start();
    await sleep(100);
    assert.equal(mon.open, true);
    const runsBefore = otherRuns;
    healthy = false;
    await sleep(40);
    assert.equal(mon.open, false);
    assert.equal(closed, 1);
    assert.ok(otherRuns > runsBefore, 'unrelated check must re-run after a close');
    mon.stop();
  });

  test('a hung check closes the gate through staleness, not just timeout', async () => {
    let t = 0;
    let hang = false;
    const mon = new GateMonitor({
      stableMs: 0,
      now: () => t,
      checks: [check('a', () => (hang ? new Promise(() => {}) : Promise.resolve('ok')), 100)],
    });
    mon.tick();
    await sleep(5);
    mon.evaluate();
    assert.equal(mon.open, true);
    hang = true;
    t += 251; // older than interval*2 + timeout
    mon.evaluate();
    assert.equal(mon.open, false);
  });

  test('never opens with zero checks', () => {
    const mon = new GateMonitor({ stableMs: 0, checks: [] });
    mon.evaluate();
    assert.equal(mon.open, false);
  });
});

describe('GatePort', () => {
  let upstream;
  let upstreamPort;
  const sockets = new Set();
  before(async () => {
    upstream = net.createServer((s) => {
      sockets.add(s);
      s.on('error', () => {});
      s.on('data', (d) => s.write(d));
    });
    upstreamPort = await listen(upstream);
  });
  after(() => { for (const s of sockets) s.destroy(); upstream.close(); });

  async function makePort(isOpen, up = () => upstreamPort) {
    const probe = net.createServer();
    const port = await listen(probe);
    await new Promise((r) => probe.close(r));
    const gp = new GatePort({ port, isOpen, upstreamPort: up });
    await gp.listen();
    return gp;
  }

  test('forwards only while open and counts bytes', async () => {
    let open = true;
    const gp = await makePort(() => open);
    assert.equal(await roundTrip(gp.port, 'hello'), 'hello');
    assert.equal(gp.stats.up, 5);
    open = false;
    assert.equal(await roundTrip(gp.port), null);
    assert.equal(gp.stats.refused, 1);
    await gp.close();
  });

  test('dropAll kills live connections immediately', async () => {
    const gp = await makePort(() => true);
    const s = net.connect({ host: '127.0.0.1', port: gp.port });
    s.on('error', () => {});
    await new Promise((r) => s.once('connect', r));
    s.write('x');
    await new Promise((r) => s.once('data', r));
    assert.equal(gp.active, 1);
    const closed = new Promise((r) => s.once('close', r));
    gp.dropAll();
    await closed;
    assert.equal(gp.active, 0);
    await gp.close();
  });

  test('dead upstream means a dropped client, with no other route', async () => {
    const dead = net.createServer();
    const deadPort = await listen(dead);
    await new Promise((r) => dead.close(r));
    const gp = await makePort(() => true, () => deadPort);
    assert.equal(await roundTrip(gp.port), null);
    await gp.close();
  });
});

describe('Seatbelt profile', () => {
  const app = (over = {}) => validateApp({ name: 'x', command: '/bin/ls', node: 'n', ...over });
  const opts = { port: 17900, sandgateDir: '/Users/t/.sandgate', home: '/Users/t' };

  test('gate mode allows only its own port and no DNS', () => {
    const p = buildProfile(app(), opts);
    assert.match(p, /\(deny network\*\)/);
    assert.match(p, /\(allow network-outbound \(remote ip "localhost:17900"\)\)/);
    assert.equal((p.match(/allow network/g) ?? []).length, 1);
    assert.doesNotMatch(p, /allow[^\n]*mDNSResponder/);
  });

  test('none mode has no network allow at all', () => {
    assert.doesNotMatch(buildProfile(app({ network: 'none' }), opts), /allow network/);
  });

  test('a path cannot break out of its string literal', () => {
    assert.equal(sbString('a"b\\c'), '"a\\"b\\\\c"');
    assert.throws(() => sbString('a\nb'));
    const p = buildProfile(app({ protected: ['/tmp/x") (allow network*) ("'] }), opts);
    assert.doesNotMatch(p, /\(allow network\*\) \("\)/);
    assert.match(p, /x\\"\) \(allow network\*\) \(\\"/);
  });

  test('unix sockets stay closed to DNS and the controller, and those denies come last', () => {
    const p = buildProfile(app({ allowUnixSockets: true }), { ...opts, controllerSocket: '/Users/t/c.sock' });
    const allowAt = p.indexOf('(allow network-outbound (remote unix-socket))');
    assert.ok(allowAt > 0);
    assert.ok(p.indexOf('mDNSResponder') > allowAt);
    assert.ok(p.indexOf('c.sock') > allowAt);
  });

  test('protected paths come after the write allows, so they win', () => {
    const p = buildProfile(app({ restrictWrites: true, writable: ['/Users/t'] }), opts);
    assert.ok(p.indexOf('.sandgate"') > p.indexOf('(allow file-write* (subpath "/Users/t"))'));
    assert.match(p, /\.ssh/);
  });

  test('NO_PROXY is stripped and proxy variables point at the gate', () => {
    const env = buildEnv(app(), 17900, { NO_PROXY: '*', no_proxy: '*', HTTPS_PROXY: 'http://evil', PATH: '/bin' });
    assert.equal(env.NO_PROXY, undefined);
    assert.equal(env.no_proxy, undefined);
    assert.equal(env.HTTPS_PROXY, 'http://127.0.0.1:17900');
    assert.equal(env.ALL_PROXY, 'socks5h://127.0.0.1:17900');
    assert.equal(env.PATH, '/bin');
  });
});

describe('validation', () => {
  test('rejects bad input', () => {
    assert.throws(() => validateApp({ name: '', command: '/bin/ls' }), ValidationError);
    assert.throws(() => validateApp({ name: 'a', command: '' }), ValidationError);
    assert.throws(() => validateApp({ name: 'a', command: '/bin/ls', env: { 'A B': 'x' } }), ValidationError);
    assert.throws(() => validateApp({ name: 'a', command: '/bin/ls', network: 'open' }), ValidationError);
    assert.throws(() => expandPath('relative/path'), ValidationError);
    assert.throws(() => expandPath('/a\nb'), ValidationError);
    assert.throws(() => validateApp({ name: 'a', command: '/bin/ls' }), /选择节点/);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { probeInterface: 'en0; rm -rf /' }), ValidationError);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { pfExtra: ['0.0.0.0/0'] }), ValidationError);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { pfExtra: ['8.0.0.0/7'] }), ValidationError);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { pfExtra: ['example.com'] }), ValidationError);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { pfCnList: '../../etc/passwd' }), ValidationError);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { pfTargets: 'US' }), ValidationError);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { controller: { port: 70000 } }), ValidationError);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { controller: { host: 'evil.example' } }), ValidationError);
    assert.throws(() => mergeGateSettings(DEFAULT_SETTINGS.gate, { probeUrl: 'file:///etc/passwd' }), ValidationError);
  });

  test('settings patch without a secret keeps the stored one', () => {
    const cur = { ...DEFAULT_SETTINGS.gate, controller: { ...DEFAULT_SETTINGS.gate.controller, secret: 's3' } };
    assert.equal(mergeGateSettings(cur, { controller: { port: 1234 } }).controller.secret, 's3');
  });
});

describe('Clash integration (fake mihomo)', () => {
  function fakeMihomo({ via }) {
    const live = new Map();
    const upstream = net.createServer((s) => {
      s.on('error', () => {});
      s.once('data', () => {
        live.set(s.remotePort, s);
        s.on('close', () => live.delete(s.remotePort));
        s.write('HTTP/1.1 200 Connection established\r\n\r\n');
      });
    });
    const controller = http.createServer((req, res) => {
      if (req.headers.authorization !== 'Bearer sekret') { res.writeHead(401); return res.end('{}'); }
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/connections') {
        return res.end(JSON.stringify({ connections: [...live.keys()].map((p) => ({ metadata: { sourcePort: String(p) }, chains: [via] })) }));
      }
      if (req.url.startsWith('/proxies/node-a/delay')) return res.end(JSON.stringify({ delay: 42 }));
      if (req.url === '/proxies') {
        return res.end(JSON.stringify({ proxies: {
          DIRECT: { type: 'Direct' },
          'node-a': { type: 'Vless', server: 'secret.example' },
          G: { type: 'Selector', now: 'node-a', all: ['node-a'] },
        } }));
      }
      res.writeHead(404);
      res.end('{}');
    });
    return { upstream, controller };
  }

  test('verifyPin accepts the pinned node and rejects anything else', async () => {
    for (const [via, ok] of [['node-a', true], ['DIRECT', false], ['node-b', false]]) {
      const { upstream, controller } = fakeMihomo({ via });
      const upstreamPort = await listen(upstream);
      const port = await listen(controller);
      const client = new ClashClient({ type: 'tcp', host: '127.0.0.1', port, secret: 'sekret' });
      const run = verifyPin({ upstreamPort, probeUrl: 'http://cp.example/x', node: 'node-a', client });
      if (ok) assert.match(await run, /node-a/);
      else await assert.rejects(run, /不是/);
      upstream.close();
      controller.close();
    }
  });

  test('proxies() omits builtins and server addresses; a bad secret is reported', async () => {
    const { controller } = fakeMihomo({ via: 'x' });
    const port = await listen(controller);
    const good = new ClashClient({ type: 'tcp', host: '127.0.0.1', port, secret: 'sekret' });
    const r = await good.proxies();
    assert.deepEqual(r.nodes, [{ name: 'node-a', type: 'Vless' }]);
    assert.ok(!JSON.stringify(r).includes('secret.example'));
    await assert.rejects(new ClashClient({ type: 'tcp', host: '127.0.0.1', port, secret: 'no' }).version(), /密钥/);
    controller.close();
  });

  test('detectVerge parses quoted values and falls back to the unix socket', () => {
    const home = tmp();
    const dir = path.join(home, 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'clash-verge.yaml'), "mixed-port: 7890\nexternal-controller: ''\nexternal-controller-unix: /tmp/m.sock\nsecret: 'abc'\ntun:\n  secret: nested\n");
    const d = detectVerge(home);
    assert.equal(d.controller.type, 'unix');
    assert.equal(d.controller.secret, 'abc');
    assert.equal(d.mixedPort, 7890);
    fs.writeFileSync(path.join(dir, 'clash-verge.yaml'), 'external-controller: 127.0.0.1:9097\nsecret: x\n');
    assert.equal(detectVerge(home).controller.port, 9097);
    assert.equal(detectVerge(tmp()), null);
  });

  test('listener snippet quotes node names safely', () => {
    const s = listenerSnippet({ '日本 "01"': 17890, 美国: 17891 });
    assert.match(s, /proxy: "日本 \\"01\\""/);
    assert.match(s, /name: sandgate-17891/);
    assert.match(s, /port: 17891\n    proxy: "美国"/);
  });
});

describe('Web API security', () => {
  let app;
  let port;
  let cookie;

  const call = (pathname, { method = 'GET', body, headers = {} } = {}) => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1', port, path: pathname, method,
      headers: { ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}), ...headers },
    }, (res) => {
      let t = '';
      res.on('data', (d) => { t += d; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(t); } catch { /* static page */ }
        resolve({ status: res.statusCode, headers: res.headers, text: t, json });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
  const authed = (p, o = {}) => call(p, { ...o, headers: { Cookie: cookie, ...(o.headers ?? {}) } });

  before(async () => {
    app = new Sandgate({ dir: tmp(), port: 0, background: false });
    await app.start();
    port = app.port;
  });
  after(() => app.stop());

  test('binds to loopback only', () => {
    assert.equal(app.server.address().address, '127.0.0.1');
  });

  test('token and config files are private', () => {
    assert.equal(fs.statSync(app.store.tokenPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(app.store.dir).mode & 0o777, 0o700);
  });

  test('API requires a session; a wrong token is refused', async () => {
    assert.equal((await call('/api/state')).status, 401);
    assert.equal((await call('/api/login', { method: 'POST', body: { token: 'nope' } })).status, 401);
  });

  test('login sets an HttpOnly, SameSite=Strict cookie', async () => {
    const r = await call('/api/login', { method: 'POST', body: { token: app.store.token } });
    assert.equal(r.status, 200);
    const c = r.headers['set-cookie'][0];
    assert.match(c, /HttpOnly/);
    assert.match(c, /SameSite=Strict/);
    cookie = c.split(';')[0];
    assert.equal((await authed('/api/state')).status, 200);
  });

  test('DNS rebinding: a foreign Host is refused even with a session', async () => {
    assert.equal((await authed('/api/state', { headers: { Host: 'evil.example' } })).status, 403);
  });

  test('CSRF: foreign Origin and non-JSON writes are refused', async () => {
    const body = { name: 'x', command: '/bin/ls' };
    assert.equal((await authed('/api/apps', { method: 'POST', body, headers: { Origin: 'http://evil.example' } })).status, 403);
    assert.equal((await authed('/api/apps', { method: 'POST', body, headers: { 'Content-Type': 'text/plain' } })).status, 415);
  });

  test('settings never expose the Clash secret', async () => {
    const r = await authed('/api/settings', { method: 'PUT', body: { gate: { controller: { secret: 'topsecret' } } } });
    assert.equal(r.status, 200);
    assert.ok(!r.text.includes('topsecret'));
    assert.equal(r.json.gate.controller.hasSecret, true);
    assert.ok(!(await authed('/api/settings')).text.includes('topsecret'));
    assert.equal(app.store.data.gate.controller.secret, 'topsecret');
  });

  test('static path traversal is refused, and pages carry a CSP', async () => {
    assert.equal((await call('/../src/daemon.js')).status, 404);
    assert.equal((await call('/..%2fpackage.json')).status, 404);
    const page = await call('/');
    assert.equal(page.status, 200);
    assert.match(page.headers['content-security-policy'], /default-src 'none'/);
  });

  test('app CRUD gives distinct ports, and validation errors are 400', async () => {
    const a = await authed('/api/apps', { method: 'POST', body: { name: 'a', command: '/bin/ls', node: 'n1' } });
    const b = await authed('/api/apps', { method: 'POST', body: { name: 'b', command: '/bin/ls', node: 'n1' } });
    assert.equal(a.status, 200);
    assert.notEqual(a.json.port, b.json.port);
    assert.equal((await authed('/api/apps', { method: 'POST', body: { name: '', command: '' } })).status, 400);
    const prof = await authed(`/api/apps/${a.json.id}/profile`);
    assert.ok(prof.json.text.includes(`localhost:${a.json.port}`));
    assert.equal((await authed(`/api/apps/${a.json.id}`, { method: 'DELETE', body: {} })).status, 200);
    assert.equal((await authed(`/api/apps/${a.json.id}/profile`)).status, 404);
  });

  test('same program, different nodes: each instance gets its own port and listener', async () => {
    const body = (name, node) => ({ method: 'POST', body: { name, command: '/bin/ls', node } });
    const a = (await authed('/api/apps', body('i1', 'jp'))).json;
    const b = (await authed('/api/apps', body('i2', 'us'))).json;
    const c = (await authed('/api/apps', body('i3', 'jp'))).json;
    assert.equal(new Set([a.port, b.port, c.port]).size, 3);
    const { listeners } = app.store.data.gate;
    assert.notEqual(listeners.jp, listeners.us);
    const used = [a.port, b.port, c.port];
    assert.ok(!used.includes(listeners.jp) && !used.includes(listeners.us), 'listener and gate ports must not collide');
    const { json } = await authed('/api/settings');
    assert.match(json.listenerSnippet, /proxy: "jp"/);
    assert.match(json.listenerSnippet, /proxy: "us"/);
    assert.equal(json.listenerSnippet.match(/proxy: "jp"/g).length, 1, 'instances on one node share a listener');
  });

  test('changing node on a stopped instance moves it; deleting the last user drops the gate', async () => {
    const a = (await authed('/api/apps', { method: 'POST', body: { name: 'mv', command: '/bin/ls', node: 'old-node' } })).json;
    assert.ok((await authed('/api/state')).json.gates.nodes['old-node']);
    const put = await authed(`/api/apps/${a.id}`, { method: 'PUT', body: { name: 'mv', command: '/bin/ls', node: 'new-node' } });
    assert.equal(put.json.node, 'new-node');
    assert.equal(put.json.port, a.port);
    const { nodes } = (await authed('/api/state')).json.gates;
    assert.ok(nodes['new-node'] && !nodes['old-node']);
    await authed(`/api/apps/${a.id}`, { method: 'DELETE', body: {} });
    assert.ok(!(await authed('/api/state')).json.gates.nodes['new-node']);
  });

  test('an unreachable Clash controller is a 502, not a server error', async () => {
    const dead = net.createServer();
    const deadPort = await listen(dead);
    await new Promise((r) => dead.close(r));
    const old = { ...app.client.cfg };
    app.client.cfg = { ...old, type: 'tcp', host: '127.0.0.1', port: deadPort };
    const r = await authed('/api/clash/proxies');
    app.client.cfg = old;
    assert.equal(r.status, 502);
    assert.ok(r.json.error);
  });

  test('every gate starts closed', async () => {
    const { gates } = (await authed('/api/state')).json;
    assert.ok(Object.keys(gates.nodes).length > 0);
    for (const g of Object.values(gates.nodes)) assert.equal(g.open, false);
  });

  test('clients cannot overwrite server-managed listeners', async () => {
    const before = { ...app.store.data.gate.listeners };
    await authed('/api/settings', { method: 'PUT', body: { gate: { listeners: { jp: 1 }, rulesHash: 'x' } } });
    assert.deepEqual(app.store.data.gate.listeners, before);
    assert.notEqual(app.store.data.gate.rulesHash, 'x');
  });
});

describe('per-node gates', () => {
  const until = async (fn, ms = 4000) => {
    const start = Date.now();
    while (!fn() && Date.now() - start < ms) await sleep(20);
    return fn();
  };

  test('a dead node closes only its own gate', async (t) => {
    const down = new Set();
    const client = {
      delay: async (node) => { if (down.has(node)) throw new Error('down'); return { delay: 10 }; },
    };
    const settings = {
      ...structuredClone(DEFAULT_SETTINGS.gate), requireTun: false, requirePin: false, stableSec: 0.02, delayIntervalSec: 0.01, listeners: {},
    };
    const live = net.createServer((s) => s.on('error', () => {}));
    settings.listeners.a = await listen(live);
    settings.listeners.b = settings.listeners.a;
    const gates = new GateManager({ getSettings: () => settings, client });
    const closed = [];
    gates.on('close', (node) => closed.push(node));
    t.after(() => { gates.stop(); live.close(); });
    gates.sync(['a', 'b']);
    gates.start();
    assert.ok(await until(() => gates.isOpen('a') && gates.isOpen('b')), 'both gates should open');
    down.add('a');
    assert.ok(await until(() => !gates.isOpen('a')), 'gate a should close');
    assert.equal(gates.isOpen('b'), true);
    assert.deepEqual([...new Set(closed)], ['a']);
    gates.setLocked(true);
    assert.equal(gates.isOpen('b'), false);
  });
});

describe('connection guard', () => {
  const conn = (via, inboundName = '', id = via) => ({ id, chains: [via, 'Group'], metadata: { inboundName, host: 'h' } });
  const cfg = { defaultNode: 'main', listeners: { jp: 17890 } };
  const ids = (list) => list.map((c) => c.id);

  test('default traffic may use DIRECT or the default node only', () => {
    const v = findViolations([conn('DIRECT'), conn('main'), conn('REJECT'), conn('other')], cfg);
    assert.deepEqual(ids(v), ['other']);
  });

  test('a listener may only use its own node, and DIRECT is not allowed there', () => {
    const v = findViolations([
      conn('jp', 'sandgate-17890', 'good'),
      conn('main', 'sandgate-17890', 'wrong-node'),
      conn('DIRECT', 'sandgate-17890', 'direct'),
      conn('jp', 'sandgate-1', 'unknown-listener'),
    ], cfg);
    assert.deepEqual(ids(v), ['wrong-node', 'direct', 'unknown-listener']);
  });

  test('without a default node, default traffic is not policed but listeners still are', () => {
    const v = findViolations([conn('anything'), conn('x', 'sandgate-17890', 'bad')], { defaultNode: '', listeners: { jp: 17890 } });
    assert.deepEqual(ids(v), ['bad']);
  });

  test('kills violations, baselines rules once, and alerts without cutting on change', async () => {
    const killed = [];
    const rule = (proxy = 'DIRECT', over = {}) => ({ index: 0, type: 'Domain', payload: 'a.test', proxy, size: -1, extra: { disabled: false, hitCount: 0, missCount: 0, ...over } });
    let rules = { rules: [rule()] };
    const settings = { defaultNode: 'main', listeners: {}, rulesHash: '' };
    const guard = new ConnectionGuard({
      getSettings: () => settings,
      saveRulesHash: (h) => { settings.rulesHash = h; },
      client: {
        connections: async () => ({ connections: [conn('other', '', 'bad'), conn('DIRECT', '', 'ok')] }),
        closeConnection: async (id) => { killed.push(id); },
        rules: async () => rules,
      },
    });
    await guard.tick();
    assert.deepEqual(killed, ['bad']);
    assert.equal(guard.status.killed, 1);
    assert.equal(guard.status.rulesChanged, false);
    assert.ok(settings.rulesHash);
    rules = { rules: [rule('DIRECT', { hitCount: 99, missCount: 500, hitAt: 'later' })] };
    await guard.tick();
    assert.equal(guard.status.rulesChanged, false, 'traffic counters must not look like a rule change');
    rules = { rules: [rule('🌐 Proxy')] };
    await guard.tick();
    assert.equal(guard.status.rulesChanged, true);
    assert.ok(!killed.includes('ok'), 'a rule change must not cut direct traffic');
    guard.acceptRules();
    await guard.tick();
    assert.equal(guard.status.rulesChanged, false);
  });

  test('rule order and the disabled switch count as changes', () => {
    const r = (payload, disabled = false) => ({ type: 'Domain', payload, proxy: 'DIRECT', extra: { disabled } });
    const base = rulesFingerprint({ rules: [r('a'), r('b')] });
    assert.notEqual(base, rulesFingerprint({ rules: [r('b'), r('a')] }));
    assert.notEqual(base, rulesFingerprint({ rules: [r('a', true), r('b')] }));
    assert.equal(base, rulesFingerprint({ rules: [r('a'), r('b')] }));
  });

  test('a baseline in the old format is replaced without an alert', async () => {
    const settings = { defaultNode: '', listeners: {}, rulesHash: 'a'.repeat(64) };
    const guard = new ConnectionGuard({
      getSettings: () => settings,
      saveRulesHash: (h) => { settings.rulesHash = h; },
      client: { connections: async () => ({ connections: [] }), rules: async () => ({ rules: [] }) },
    });
    await guard.tick();
    assert.equal(guard.status.rulesChanged, false);
    assert.ok(settings.rulesHash.startsWith('v2:'));
  });

  test('an unreachable controller is reported, not fatal', async () => {
    const guard = new ConnectionGuard({
      getSettings: () => ({ defaultNode: 'm', listeners: {}, rulesHash: '' }),
      saveRulesHash: () => {},
      client: { connections: async () => { throw new Error('refused'); } },
    });
    await guard.tick();
    assert.equal(guard.status.active, false);
    assert.equal(guard.status.error, 'refused');
  });
});

describe('instance isolation', () => {
  const opts = { port: 17900, sandgateDir: '/Users/t/.sandgate', instancesDir: '/Users/t/.sandgate-instances', instanceHome: '/Users/t/.sandgate-instances/abc', home: '/Users/t' };
  const app = (over = {}) => validateApp({ name: 'x', command: '/bin/ls', node: 'n', ...over });

  test('an instance reaches its own data but no other instance', () => {
    const p = buildProfile(app(), opts);
    const deny = p.indexOf('(deny file-read* file-write* (subpath "/Users/t/.sandgate-instances"))');
    const allow = p.indexOf('(allow file-read* file-write* (subpath "/Users/t/.sandgate-instances/abc"))');
    assert.ok(deny > 0 && allow > deny, 'last match wins, so the allow must follow the deny');
    assert.ok(p.indexOf('(deny file-read* file-write* (subpath "/Users/t/.sandgate"))') > allow);
  });

  test('without isolation the instance sees no instance data at all', () => {
    assert.doesNotMatch(buildProfile(app({ isolateHome: false }), opts), /allow file-read\*/);
  });

  test('HOME moves only for an isolated instance; {home} and {port} expand', () => {
    const env = buildEnv(app(), 17900, { HOME: '/Users/t' }, '/inst/abc');
    assert.equal(env.HOME, '/inst/abc');
    assert.equal(env.CFFIXED_USER_HOME, '/inst/abc');
    assert.equal(buildEnv(app({ isolateHome: false }), 17900, { HOME: '/Users/t' }, '/inst/abc').HOME, '/Users/t');
    assert.equal(expandVars('--p={port} --d={home}/x', { port: 1, home: '/h' }), '--p=1 --d=/h/x');
  });

  test('instance homes live outside the protected data dir', () => {
    const store = new Store(path.join(tmp(), 'data'));
    assert.ok(!store.instanceHome('a').startsWith(`${store.dir}/`));
    assert.equal(fs.statSync(store.instancesDir).mode & 0o777, 0o700);
  });

  test('an older single-node config migrates', () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({
      gate: { node: 'old', upstreamPort: 17890, controller: { port: 9097 } },
      apps: [{ id: 'a', name: 'a', command: '/bin/ls', args: [], network: 'gate', port: 17900 }],
    }));
    const { data } = new Store(dir);
    assert.equal(data.gate.defaultNode, 'old');
    assert.equal(data.gate.listeners.old, 17890);
    assert.equal(data.apps[0].node, 'old');
    assert.equal(data.apps[0].isolateHome, false);
    assert.equal(data.gate.upstreamPort, undefined);
  });
});

describe('background service', () => {
  const entry = path.join(import.meta.dirname, '../bin/sandgate.js');

  function setup() {
    const home = tmp();
    const store = new Store(path.join(home, 'data'));
    const calls = [];
    let loaded = false;
    const run = async (args) => {
      calls.push(args);
      if (args[0] === 'bootout') loaded = false;
      if (args[0] === 'bootstrap') loaded = true;
      if (args[0] === 'print') {
        if (!loaded) throw new Error('not loaded');
        return { stdout: 'state = running\n\tpid = 4242\n' };
      }
      return { stdout: '' };
    };
    const service = new ServiceManager({ store, home, uid: 501, node: '/opt/node', entry: '/app/bin/sandgate.js', run, sandgateHome: undefined });
    return { service, calls, home };
  }

  test('the plist is valid, restarts only after a crash, and sets no proxy variables', () => {
    const p = buildPlist({ node: '/opt/node', entry: '/app/bin/sandgate.js', logFile: '/l/d.log', home: '/Users/t' });
    const file = path.join(tmp(), 'a.plist');
    fs.writeFileSync(file, p);
    execFileSync('/usr/bin/plutil', ['-lint', file], { stdio: 'pipe' });
    const json = JSON.parse(execFileSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', file], { encoding: 'utf8' }));
    assert.deepEqual(json.ProgramArguments, ['/opt/node', '/app/bin/sandgate.js']);
    assert.deepEqual(json.KeepAlive, { SuccessfulExit: false });
    assert.equal(json.RunAtLoad, true);
    assert.equal(json.WorkingDirectory, '/app');
    assert.ok(!Object.keys(json.EnvironmentVariables).some((k) => /proxy/i.test(k)));
    assert.ok(!p.includes('UserName') && !p.includes('/Library/LaunchDaemons'), 'must stay a per-user agent');
  });

  test('paths with XML characters cannot break the plist', () => {
    const file = path.join(tmp(), 'b.plist');
    fs.writeFileSync(file, buildPlist({ node: '/a&b/<node>', entry: '/c/bin/x.js', logFile: '/l', home: '/h' }));
    const json = JSON.parse(execFileSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', file], { encoding: 'utf8' }));
    assert.equal(json.ProgramArguments[0], '/a&b/<node>');
  });

  test('install replaces any old copy and loads into the user domain', async () => {
    const { service, calls, home } = setup();
    await service.install();
    assert.ok(service.plistPath.startsWith(path.join(home, 'Library/LaunchAgents')));
    assert.deepEqual(calls.map((c) => c[0]), ['bootout', 'print', 'bootstrap']);
    assert.deepEqual(calls.at(-1), ['bootstrap', 'gui/501', service.plistPath]);
    assert.ok(fs.existsSync(service.plistPath));
  });

  // Models launchd: after bootout the service stays visible for a while, and a
  // bootstrap in that window fails with exit code 5, as seen on a real reinstall.
  function reinstallSetup({ printsWhileStopping = 3, extraBusy = 0, stderr = 'Bootstrap failed: 5: Input/output error' } = {}) {
    const home = tmp();
    let phase = 'running';
    let stopping = printsWhileStopping;
    let busy = extraBusy;
    const calls = [];
    const slept = [];
    const run = async (args) => {
      calls.push(args[0]);
      const failBusy = () => Object.assign(new Error('Command failed'), { code: 5, stderr });
      if (args[0] === 'bootout') { phase = 'stopping'; return { stdout: '' }; }
      if (args[0] === 'print') {
        if (phase === 'gone') throw new Error('not found');
        if (phase === 'stopping' && --stopping <= 0) phase = 'gone';
        return { stdout: '' };
      }
      if (args[0] === 'bootstrap') {
        if (phase !== 'gone' || busy-- > 0) throw failBusy();
        phase = 'running';
      }
      return { stdout: '' };
    };
    const service = new ServiceManager({
      store: new Store(path.join(home, 'data')), home, uid: 501, node: '/n', entry: '/a/bin/s.js', run, sandgateHome: undefined,
      sleep: async (ms) => { slept.push(ms); },
    });
    return { service, calls, slept, phase: () => phase };
  }

  test('reinstalling over a running service waits for it to unload', async () => {
    const { service, calls, phase } = reinstallSetup();
    await service.install();
    assert.equal(phase(), 'running');
    assert.equal(calls.filter((c) => c === 'bootstrap').length, 1, 'must not bootstrap while the old service is going away');
    assert.ok(calls.indexOf('bootstrap') > calls.lastIndexOf('print'));
  });

  test('bootstrap retries a transient error 5', async () => {
    const { service, calls, phase } = reinstallSetup({ extraBusy: 2 });
    await service.install();
    assert.equal(phase(), 'running');
    assert.equal(calls.filter((c) => c === 'bootstrap').length, 3);
  });

  test('a lasting bootstrap failure reports one clear line', async () => {
    const { service, calls } = reinstallSetup({ extraBusy: 100 });
    await assert.rejects(service.install(), /^Error: launchd 加载失败：Bootstrap failed: 5: Input\/output error$/);
    assert.equal(calls.filter((c) => c === 'bootstrap').length, 8);
  });

  test('other bootstrap errors do not retry', async () => {
    const { service, calls } = reinstallSetup();
    const original = service.run;
    service.run = async (args) => {
      if (args[0] === 'bootstrap') { calls.push('bootstrap'); throw Object.assign(new Error('x'), { code: 113, stderr: 'Could not find domain' }); }
      return original(args);
    };
    await assert.rejects(service.install(), /Could not find domain/);
    assert.equal(calls.filter((c) => c === 'bootstrap').length, 1);
  });

  test('a service that never unloads gives up with a message', async () => {
    const { service } = reinstallSetup({ printsWhileStopping: Infinity });
    await assert.rejects(service.install(), /等待旧服务退出超时/);
  });

  test('status reports each state, and uninstall removes the plist but not the data', async () => {
    const { service, calls } = setup();
    assert.deepEqual((await service.status()), { installed: false, loaded: false, pid: null, plistPath: service.plistPath });
    await service.install();
    const up = await service.status();
    assert.equal(up.pid, 4242);
    await service.uninstall();
    assert.ok(!fs.existsSync(service.plistPath));
    assert.ok(fs.existsSync(service.store.tokenPath));
    assert.deepEqual(calls.at(-2), ['bootout', 'gui/501/com.sandgate.daemon']);
    assert.equal(calls.at(-1)[0], 'print', 'uninstall confirms the service is gone');
  });

  test('the login token never reaches a log', () => {
    const url = 'http://127.0.0.1:7878/#token=SECRET';
    assert.ok(!startMessage({ url, isTTY: false, tokenPath: '/t' }).includes('SECRET'));
    assert.ok(startMessage({ url, isTTY: true, tokenPath: '/t' }).includes('SECRET'));
  });

  test('url prints the login link', () => {
    const dir = tmp();
    const out = execFileSync(process.execPath, [entry, 'url'], { env: { ...process.env, SANDGATE_HOME: dir }, encoding: 'utf8' });
    assert.ok(out.includes(`#token=${fs.readFileSync(path.join(dir, 'token'), 'utf8').trim()}`));
    assert.match(out, /:7878\//);
  });

  test('a port in use gives a clear message rather than a crash', async () => {
    const dir = tmp();
    const holder = net.createServer();
    const uiPort = await listen(holder);
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ uiPort }));
    const r = await new Promise((resolve) => {
      execFile(process.execPath, [entry], { env: { ...process.env, SANDGATE_HOME: dir }, timeout: 8000 }, (e, stdout, stderr) => resolve({ code: e?.code, stderr }));
    });
    holder.close();
    assert.equal(r.code, 1);
    assert.match(r.stderr, /已被占用/);
    assert.doesNotMatch(r.stderr, /EADDRINUSE|at /);
  });

  test('unknown commands show usage', () => {
    assert.throws(() => execFileSync(process.execPath, [entry, 'nope'], { env: { ...process.env, SANDGATE_HOME: tmp() }, stdio: 'pipe' }), (e) => e.status === 2 && e.stderr.toString().includes('用法'));
  });
});

describe('pf allow-list planning', () => {
  // Same shape as the config Clash Verge generates.
  const yaml = `mode: rule
dns:
  enable: true
  default-nameserver:
  - 223.5.5.5
  - 119.29.29.29
  nameserver:
  - https://dns.alidns.com/dns-query
proxies:
- name: SG_Residential
  type: socks5
  server: 203.0.113.99
  port: 7162
  username: u
  dialer-proxy: Dialer-Res
- name: LA-HY2
  type: hysteria2
  server: 203.0.113.1
  port: 8443
  alpn:
  - h3
- name: LA-Trojan
  type: trojan
  server: 203.0.113.2
  ws-opts:
    headers:
      Host: example.com
- name: "HK \\U0001F1ED\\U0001F1F0"
  type: trojan
  server: 203.0.113.3
- name: By-Domain
  type: trojan
  server: node.example.com
proxy-groups:
- name: Dialer-Res
  type: url-test
  proxies:
  - LA-Trojan
  - LA-HY2
- name: US
  type: url-test
  proxies:
  - LA-Trojan
- name: Mixed
  type: select
  proxies:
  - US
  - DIRECT
  - SG_Residential
- name: Loop
  type: select
  proxies:
  - Loop
  - US
rules:
- MATCH,Mixed
`;
  const config = parseClashConfig(yaml);

  test('parses Verge-style YAML, ignoring nested keys', () => {
    assert.equal(config.proxies.length, 5);
    assert.equal(config.proxies[0]['dialer-proxy'], 'Dialer-Res');
    assert.equal(config.proxies[2].server, '203.0.113.2');
    assert.equal(config.proxies[3].name, 'HK 🇭🇰');
    assert.deepEqual(config.groups[0].proxies, ['LA-Trojan', 'LA-HY2']);
    assert.deepEqual(config.dns, ['223.5.5.5', '119.29.29.29']);
  });

  test('a group expands to its members', () => {
    assert.deepEqual(resolveTargets(['US'], config).ips, ['203.0.113.2']);
  });

  test('a chained node allows its dialer, never its own server', () => {
    const r = resolveTargets(['SG_Residential'], config);
    assert.deepEqual(r.ips, ['203.0.113.1', '203.0.113.2']);
    assert.ok(!r.ips.includes('203.0.113.99'));
    assert.ok(r.nodes.includes('SG_Residential'));
  });

  test('nested groups, DIRECT and cycles are handled', () => {
    assert.deepEqual(resolveTargets(['Mixed'], config).ips, ['203.0.113.1', '203.0.113.2']);
    assert.deepEqual(resolveTargets(['Loop'], config).ips, ['203.0.113.2']);
  });

  test('unselected nodes stay out', () => {
    assert.ok(!resolveTargets(['US', 'SG_Residential'], config).ips.includes('203.0.113.3'));
  });

  test('unknown names and domain servers warn instead of being allowed', () => {
    assert.match(resolveTargets(['Nope'], config).warnings[0], /找不到/);
    const d = resolveTargets(['By-Domain'], config);
    assert.deepEqual(d.ips, []);
    assert.match(d.warnings[0], /不是 IPv4/);
  });

  test('flow-style entries parse too', () => {
    const c = parseClashConfig('proxies:\n  - { name: a, type: ss, server: 203.0.113.7 }\nproxy-groups:\n  - { name: G, type: select, proxies: [a, DIRECT] }\n');
    assert.deepEqual(resolveTargets(['G'], c).ips, ['203.0.113.7']);
  });

  test('CIDR lists accept both forms and drop broad or invalid entries', () => {
    const cidrs = parseCidrList('# comment\n1.0.1.0/24\nIP-CIDR,1.0.2.0/23,no-resolve\n0.0.0.0/0\n1.2.3.4/33\nDOMAIN,x.com\n');
    assert.deepEqual(cidrs, ['1.0.1.0/24', '1.0.2.0/23']);
  });

  describe('planner', () => {
    const cnList = Array.from({ length: 1200 }, (_, i) => `36.${i >> 8}.${i & 255}.0/24`).join('\n');
    const setup = (targets = ['US']) => {
      const home = tmp();
      const verge = path.join(home, 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev');
      fs.mkdirSync(path.join(verge, 'ruleset/sukka'), { recursive: true });
      fs.writeFileSync(path.join(verge, 'clash-verge.yaml'), yaml);
      fs.writeFileSync(path.join(verge, 'ruleset/sukka/china-ip.txt'), cnList);
      const store = new Store(path.join(home, 'data'));
      store.data.gate.pfTargets = targets;
      const planner = new PfPlanner({ store, getSettings: () => store.data.gate, home });
      const read = (name) => fs.readFileSync(path.join(planner.dir, `${name}.txt`), 'utf8');
      return { verge, store, planner, read };
    };

    test('writes the lists and rewrites nodes when the subscription changes', () => {
      const { verge, planner, read } = setup();
      planner.tick();
      assert.equal(planner.status.ready, true);
      assert.equal(read('nodes'), '203.0.113.2\n');
      assert.equal(read('dns'), '223.5.5.5\n119.29.29.29\n');
      assert.deepEqual(planner.status.changed.sort(), ['cn', 'dns', 'extra', 'nodes']);
      planner.tick();
      assert.deepEqual(planner.status.changed, [], 'unchanged lists must not touch the files');
      fs.writeFileSync(path.join(verge, 'clash-verge.yaml'), yaml.replace('203.0.113.2', '203.0.113.200'));
      planner.tick();
      assert.equal(read('nodes'), '203.0.113.200\n');
      assert.deepEqual(planner.status.changed, ['nodes']);
    });

    test('keeps the last good lists on a bad read', () => {
      const { verge, planner, read } = setup();
      planner.tick();
      fs.writeFileSync(path.join(verge, 'clash-verge.yaml'), 'proxies: oops\n');
      planner.tick();
      assert.equal(read('nodes'), '203.0.113.2\n');
      assert.equal(planner.status.ready, false);
      fs.writeFileSync(path.join(verge, 'clash-verge.yaml'), yaml.replaceAll('name: US', 'name: RENAMED'));
      planner.tick();
      assert.equal(read('nodes'), '203.0.113.2\n');
      assert.ok(planner.status.warnings.some((w) => w.includes('找不到')));
    });

    test('keeps the last good CN list when the new one looks truncated', () => {
      const { verge, planner, read } = setup();
      planner.tick();
      const before = read('cn');
      fs.writeFileSync(path.join(verge, 'ruleset/sukka/china-ip.txt'), '1.0.1.0/24\n');
      planner.tick();
      assert.equal(read('cn'), before);
      assert.ok(planner.status.warnings.some((w) => w.includes('疑似损坏')));
    });

    test('nodes used by sandbox instances are included', () => {
      const { store, planner, read } = setup([]);
      store.data.apps.push(validateApp({ name: 'i', command: '/bin/ls', node: 'LA-HY2' }));
      planner.tick();
      assert.equal(read('nodes'), '203.0.113.1\n');
    });

    test('its output passes the root script validation', () => {
      const { planner } = setup();
      planner.tick();
      const out = execFileSync('/bin/bash', [path.join(import.meta.dirname, '../scripts/sandgate-pf.sh'), 'check', planner.dir], { encoding: 'utf8' });
      assert.match(out, /cn: 1200 条/);
    });
  });
});

describe('pf rules', () => {
  const script = path.join(import.meta.dirname, '../scripts/sandgate-pf.sh');
  const render = (env = {}, ...ifaces) => execFileSync('/bin/bash', [script, 'render', ...ifaces], { env: { PATH: process.env.PATH, ...env }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

  test('never matches on user or group, which deadlocked the kernel', () => {
    const rules = render({}, 'en0', 'en1');
    assert.doesNotMatch(rules, /\b(user|group)\b/);
    const source = fs.readFileSync(script, 'utf8');
    assert.doesNotMatch(source, /echo "(pass|block)[^"]*\b(user|group)\b/);
  });

  test('allow-lists come before the final block, on every interface', () => {
    const rules = render({}, 'en0', 'en1').split('\n');
    for (const i of ['en0', 'en1']) {
      const block = rules.indexOf(`block drop out quick on ${i} all`);
      for (const rule of [`pass out quick on ${i} inet to <sg_nodes> no state`, `pass out quick on ${i} inet to <sg_cn> no state`, `pass out quick on ${i} inet to <sg_extra> no state`]) {
        const at = rules.indexOf(rule);
        assert.ok(at >= 0 && at < block, rule);
      }
    }
  });

  test('tables are declared before any rule uses them', () => {
    const r = render({}, 'en0');
    const lastTable = r.lastIndexOf('table <sg_');
    assert.ok(lastTable >= 0 && lastTable < r.indexOf('pass out'));
  });

  test('plain DNS only reaches the bootstrap servers', () => {
    const r = render({}, 'en0');
    assert.ok(r.indexOf('to <sg_dns> port 53') < r.indexOf('to any port 53'));
    assert.ok(r.indexOf('to any port 53') < r.indexOf('to <sg_cn>'), '114.114.114.114 is a Chinese IP, so the block must precede the CN pass');
  });

  test('never filters the TUN device', () => {
    assert.doesNotMatch(render({}, 'en0'), /utun/);
  });

  test('LAN pass comes after the DNS block, and idle NICs do not fail the load', () => {
    const r = render({}, 'en0');
    assert.ok(r.indexOf('to any port 53') < r.indexOf('(en0:network)'));
    assert.match(r, /to \(en0:network\)/);
  });

  test('ALLOW_LAN=0 removes the LAN passes', () => {
    assert.doesNotMatch(render({ ALLOW_LAN: '0' }, 'en0'), /:network|224\.0\.0\.0/);
  });

  test('rejects values that could inject rules', () => {
    assert.throws(() => render({ ALLOW_LAN: '1; pass out all' }, 'en0'));
  });

  test('install stays closed and nothing persists across a reboot', () => {
    assert.throws(() => execFileSync('/bin/bash', [script, 'install'], { stdio: 'pipe' }), (e) => e.status === 2 && e.stderr.toString().includes('暂未开放'));
    assert.doesNotMatch(fs.readFileSync(script, 'utf8'), /StartInterval|WatchPaths|launchctl bootstrap/);
  });

  test('the old probe with a user rule stays disabled', () => {
    assert.throws(() => execFileSync('/bin/bash', [path.join(import.meta.dirname, '../scripts/pf-probe.sh')], { stdio: 'pipe' }), (e) => e.status === 2 && e.stderr.toString().includes('已停用'));
  });

  describe('allow-list validation', () => {
    const cn = Array.from({ length: 1000 }, (_, i) => `36.${i >> 8}.${i & 255}.0/24`);
    const write = (over = {}) => {
      const dir = tmp();
      const lists = { nodes: ['203.0.113.10'], dns: ['223.5.5.5'], cn, extra: [], ...over };
      for (const [name, lines] of Object.entries(lists)) fs.writeFileSync(path.join(dir, `${name}.txt`), lines.length ? `${lines.join('\n')}\n` : '');
      return dir;
    };
    const check = (dir) => execFileSync('/bin/bash', [script, 'check', dir], { stdio: 'pipe', encoding: 'utf8' });

    test('accepts good lists', () => {
      assert.match(check(write()), /nodes: 1 条[\s\S]*cn: 1000 条/);
    });

    for (const [label, over] of [
      ['the whole internet in cn', { cn: [...cn, '0.0.0.0/0'] }],
      ['half the internet in cn', { cn: [...cn, '128.0.0.0/1'] }],
      ['a wide prefix in extra', { extra: ['8.0.0.0/7'] }],
      ['a CIDR as a node', { nodes: ['203.0.113.0/24'] }],
      ['no nodes', { nodes: [] }],
      ['too many nodes', { nodes: Array.from({ length: 65 }, (_, i) => `203.0.113.${i + 1}`) }],
      ['a truncated cn list', { cn: cn.slice(0, 10) }],
      ['an invalid octet', { nodes: ['203.0.113.999'] }],
      ['loopback', { dns: ['127.0.0.1'] }],
      ['multicast', { extra: ['224.0.0.0/8'] }],
      ['rule injection', { nodes: ['203.0.113.10 } pass out all'] }],
      ['a domain', { nodes: ['example.com'] }],
    ]) {
      test(`rejects ${label}`, () => {
        assert.throws(() => check(write(over)));
      });
    }

    test('rejects a symlink, and a missing list', () => {
      const dir = write();
      fs.rmSync(path.join(dir, 'extra.txt'));
      assert.throws(() => check(dir));
      fs.symlinkSync('/etc/hosts', path.join(dir, 'extra.txt'));
      assert.throws(() => check(dir));
    });
  });

  test('privileged commands refuse to run without root', { skip: process.getuid() === 0 }, () => {
    for (const cmd of ['trial', 'uninstall', 'status']) {
      assert.throws(() => execFileSync('/bin/bash', [script, cmd], { stdio: 'ignore' }), { status: 2 });
    }
  });
});

// Needs a host where sandbox-exec works; it cannot nest inside another sandbox.
const canSandbox = (() => {
  try { execFileSync('/usr/bin/sandbox-exec', ['-p', '(version 1)(allow default)', '/usr/bin/true'], { stdio: 'ignore' }); return true; }
  catch { return false; }
})();

describe('real sandbox-exec', { skip: canSandbox ? false : 'sandbox-exec unavailable (nested sandbox?)' }, () => {
  test('profile blocks direct access to a local port other than the gate', async () => {
    const dir = tmp();
    const allowed = net.createServer((s) => s.end('ok'));
    const denied = net.createServer((s) => s.end('leak'));
    const allowedPort = await listen(allowed);
    const deniedPort = await listen(denied);
    const profile = path.join(dir, 'p.sb');
    const appDef = validateApp({ name: 'x', command: '/usr/bin/nc', node: 'n' });
    fs.writeFileSync(profile, buildProfile(appDef, { port: allowedPort, sandgateDir: dir }));
    const { execFile } = await import('node:child_process');
    const nc = (port) => new Promise((resolve) => {
      execFile('/usr/bin/sandbox-exec', ['-f', profile, '/usr/bin/nc', '-z', '-G', '2', '127.0.0.1', String(port)], { timeout: 6000 }, (e) => resolve(e ? e.code : 0));
    });
    assert.equal(await nc(allowedPort), 0);
    assert.notEqual(await nc(deniedPort), 0);
    allowed.close();
    denied.close();
  });
});
