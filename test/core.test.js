import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { AppManager, instanceArgs, nscurlBlocked, stopRecordedInstances } from '../src/apps.js';
import { appLabel, groupApps } from '../public/grouping.js';
import { detectVerge, ClashClient } from '../src/clash.js';
import { Store, ValidationError, expandPath, mergeGateSettings, validateApp, DEFAULT_SETTINGS } from '../src/config.js';
import { Sandgate } from '../src/daemon.js';
import { GateManager, GateMonitor, PinMismatch, buildChecks, decide, verifyPin } from '../src/gate.js';
import { ClashSync, applySpec, buildSpec, currentScriptFile, missingTargets, renderRuntimeYaml, validateNetProfile, withManagedBlock } from '../src/netprofile.js';
import { GatePort } from '../src/gateport.js';
import { ConnectionGuard, findViolations, rulesFingerprint, ipv6Check, modeWarning } from '../src/guard.js';
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
    assert.throws(() => validateApp({ name: 'a', command: '/bin/ls', network: 'bogus' }), ValidationError);
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

  // A chained node took about 1.8 s to dial on a real mihomo, after CONNECT was answered.
  test('verifyPin waits for a connection that is listed only after dialing', async () => {
    const { upstream, controller } = fakeMihomo({ via: 'node-a' });
    const upstreamPort = await listen(upstream);
    const port = await listen(controller);
    const real = new ClashClient({ type: 'tcp', host: '127.0.0.1', port, secret: 'sekret' });
    const started = Date.now();
    const client = { connections: () => (Date.now() - started < 2000 ? { connections: [] } : real.connections()) };
    assert.match(await verifyPin({ upstreamPort, probeUrl: 'http://cp.example/x', node: 'node-a', client }), /node-a/);
    assert.ok(Date.now() - started >= 2000);
    upstream.close();
    controller.close();
  });

  test('verifyPin gives up when the connection never appears', async () => {
    const { upstream, controller } = fakeMihomo({ via: 'node-a' });
    const upstreamPort = await listen(upstream);
    const client = { connections: () => ({ connections: [] }) };
    await assert.rejects(verifyPin({ upstreamPort, probeUrl: 'http://cp.example/x', node: 'node-a', client, findTimeoutMs: 300 }), (e) => /找不到探测连接/.test(e.message) && !(e instanceof PinMismatch));
    upstream.close();
    controller.close();
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
    const spec = buildSpec(app.store.data);
    assert.equal(spec.listeners.filter((l) => l.proxy === 'jp').length, 1, 'instances on one node share a listener');
    assert.equal(spec.listeners.filter((l) => l.proxy === 'us').length, 1);
  });

  describe('network profile API', () => {
    const post = (path, body) => authed(path, { method: 'POST', body });
    const inst = (name, netProfile) => post('/api/apps', { name, command: '/bin/ls', netProfile });
    const customBody = (name, exits = { Proxy: 'us' }) => ({ name, mode: 'custom', exits, timezone: 'Asia/Tokyo' });

    test('an instance can follow Clash, with no port or gate', async () => {
      const { json } = await inst('f1', 'follow');
      assert.equal(json.network, 'open');
      assert.equal(json.port, null);
      assert.equal(json.node, '');
      await authed(`/api/apps/${json.id}`, { method: 'DELETE', body: {} });
    });

    test('a custom profile gives instances a port and their own gate, shared between them', async () => {
      const { json: { profile } } = await post('/api/netprofiles', customBody('p-shared'));
      const before = Object.keys(app.store.data.gate.listeners).length;
      const a = (await inst('c1', profile.id)).json;
      const b = (await inst('c2', profile.id)).json;
      assert.equal(a.network, 'rules');
      assert.equal(a.node, `sgp-${profile.id}`);
      assert.notEqual(a.port, b.port);
      assert.equal(Object.keys(app.store.data.gate.listeners).length, before, 'new instances need no new listener, so no Clash reload');
      assert.ok((await authed('/api/state')).json.gates.nodes[a.node]);
      for (const x of [a, b]) await authed(`/api/apps/${x.id}`, { method: 'DELETE', body: {} });
    });

    test('a profile in use cannot be deleted; an unused one releases its listener', async () => {
      const { json: { profile } } = await post('/api/netprofiles', customBody('p-del'));
      const key = `sgp-${profile.id}`;
      const a = (await inst('d1', profile.id)).json;
      const refused = await authed(`/api/netprofiles/${profile.id}`, { method: 'DELETE', body: {} });
      assert.equal(refused.status, 409);
      assert.match(refused.json.error, /d1/);
      await authed(`/api/apps/${a.id}`, { method: 'DELETE', body: {} });
      assert.equal((await authed(`/api/netprofiles/${profile.id}`, { method: 'DELETE', body: {} })).status, 200);
      assert.equal(app.store.data.gate.listeners[key], undefined);
    });

    test('changing a node profile moves its stopped instances', async () => {
      const { json: { profile } } = await post('/api/netprofiles', { name: 'p-node', mode: 'node', node: 'node-a' });
      const a = (await inst('n1', profile.id)).json;
      assert.equal(a.network, 'gate');
      assert.equal(a.node, 'node-a');
      const put = await authed(`/api/netprofiles/${profile.id}`, { method: 'PUT', body: { name: 'p-node', mode: 'node', node: 'node-b' } });
      assert.equal(put.status, 200);
      const moved = (await authed('/api/state')).json.apps.find((x) => x.id === a.id);
      assert.equal(moved.node, 'node-b');
      assert.equal(app.store.data.gate.listeners['node-a'], undefined);
      assert.ok(app.store.data.gate.listeners['node-b']);
      await authed(`/api/apps/${a.id}`, { method: 'DELETE', body: {} });
      await authed(`/api/netprofiles/${profile.id}`, { method: 'DELETE', body: {} });
    });

    test('one node cannot have two profiles', async () => {
      const { json: { profile } } = await post('/api/netprofiles', { name: 'p-one', mode: 'node', node: 'node-c' });
      assert.equal((await post('/api/netprofiles', { name: 'p-two', mode: 'node', node: 'node-c' })).status, 409);
      await authed(`/api/netprofiles/${profile.id}`, { method: 'DELETE', body: {} });
    });

    test('rejects a missing profile and a bad body', async () => {
      assert.equal((await inst('x', 'ffffff')).status, 400);
      assert.equal((await post('/api/netprofiles', { name: 'empty', mode: 'custom' })).status, 400);
      assert.equal((await authed('/api/netprofiles/ffffff', { method: 'DELETE', body: {} })).status, 404);
    });

    test('the state lists profiles and the sync status', async () => {
      const { json } = await authed('/api/state');
      assert.ok(Array.isArray(json.netProfiles));
      assert.ok(json.sync.state);
    });
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

  // A real mihomo returned 502 for a dead or unknown node, and never fell back to direct.
  describe('a dead node', () => {
    const setup = async (t, over = {}) => {
      const state = { down: false };
      const live = net.createServer((s) => s.on('error', () => {}));
      const settings = {
        ...structuredClone(DEFAULT_SETTINGS.gate), requireTun: false, requirePin: false, stableSec: 0.02, delayIntervalSec: 0.01, listeners: {}, ...over,
      };
      settings.listeners.a = await listen(live);
      const client = { delay: async () => { if (state.down) throw new Error('down'); return { delay: 10 }; } };
      const gates = new GateManager({ getSettings: () => settings, client });
      const closed = [];
      gates.on('close', (node) => closed.push(node));
      t.after(() => { gates.stop(); live.close(); });
      gates.sync(['a']);
      gates.start();
      assert.ok(await until(() => gates.isOpen('a')));
      return { state, gates, closed };
    };

    test('keeps the gate open and reports it as a warning', async (t) => {
      const { state, gates, closed } = await setup(t);
      state.down = true;
      const node = () => gates.snapshot().nodes.a.checks.find((c) => c.id === 'node');
      assert.ok(await until(() => node().detail === 'down'));
      await sleep(100);
      assert.equal(gates.isOpen('a'), true);
      assert.deepEqual(closed, []);
      assert.equal(node().advisory, true);
      assert.equal(node().ok, false);
    });

    test('closes the gate only when asked to', async (t) => {
      const { state, gates } = await setup(t, { requireNode: true });
      state.down = true;
      assert.ok(await until(() => !gates.isOpen('a')));
    });
  });

  describe('route confirmation', () => {
    // Drives the real pin check through a fake mihomo whose answers can change.
    const setup = async (t) => {
      const state = { via: null };
      const upstream = net.createServer((s) => {
        s.on('error', () => {});
        s.on('data', () => s.write('HTTP/1.1 200 Connection established\r\n\r\n'));
      });
      const port = await listen(upstream);
      const settings = {
        ...structuredClone(DEFAULT_SETTINGS.gate), requireTun: false, stableSec: 0.02, delayIntervalSec: 0.01, pinIntervalSec: 0.05, listeners: { a: port },
      };
      const sockets = [];
      upstream.on('connection', (s) => sockets.push(s));
      const client = {
        delay: async () => ({ delay: 10 }),
        connections: async () => ({
          connections: state.via ? sockets.map((s) => ({ metadata: { sourcePort: String(s.remotePort) }, chains: [state.via] })) : [],
        }),
      };
      const gates = new GateManager({ getSettings: () => settings, client });
      t.after(() => { gates.stop(); upstream.close(); for (const s of sockets) s.destroy(); });
      return { state, gates };
    };

    test('a route never confirmed keeps the gate closed', async (t) => {
      const { gates } = await setup(t);
      gates.sync(['a']);
      gates.start();
      await sleep(300);
      assert.equal(gates.isOpen('a'), false);
    });

    test('a wrong route closes the gate', async (t) => {
      const { state, gates } = await setup(t);
      state.via = 'a';
      gates.sync(['a']);
      gates.start();
      assert.ok(await until(() => gates.isOpen('a')));
      state.via = 'DIRECT';
      assert.ok(await until(() => !gates.isOpen('a')), 'gate stays open on a wrong route');
    });
  });

  test('a failing basic check closes only its own gate', async (t) => {
    const down = new Set();
    const client = {
      delay: async (node) => { if (down.has(node)) throw new Error('down'); return { delay: 10 }; },
    };
    const settings = {
      ...structuredClone(DEFAULT_SETTINGS.gate), requireNode: true, requireTun: false, requirePin: false, stableSec: 0.02, delayIntervalSec: 0.01, listeners: {},
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
    assert.ok(p.indexOf('(allow file-read-metadata (literal "/Users/t/.sandgate-instances"))') > deny, 'realpath needs to stat the parent, or Chrome rejects its data directory');
    assert.doesNotMatch(p, /allow file-read-metadata \(subpath/, 'only the parent itself, not its contents');
    assert.ok(deny > 0 && allow > deny, 'last match wins, so the allow must follow the deny');
    assert.ok(p.indexOf('(deny file-read* file-write* (subpath "/Users/t/.sandgate"))') > allow);
  });

  describe('shared data', () => {
    const p = buildProfile(app({ isolateHome: false }), opts);

    test('leaves the home folder and temp directory visible', () => {
      assert.doesNotMatch(p, /subpath "\/Users\/t"\)/);
      assert.equal(buildEnv(app({ isolateHome: false }), 17900, { HOME: '/Users/t', TMPDIR: '/t/' }, '/inst/abc').TMPDIR, '/t/');
    });

    test('still hides other instances and protected paths', () => {
      assert.ok(p.includes('(deny file-read* file-write* (subpath "/Users/t/.sandgate-instances"))'));
      assert.ok(p.includes('(deny file-read* file-write* (subpath "/Users/t/.ssh"))'));
    });

    test('{data} still points at the instance directory, so Chrome gets its own profile', () => {
      const env = buildEnv(app({ isolateHome: false, env: { D: '{data}/x', H: '{home}/y' } }), 17900, { HOME: '/Users/t' }, '/inst/abc');
      assert.equal(env.D, '/inst/abc/x');
      assert.equal(env.H, '/Users/t/y');
    });
  });

  describe('clone', () => {
    const cloneOpts = { ...opts, tempDir: '/nonexistent/T' };
    const deny = (x) => `(deny file-read* file-write* (subpath "${x}"))`;
    const rw = (x) => `(allow file-read* file-write* (subpath "${x}"))`;
    const meta = (x) => `(allow file-read-metadata (literal "${x}"))`;

    test('hides the real home folder, and lists nothing in the system temp directory', () => {
      const p = buildProfile(app(), cloneOpts);
      assert.ok(p.includes(deny('/Users/t')));
      assert.ok(p.includes('(deny file-read-data (literal "/nonexistent/T"))'));
      assert.ok(!p.includes(deny('/nonexistent/T')), 'Chrome exits with code 21 if it cannot create its singleton socket here');
    });

    test('keeps its own directory, with only metadata on the parents', () => {
      const p = buildProfile(app(), cloneOpts);
      assert.ok(p.indexOf(rw('/Users/t/.sandgate-instances/abc')) > p.indexOf(deny('/Users/t')));
      assert.ok(p.indexOf(meta('/Users/t')) > p.indexOf(deny('/Users/t')));
      assert.ok(p.includes(meta('/Users/t/.sandgate-instances')));
      assert.doesNotMatch(p, /file-read\* file-write\* \(subpath "\/Users\/t\/\.sandgate-instances"\)\)\n\(allow/, 'parents are never opened');
    });

    test('shared folders and the working directory stay reachable', () => {
      const p = buildProfile(app({ shared: ['/Users/t/Downloads/x'], cwd: '/Users/t/work' }), cloneOpts);
      for (const d of ['/Users/t/Downloads/x', '/Users/t/work']) assert.ok(p.indexOf(rw(d)) > p.indexOf(deny('/Users/t')), d);
      assert.ok(p.includes(meta('/Users/t/Downloads')));
    });

    test('a protected path wins over a shared folder', () => {
      const p = buildProfile(app({ shared: ['/Users/t/.ssh'] }), cloneOpts);
      assert.ok(p.lastIndexOf(deny('/Users/t/.ssh')) > p.indexOf(rw('/Users/t/.ssh')));
    });

    test('a program inside the home folder can run but not be written to', () => {
      const p = buildProfile(app({ command: '/Users/t/Applications/Foo.app' }), cloneOpts);
      assert.ok(p.includes('(allow file-read* (subpath "/Users/t/Applications/Foo.app"))'));
      assert.ok(!p.includes(rw('/Users/t/Applications/Foo.app')));
      assert.doesNotMatch(buildProfile(app({ command: '/Applications/Foo.app' }), cloneOpts), /allow file-read\* \(subpath "\/Applications/);
    });

    test('writable paths reopen only when writes are restricted', () => {
      assert.ok(!buildProfile(app({ writable: ['/Users/t/w'] }), cloneOpts).includes(rw('/Users/t/w')));
      assert.ok(buildProfile(app({ writable: ['/Users/t/w'], restrictWrites: true }), cloneOpts).includes(rw('/Users/t/w')));
    });

    test('gets its own HOME and temp directory', () => {
      const env = buildEnv(app(), 17900, { HOME: '/Users/t', TMPDIR: '/t/' }, '/inst/abc');
      assert.equal(env.TMPDIR, '/inst/abc/tmp');
      assert.equal(env.HOME, '/inst/abc');
    });
  });

  describe('time zone', () => {
    const base = { HOME: '/Users/t', TZ: 'Asia/Singapore' };

    test('new instances default to Los Angeles, and it reaches the child', () => {
      assert.equal(app().timezone, 'America/Los_Angeles');
      assert.equal(buildEnv(app(), 17900, base, '/inst/abc').TZ, 'America/Los_Angeles');
    });

    test('can be chosen, changed later, and kept by an edit that omits it', () => {
      const first = app({ timezone: 'Asia/Tokyo' });
      assert.equal(first.timezone, 'Asia/Tokyo');
      assert.equal(validateApp({ name: 'x', command: '/bin/ls', node: 'n', timezone: 'Asia/Singapore' }, first).timezone, 'Asia/Singapore');
      assert.equal(validateApp({ name: 'x', command: '/bin/ls', node: 'n' }, first).timezone, 'Asia/Tokyo');
    });

    test('empty follows the system', () => {
      assert.equal(buildEnv(app({ timezone: '' }), 17900, base, '/inst/abc').TZ, 'Asia/Singapore');
    });

    test('an explicit TZ in the environment field wins', () => {
      assert.equal(buildEnv(app({ env: { TZ: 'UTC' } }), 17900, base, '/inst/abc').TZ, 'UTC');
    });

    test('rejects a name that is not a time zone', () => {
      assert.throws(() => app({ timezone: 'Mars/Olympus' }), /时区无效/);
    });

    test('instances saved before this field keep the system zone', () => {
      const dir = tmp();
      fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ apps: [{ id: 'a', name: 'a', command: '/bin/ls', args: [], network: 'none' }] }));
      assert.equal(new Store(dir).data.apps[0].timezone, '');
    });
  });

  describe('deleting an instance', () => {
    const setup = () => {
      const store = new Store(path.join(tmp(), 'data'));
      const manager = new AppManager({ store, gates: { on() {}, isOpen: () => false }, controllerSocket: () => '' });
      const add = (over = {}) => {
        const a = validateApp({ name: 'x', command: '/bin/ls', network: 'none', ...over });
        store.data.apps.push(a);
        return a;
      };
      return { store, manager, add };
    };

    test('removes its directory and nothing else', async () => {
      const { store, manager, add } = setup();
      const [a, b] = [add(), add()];
      for (const x of [a, b]) {
        fs.mkdirSync(path.join(store.instanceHome(x.id), 'profile'), { recursive: true });
        fs.writeFileSync(path.join(store.instanceHome(x.id), 'profile/f'), 'x');
      }
      await manager.remove(a.id);
      assert.equal(fs.existsSync(store.instanceHome(a.id)), false);
      assert.equal(fs.readFileSync(path.join(store.instanceHome(b.id), 'profile/f'), 'utf8'), 'x');
    });

    test('does not follow symlinks out of the directory', async () => {
      const { store, manager, add } = setup();
      const a = add();
      const outside = tmp();
      fs.writeFileSync(path.join(outside, 'keep'), 'x');
      fs.mkdirSync(store.instanceHome(a.id));
      fs.symlinkSync(outside, path.join(store.instanceHome(a.id), 'link'));
      await manager.remove(a.id);
      assert.equal(fs.readFileSync(path.join(outside, 'keep'), 'utf8'), 'x');
    });

    test('works when the instance never had a directory', async () => {
      const { manager, add } = setup();
      await manager.remove(add({ isolateHome: false }).id);
    });
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

  describe('installed daemon', () => {
    const cnList = Array.from({ length: 1000 }, (_, i) => `36.${i >> 8}.${i & 255}.0/24`).join('\n');

    // Runs the real functions against a fake pfctl and temporary paths.
    function rig({ attached = true } = {}) {
      const dir = tmp();
      const src = path.join(dir, 'src');
      fs.mkdirSync(src);
      const writeLists = (nodes = '203.0.113.10') => {
        fs.writeFileSync(path.join(src, 'nodes.txt'), `${nodes}\n`);
        fs.writeFileSync(path.join(src, 'dns.txt'), '223.5.5.5\n');
        fs.writeFileSync(path.join(src, 'cn.txt'), `${cnList}\n`);
        fs.writeFileSync(path.join(src, 'extra.txt'), '');
      };
      writeLists();
      const p = (name) => path.join(dir, name);
      fs.writeFileSync(p('env'), `ALLOW_LAN=1\nLISTS_DIR=${src}\n`);
      fs.writeFileSync(p('ifaces'), 'en0\n');
      fs.writeFileSync(p('boot'), '100');
      fs.writeFileSync(p('pfctl'), `#!/bin/bash
printf "%s\n" "$*" >> "${p('calls')}"
case "$*" in
  "-E") echo "Token : 42" ;;
  "-s rules") ${attached ? `echo 'anchor "com.apple/*" all'` : ':'} ;;
  "-s info") echo "Status: Enabled" ;;
  *"-s rules") echo "block drop out quick on en0 all" ;;
esac
exit 0
`, { mode: 0o755 });
      const state = p('state');
      const prelude = `
source '${script}'
need_root() { :; }
physical_interfaces() { /bin/cat '${p('ifaces')}'; }
boot_id() { /bin/cat '${p('boot')}'; }
PFCTL='${p('pfctl')}'; ENV_FILE='${p('env')}'; TOKEN_FILE='${p('token')}'; STATE_DIR='${state}'
SYNC_SECONDS=0.2
`;
      const shell = (body) => execFileSync('/bin/bash', ['-c', `${prelude}\n${body}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      const calls = () => (fs.existsSync(p('calls')) ? fs.readFileSync(p('calls'), 'utf8').trim().split('\n') : []);
      const start = (extra = '') => spawn('/bin/bash', ['-c', `${prelude}\n${extra}\nrun`], { stdio: 'ignore' });
      return { dir, p, src, state, writeLists, shell, calls, start };
    }

    const until = async (check) => {
      for (let i = 0; i < 100; i++) {
        if (check()) return;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.fail('condition not reached');
    };
    const stop = (child) => new Promise((resolve) => { child.once('exit', (code) => resolve(code)); child.kill('SIGTERM'); });
    const loads = (calls) => calls.filter((c) => /^-a com\.apple\/sandgate -f /.test(c));
    const replaces = (calls) => calls.filter((c) => c.includes('-T replace'));

    test('loads once, calls pfctl for tables only on a change, and keeps rules when stopped', async (t) => {
      const r = rig();
      const child = r.start();
      t.after(() => child.kill('SIGKILL'));
      await until(() => loads(r.calls()).length === 1 && r.calls().includes('-E'));
      await new Promise((res) => setTimeout(res, 800));
      assert.equal(loads(r.calls()).length, 1, 'no reload while nothing changes');
      assert.equal(replaces(r.calls()).length, 0, 'no table updates while nothing changes');

      r.writeLists('203.0.113.11');
      await until(() => replaces(r.calls()).length === 4);
      await until(() => fs.readFileSync(path.join(r.state, 'lists/nodes.txt'), 'utf8') === '203.0.113.11\n');
      assert.equal(loads(r.calls()).length, 1, 'a list change swaps tables instead of reloading rules');

      assert.equal(await stop(child), 0);
      assert.equal(r.calls().filter((c) => /(^| )-[FX]( |$)/.test(c)).length, 0, 'stopping never flushes or releases pf');
      assert.equal(fs.readFileSync(path.join(r.state, 'failed'), 'utf8'), '0\n', 'a clean stop does not count as a failed boot');
    });

    test('a bad list changes nothing, and the next good one applies', async (t) => {
      const r = rig();
      const child = r.start();
      t.after(() => child.kill('SIGKILL'));
      await until(() => loads(r.calls()).length === 1);
      fs.writeFileSync(path.join(r.src, 'nodes.txt'), '0.0.0.0/0\n');
      await new Promise((res) => setTimeout(res, 800));
      assert.equal(replaces(r.calls()).length, 0);
      assert.equal(fs.readFileSync(path.join(r.state, 'lists/nodes.txt'), 'utf8'), '203.0.113.10\n');

      r.writeLists('203.0.113.12');
      await until(() => replaces(r.calls()).length === 4);
      await stop(child);
    });

    test('a new NIC reloads the rules once with validated lists, and a removed one does not', async (t) => {
      const r = rig();
      const child = r.start();
      t.after(() => child.kill('SIGKILL'));
      await until(() => loads(r.calls()).length === 1);

      fs.writeFileSync(r.p('ifaces'), 'en0\nen7\n');
      await until(() => loads(r.calls()).length === 2);
      const rules = fs.readFileSync(path.join(r.state, 'lists/rules.conf'), 'utf8');
      assert.match(rules, /block drop out quick on en0 all/);
      assert.match(rules, /block drop out quick on en7 all/);
      assert.ok(rules.includes(`file "${path.join(r.state, 'lists')}/nodes.txt"`), 'tables load from the root-owned copy');

      fs.writeFileSync(r.p('ifaces'), 'en0\n');
      await new Promise((res) => setTimeout(res, 800));
      assert.equal(loads(r.calls()).length, 2);
      await stop(child);
    });

    test('boots from the last good lists when the source is unusable', async (t) => {
      const r = rig();
      fs.mkdirSync(path.join(r.state, 'lists'), { recursive: true });
      for (const f of ['nodes', 'dns', 'cn', 'extra']) fs.copyFileSync(path.join(r.src, `${f}.txt`), path.join(r.state, 'lists', `${f}.txt`));
      fs.rmSync(r.src, { recursive: true });
      const child = r.start();
      t.after(() => child.kill('SIGKILL'));
      await until(() => loads(r.calls()).length === 1);
      await stop(child);
    });

    test('exits with an error instead of loading when no list is usable', async () => {
      const r = rig();
      fs.rmSync(r.src, { recursive: true });
      const code = await new Promise((resolve) => r.start().once('exit', resolve));
      assert.equal(code, 1);
      assert.equal(loads(r.calls()).length, 0);
    });

    test('restores a missing com.apple anchor while settling', async (t) => {
      const r = rig({ attached: false });
      const child = r.start();
      t.after(() => child.kill('SIGKILL'));
      await until(() => r.calls().includes('-f /etc/pf.conf'));
      await stop(child);
    });

    test('checks stop once stable, which also clears the failed-boot count', async (t) => {
      const r = rig();
      const child = r.start('STABLE_SECONDS=1');
      t.after(() => child.kill('SIGKILL'));
      await until(() => fs.existsSync(path.join(r.state, 'failed')) && fs.readFileSync(path.join(r.state, 'failed'), 'utf8') === '0\n');
      await new Promise((res) => setTimeout(res, 300));
      const before = r.calls().length;
      await new Promise((res) => setTimeout(res, 800));
      assert.equal(r.calls().length, before, 'no pfctl calls at all once stable and unchanged');
      await stop(child);
    });

    test('two unclean boots in a row stop the rules until the next install', () => {
      const r = rig();
      fs.mkdirSync(r.state);
      const guard = (boot) => {
        fs.writeFileSync(r.p('boot'), boot);
        try { r.shell('boot_guard'); return true; } catch { return false; }
      };
      assert.equal(guard('1'), true);
      assert.equal(guard('1'), true, 'a daemon restart in the same boot is not counted');
      assert.equal(fs.readFileSync(path.join(r.state, 'failed'), 'utf8'), '1\n');
      assert.equal(guard('2'), true);
      assert.equal(guard('3'), false);
      assert.ok(fs.existsSync(path.join(r.state, 'tripped')));
      assert.equal(guard('4'), false, 'stays stopped on later boots');
    });

    test('boots that reach stability or stop cleanly are not counted', () => {
      const r = rig();
      fs.mkdirSync(r.state);
      for (const boot of ['1', '2', '3', '4']) {
        fs.writeFileSync(r.p('boot'), boot);
        r.shell('boot_guard');
        fs.writeFileSync(path.join(r.state, 'failed'), '0\n');
      }
      assert.equal(fs.existsSync(path.join(r.state, 'tripped')), false);
    });

    // macOS ships bash 3.2, which reads the bytes of a following Chinese character as part
    // of the variable name. With `set -u` that killed the daemon right after loading rules.
    test('no variable is followed directly by a non-ASCII character', () => {
      for (const file of ['sandgate-pf.sh', 'pf-probe.sh']) {
        const source = fs.readFileSync(path.join(import.meta.dirname, '../scripts', file), 'utf8');
        assert.doesNotMatch(source, /\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7f]/, file);
      }
    });

    test('the plist is valid, restarts only after a crash, and has no timers', () => {
      const r = rig();
      const plist = r.shell('render_plist');
      const file = r.p('daemon.plist');
      fs.writeFileSync(file, plist);
      execFileSync('/usr/bin/plutil', ['-lint', '-s', file]);
      assert.match(plist, /<key>SuccessfulExit<\/key><false\/>/);
      assert.doesNotMatch(fs.readFileSync(script, 'utf8'), /<key>(StartInterval|StartCalendarInterval|WatchPaths)/);
    });

    test('install and run need root', () => {
      for (const cmd of ['install', 'run']) {
        assert.throws(() => execFileSync('/bin/bash', [script, cmd], { stdio: 'pipe' }), (e) => e.status === 2 && e.stderr.toString().includes('需要 sudo'));
      }
    });

    test('the installed copy is not reachable from any path a normal user can change', () => {
      const source = fs.readFileSync(script, 'utf8');
      assert.match(source, /INSTALLED="\/usr\/local\/sbin\/sandgate-pf"/);
      assert.match(source, /install -o root -g wheel -m 755 "\$self" "\$INSTALLED"/);
    });
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

describe('Clash mode and IPv6 checks', () => {
  test('only rule mode is quiet', () => {
    assert.equal(modeWarning('rule'), '');
    assert.equal(modeWarning(undefined), '');
    assert.match(modeWarning('direct'), /direct 模式/);
    assert.match(modeWarning('global'), /global 模式/);
    assert.match(modeWarning('other'), /other 模式/);
  });

  test('says IPv6 is blocked when pf is working, whatever Clash has set', () => {
    for (const clash of [true, false]) {
      const r = ipv6Check('protected', clash);
      assert.equal(r.status, 'ok');
      assert.match(r.detail, /已拦截公网 IPv6/);
    }
  });

  test('warns when pf is off or unknown, and never claims a block', () => {
    for (const state of ['exposed', 'unknown', undefined]) {
      const r = ipv6Check(state, true);
      assert.equal(r.status, 'warn');
      assert.doesNotMatch(r.detail, /已拦截/);
    }
  });

  test('the final pf rule has no address family, so it also drops IPv6', () => {
    const rules = execFileSync('/bin/bash', [path.join(import.meta.dirname, '../scripts/sandgate-pf.sh'), 'render', 'en0'], { encoding: 'utf8' });
    assert.match(rules, /^block drop out quick on en0 all$/m);
  });

  test('the guard reports a mode change and clears it again', async () => {
    let mode = 'direct';
    const client = { connections: async () => ({ connections: [] }), rules: async () => ({ rules: [] }), configs: async () => ({ mode }) };
    const guard = new ConnectionGuard({ client, getSettings: () => ({ defaultNode: '', listeners: {}, rulesHash: '' }), saveRulesHash() {} });
    await guard.tick();
    assert.match(guard.status.modeWarning, /direct/);
    mode = 'rule';
    await guard.tick();
    assert.equal(guard.status.modeWarning, '');
    assert.equal(guard.status.active, true);
  });
});

describe('network profiles', () => {
  const base = {
    rules: ['DOMAIN,a.example,DIRECT', 'DOMAIN-SUFFIX,b.example,Proxy', 'IP-CIDR,1.2.3.0/24,AI,no-resolve', 'RULE-SET,set,REJECT', 'MATCH,Final'],
    proxies: [{ name: 'us' }, { name: 'sg' }],
    'proxy-groups': [{ name: 'Proxy' }, { name: 'AI' }, { name: 'Final' }],
    listeners: [{ name: 'mine', port: 1 }, { name: 'sandgate-99', port: 99 }, { name: 'sgp-old', port: 98 }],
    'sub-rules': { mine: ['MATCH,DIRECT'], 'sgp-old': ['MATCH,REJECT'] },
  };
  const custom = (over = {}) => ({ id: 'abc', name: 'c', mode: 'custom', node: '', exits: { Proxy: 'us', Final: 'us' }, extraRules: ['DOMAIN,x.example,DIRECT'], timezone: '', ...over });
  const specOf = (netProfiles, listeners = { 'sgp-abc': 17990, sg: 17991 }) => buildSpec({ netProfiles, gate: { listeners } });

  describe('validation', () => {
    test('accepts both modes and drops empty exits', () => {
      assert.deepEqual(validateNetProfile({ name: 'a', mode: 'custom', exits: { P: 'us', Q: ' ' } }).exits, { P: 'us' });
      assert.equal(validateNetProfile({ name: 'a', mode: 'node', node: 'us' }).node, 'us');
    });

    test('a custom profile must change something', () => {
      assert.throws(() => validateNetProfile({ name: 'a', mode: 'custom' }), /至少/);
    });

    test('rejects malformed or rule-hiding extra rules', () => {
      for (const r of ['nonsense', 'DOMAIN,only-two', 'MATCH,x,DIRECT', 'AND,a,DIRECT', 'DOMAIN,a\nb,DIRECT']) {
        assert.throws(() => validateNetProfile({ name: 'a', mode: 'custom', extraRules: [r] }), ValidationError, r);
      }
    });

    test('a node profile needs a node', () => {
      assert.throws(() => validateNetProfile({ name: 'a', mode: 'node' }), /节点/);
    });
  });

  describe('applying to a config', () => {
    const applied = () => applySpec(structuredClone(base), specOf([custom()]));

    test('replaces only the chosen exits, and extra rules come first', () => {
      assert.deepEqual(applied()['sub-rules']['sgp-abc'], [
        'DOMAIN,x.example,DIRECT',
        'DOMAIN,a.example,DIRECT',
        'DOMAIN-SUFFIX,b.example,us',
        'IP-CIDR,1.2.3.0/24,AI,no-resolve',
        'RULE-SET,set,REJECT',
        'MATCH,us',
      ]);
    });

    test('never changes the main rules', () => {
      assert.deepEqual(applied().rules, base.rules);
    });

    test('keeps the user\'s own entries and drops stale managed ones', () => {
      const c = applied();
      assert.deepEqual(c.listeners.map((l) => l.name), ['mine', 'sgp-abc']);
      assert.deepEqual(Object.keys(c['sub-rules']).sort(), ['mine', 'sgp-abc']);
    });

    test('an unknown target rejects instead of breaking Clash or using another exit', () => {
      const c = applySpec(structuredClone(base), specOf([custom({ exits: { Proxy: 'gone' }, extraRules: ['DOMAIN,x.example,alsogone'] })]));
      assert.ok(c['sub-rules']['sgp-abc'].includes('DOMAIN-SUFFIX,b.example,REJECT'));
      assert.equal(c['sub-rules']['sgp-abc'][0], 'DOMAIN,x.example,REJECT');
    });

    test('reports the targets it could not find', () => {
      const missing = missingTargets(specOf([custom({ exits: { Proxy: 'gone', Final: 'us' }, extraRules: ['DOMAIN,x,alsogone'] })]), { proxies: base.proxies, groups: base['proxy-groups'] });
      assert.deepEqual(missing.sort(), ['alsogone', 'gone']);
    });

    test('a node profile gets a listener with no rules', () => {
      const spec = specOf([{ id: 'n', name: 'n', mode: 'node', node: 'sg', exits: {}, extraRules: [] }]);
      assert.deepEqual(spec.listeners, [{ name: 'sandgate-17991', type: 'mixed', listen: '127.0.0.1', port: 17991, proxy: 'sg' }]);
      assert.deepEqual(spec.subRules, {});
    });

    test('with no profiles it removes everything it managed', () => {
      const c = applySpec(structuredClone(base), { listeners: [], subRules: {} });
      assert.deepEqual(c.listeners.map((l) => l.name), ['mine']);
      assert.deepEqual(Object.keys(c['sub-rules']), ['mine']);
    });
  });

  describe('rewriting the generated YAML', () => {
    const yaml = `mixed-port: 7890
proxies:
- name: us
  type: ss
  server: 1.1.1.1
proxy-groups:
- name: Proxy
  type: select
  proxies:
  - us
- name: 🧭 Final
  type: select
  proxies:
  - us
listeners:
- name: mine
  type: mixed
  port: 1
- name: sandgate-99
  type: mixed
  port: 99
  proxy: us
sub-rules:
  mine:
  - MATCH,DIRECT
  sgp-old:
  - MATCH,REJECT
rules:
- DOMAIN,a.example,DIRECT
- MATCH,🧭 Final
tun:
  enable: true
`;
    const spec = specOf([custom({ exits: { '🧭 Final': 'us' }, extraRules: [] })]);
    const topKeys = (t) => t.split('\n').filter((l) => /^[a-z]/.test(l)).map((l) => l.split(':')[0]);

    test('keeps every other section and has each key once', () => {
      const keys = topKeys(renderRuntimeYaml(yaml, spec));
      assert.deepEqual([...keys].sort(), ['listeners', 'mixed-port', 'proxies', 'proxy-groups', 'rules', 'sub-rules', 'tun']);
      assert.match(renderRuntimeYaml(yaml, spec), /tun:\n {2}enable: true/);
    });

    test('keeps unmanaged entries as written and replaces managed ones', () => {
      const out = renderRuntimeYaml(yaml, spec);
      assert.match(out, /- name: mine\n {2}type: mixed\n {2}port: 1/);
      assert.match(out, / {2}mine:\n {2}- MATCH,DIRECT/);
      assert.doesNotMatch(out, /sandgate-99|sgp-old/);
      assert.match(out, /"name":"sgp-abc".*"rule":"sgp-abc"/);
      assert.ok(out.includes('"MATCH,us"'));
    });

    test('running twice gives the same result', () => {
      const once = renderRuntimeYaml(yaml, spec);
      assert.equal(renderRuntimeYaml(once, spec), once);
    });

    test('with nothing to manage the sections disappear when empty', () => {
      const plain = 'proxies:\n- name: us\n  type: ss\nrules:\n- MATCH,DIRECT\n';
      assert.equal(renderRuntimeYaml(plain, { listeners: [], subRules: {} }), plain);
    });
  });

  describe('the script extension', () => {
    const script = 'function main(config, profileName) {\n  config.x = 1;\n  return config;\n}\n';
    const spec = specOf([custom()]);

    test('runs before the return and gives the same result as here', () => {
      const out = withManagedBlock(script, spec);
      const main = new Function(`${out};return main;`)();
      const expected = applySpec({ ...structuredClone(base), x: 1 }, spec);
      assert.deepEqual(main(structuredClone(base), 'p'), expected);
    });

    test('is plain ES5, since Clash Verge runs it in its own engine', () => {
      const out = withManagedBlock(script, spec);
      const generated = out.slice(out.indexOf('config = ('), out.indexOf('// <<<'));
      assert.doesNotMatch(generated, /=>|\bconst\b|\blet\b|`/);
    });

    test('replaces its own block, and removing it restores the script exactly', () => {
      const once = withManagedBlock(script, spec);
      assert.equal(withManagedBlock(once, spec), once);
      assert.equal(withManagedBlock(once, { listeners: [], subRules: {} }), script);
    });

    test('refuses a script it cannot place the block in', () => {
      assert.throws(() => withManagedBlock('function main(c) { return c; }', spec), /return config/);
    });

    test('finds the current profile\'s script', () => {
      const yaml = 'current: R1\nitems:\n- uid: S1\n  type: script\n  file: S1.js\n- uid: R1\n  type: remote\n  file: R1.yaml\n  option:\n    merge: M1\n    script: S1\n- uid: R2\n  file: R2.yaml\n  option:\n    script: S9\n';
      assert.equal(currentScriptFile(yaml), 'S1.js');
      assert.equal(currentScriptFile('current: X\nitems:\n- uid: X\n  file: x.yaml\n'), null);
    });
  });

  describe('syncing to Clash', () => {
    const VERGE = 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev';
    const setup = ({ reload = async () => ({}) } = {}) => {
      const home = tmp();
      const dir = path.join(home, VERGE);
      fs.mkdirSync(path.join(dir, 'profiles'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'profiles.yaml'), 'current: R\nitems:\n- uid: S\n  file: S.js\n- uid: R\n  file: R.yaml\n  option:\n    script: S\n');
      const scriptFile = path.join(dir, 'profiles/S.js');
      fs.writeFileSync(scriptFile, 'function main(config) {\n  return config;\n}\n');
      fs.writeFileSync(path.join(dir, 'clash-verge.yaml'), 'proxies:\n- name: us\n  type: ss\nrules:\n- MATCH,DIRECT\n');
      const store = new Store(path.join(tmp(), 'data'));
      store.data.netProfiles.push(custom({ exits: { Proxy: 'us' }, extraRules: [] }));
      store.data.gate.listeners['sgp-abc'] = 17990;
      const payloads = [];
      const sync = new ClashSync({ store, home, client: { reload: async (p) => { payloads.push(p); return reload(p); } } });
      return { sync, scriptFile, store, payloads };
    };

    test('updates the script, keeps one backup, and loads the result', async () => {
      const { sync, scriptFile, store, payloads } = setup();
      const original = fs.readFileSync(scriptFile, 'utf8');
      assert.equal((await sync.apply()).state, 'ok');
      assert.match(fs.readFileSync(scriptFile, 'utf8'), /SandGate managed block/);
      assert.match(payloads[0], /"name":"sgp-abc"/);
      await sync.apply();
      assert.equal(fs.readFileSync(path.join(store.dir, 'backups/S.js.before-sandgate'), 'utf8'), original);
    });

    test('a refused config is reported, and says Clash kept the old one', async () => {
      const { sync } = setup({ reload: async () => { throw new Error('bad'); } });
      const status = await sync.apply();
      assert.equal(status.state, 'fail');
      assert.match(status.message, /仍在使用原来的配置/);
    });

    test('warns about an exit Clash no longer has', async () => {
      const { sync, store } = setup();
      store.data.netProfiles[0].exits = { Proxy: 'gone' };
      const status = await sync.apply();
      assert.equal(status.state, 'warn');
      assert.match(status.message, /gone/);
    });

    test('still reloads when the script cannot be updated, and says what that means', async () => {
      const { sync, scriptFile, payloads } = setup();
      fs.writeFileSync(scriptFile, 'function main(c) { return c; }');
      const status = await sync.apply();
      assert.equal(status.state, 'warn');
      assert.match(status.message, /改动会丢失/);
      assert.equal(payloads.length, 1);
    });

    describe('Clash Verge\'s generated config', () => {
      const prepared = async () => {
        const r = setup();
        await r.sync.apply(); // writes the managed block into the script
        const generated = path.join(r.sync.vergeDir, 'clash-verge.yaml');
        const at = (file, seconds) => fs.utimesSync(file, seconds, seconds);
        return { ...r, generated, at };
      };

      test('waiting: the script is newer, so the next generation brings them', async () => {
        const { sync, generated, scriptFile, at } = await prepared();
        at(generated, 1000);
        at(scriptFile, 2000);
        const s = sync.generatedStatus();
        assert.equal(s.state, 'pending');
        assert.deepEqual(s.missing, ['sgp-abc']);
      });

      test('broken: generated from this script, and still missing', async () => {
        const { sync, generated, scriptFile, at } = await prepared();
        at(scriptFile, 1000);
        at(generated, 2000);
        assert.equal(sync.generatedStatus().state, 'broken');
      });

      test('no script: the next generation would drop them, however new the script is', async () => {
        const { sync, generated, scriptFile, at } = await prepared();
        fs.writeFileSync(scriptFile, 'function main(config) {\n  return config;\n}\n');
        at(generated, 1000);
        at(scriptFile, 2000);
        assert.equal(sync.generatedStatus().state, 'no-script');
      });

      test('a missing script extension counts as no script', async () => {
        const { sync, generated } = await prepared();
        fs.writeFileSync(path.join(sync.vergeDir, 'profiles.yaml'), 'current: R\nitems:\n- uid: R\n  file: R.yaml\n');
        assert.equal(fs.existsSync(generated), true);
        assert.equal(sync.generatedStatus().state, 'no-script');
      });

      test('ok: present, whatever the times say', async () => {
        const { sync, generated, scriptFile, at } = await prepared();
        fs.writeFileSync(generated, `${fs.readFileSync(generated, 'utf8')}listeners:\n- name: sgp-abc\n  type: mixed\n  port: 17990\n  rule: sgp-abc\n`);
        at(generated, 1000);
        at(scriptFile, 2000);
        const s = sync.generatedStatus();
        assert.equal(s.state, 'ok');
        assert.deepEqual(s.missing, []);
      });
    });

    test('does nothing when disabled, so tests never touch a real Clash', async () => {
      const { store, payloads } = setup();
      const sync = new ClashSync({ store, client: { reload: async (p) => payloads.push(p) }, enabled: false });
      await sync.apply();
      assert.equal(payloads.length, 0);
    });
  });

  describe('instances', () => {
    const sb = { port: 17900, sandgateDir: '/Users/t/.sandgate', instancesDir: '/Users/t/.sandgate-instances', instanceHome: '/Users/t/.sandgate-instances/abc', home: '/Users/t', tempDir: '/nonexistent/T' };
    const inst = (over) => validateApp({ name: 'x', command: '/bin/ls', ...over });

    test('following rules leaves the network open and sets no proxy', () => {
      const a = inst({ network: 'open' });
      assert.doesNotMatch(buildProfile(a, { ...sb, port: null }), /deny network\*\)/);
      assert.equal(buildEnv(a, null, { HOME: '/Users/t' }, '/inst').HTTP_PROXY, undefined);
    });

    test('a rules instance keeps DNS and sockets working, and gets the proxy', () => {
      const a = inst({ network: 'rules', node: 'sgp-abc' });
      const p = buildProfile(a, sb);
      assert.doesNotMatch(p, /mDNSResponder/);
      assert.doesNotMatch(p, /deny network\*\)/);
      assert.equal(buildEnv(a, 17900, { HOME: '/Users/t' }, '/inst').HTTP_PROXY, 'http://127.0.0.1:17900');
    });

    test('files stay isolated in every network mode', () => {
      for (const network of ['open', 'rules']) {
        const p = buildProfile(inst({ network, node: network === 'rules' ? 'sgp-abc' : '' }), sb);
        assert.ok(p.includes('(deny file-read* file-write* (subpath "/Users/t"))'), network);
        assert.ok(p.includes('(deny file-read* file-write* (subpath "/Users/t/.ssh"))'), network);
      }
    });

    test('the Clash control socket stays blocked with the network open', () => {
      const p = buildProfile(inst({ network: 'open' }), { ...sb, port: null, controllerSocket: '/tmp/c.sock' });
      assert.match(p, /deny network\* \(literal "[^"]*c\.sock"\)/);
    });

    test('a whole-node instance is still locked to its port', () => {
      assert.match(buildProfile(inst({ network: 'gate', node: 'us' }), sb), /\(deny network\*\)\n\(allow network-outbound \(remote ip "localhost:17900"\)\)/);
    });

    test('a saved whole-node instance becomes a profile with the same behavior', () => {
      const dir = tmp();
      fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({
        gate: { listeners: { us: 17891 } },
        apps: [
          { id: 'a', name: 'a', command: '/bin/ls', args: [], network: 'gate', node: 'us', port: 17890 },
          { id: 'b', name: 'b', command: '/bin/ls', args: [], network: 'gate', node: 'us', port: 17892 },
          { id: 'c', name: 'c', command: '/bin/ls', args: [], network: 'none' },
        ],
      }));
      const { data } = new Store(dir);
      assert.equal(data.netProfiles.length, 1);
      assert.equal(data.netProfiles[0].node, 'us');
      assert.equal(data.apps[0].netProfile, data.netProfiles[0].id);
      assert.equal(data.apps[1].netProfile, data.netProfiles[0].id);
      assert.equal(data.apps[0].network, 'gate');
      assert.equal(data.apps[2].netProfile, 'none');
      assert.equal(new Store(dir).data.netProfiles[0].id, data.netProfiles[0].id, 'stable after a restart');
    });

    test('pf allows what a rules profile can dial, not its internal key', () => {
      const store = new Store(path.join(tmp(), 'data'));
      store.data.netProfiles.push(custom({ exits: { Proxy: 'us' }, extraRules: ['DOMAIN,x,sg', 'DOMAIN,y,DIRECT'] }));
      store.data.apps.push(inst({ network: 'rules', node: 'sgp-abc', netProfile: 'abc' }), inst({ network: 'gate', node: 'jp' }), inst({ network: 'open' }));
      assert.deepEqual(store.instanceTargets().sort(), ['DIRECT', 'jp', 'sg', 'us'].sort());
      assert.deepEqual(store.usedNodes().sort(), ['jp', 'sgp-abc']);
    });

    test('a rules gate checks only that the entry and TUN are up', () => {
      const ids = buildChecks({ ...structuredClone(DEFAULT_SETTINGS.gate), listeners: { 'sgp-abc': 1 }, exitIps: { 'sgp-abc': '1.1.1.1' } }, {}, 'sgp-abc').map((c) => c.id);
      assert.deepEqual(ids, ['upstream', 'route', 'tun']);
    });

    test('the guard never judges a profile listener by a single node', () => {
      const conn = { id: '1', chains: ['other'], metadata: { inboundName: 'sgp-abc' } };
      assert.deepEqual(findViolations([conn], { defaultNode: 'us', listeners: {} }), []);
    });
  });
});

describe('waking from sleep', () => {
  const setup = (run) => {
    let t = 1000;
    const mon = new GateMonitor({ checks: [{ id: 'c', label: 'C', intervalMs: 1000, timeoutMs: 1000, run }], stableMs: 10, tickMs: 500, now: () => t });
    return { mon, advance: (ms) => { t += ms; } };
  };
  const settle = () => new Promise((r) => setTimeout(r, 10));

  test('a long gap does not close the gate, and every check runs again', async () => {
    let runs = 0;
    const { mon, advance } = setup(async () => { runs++; return 'ok'; });
    const closed = [];
    mon.on('close', (r) => closed.push(r));
    mon.tick();
    await settle();
    advance(20);
    mon.tick();
    assert.equal(mon.open, true);
    const before = runs;
    advance(3600000);
    mon.tick();
    assert.equal(mon.open, true);
    assert.deepEqual(closed, []);
    await settle();
    assert.ok(runs > before);
  });

  test('a check that really fails after waking still closes the gate', async () => {
    let ok = true;
    const { mon, advance } = setup(async () => { if (!ok) throw new Error('down'); return 'ok'; });
    mon.tick();
    await settle();
    advance(20);
    mon.tick();
    assert.equal(mon.open, true);
    ok = false;
    advance(3600000);
    mon.tick();
    await settle();
    assert.equal(mon.open, false);
    assert.match(mon.snapshot().reason, /down/);
  });

  test('a stale result is described as stale, not as the old success', async () => {
    const { mon, advance } = setup(async () => 'looks fine');
    mon.tick();
    await settle();
    advance(20);
    mon.tick();
    const reasons = [];
    mon.on('close', (r) => reasons.push(r));
    mon.checks[0].running = true; // a hung check: it never reports again
    for (let i = 0; i < 8; i++) { advance(1000); mon.tick(); }
    assert.equal(mon.open, false);
    assert.match(reasons[0], /已过期/);
  });
});

describe('grouping instances on the page', () => {
  const inst = (name, command, netProfile, extra = {}) => ({ name, command, netProfile, network: 'gate', running: false, ...extra });
  const profiles = [{ id: 'p1', name: '美国' }, { id: 'p2', name: '新加坡' }];
  const apps = [
    inst('n', '/bin/ls', 'none'),
    inst('b', '/Applications/Google Chrome.app', 'p2', { running: true }),
    inst('a', '/usr/bin/curl', 'p1'),
    inst('c', '/Applications/Google Chrome.app', 'p1'),
    inst('f', '/usr/bin/curl', 'follow'),
  ];

  test('by profile: follow first, no network last, profiles in their own order', () => {
    const groups = groupApps(apps, 'profile', profiles);
    assert.deepEqual(groups.map((g) => g.title), ['跟随 Clash 规则', '美国', '新加坡', '完全禁网']);
    assert.deepEqual(groups[1].apps.map((a) => a.name), ['a', 'c']);
    assert.equal(groups[2].running, 1);
  });

  test('by application: same program together, whatever its profile', () => {
    const groups = groupApps(apps, 'app', profiles);
    assert.deepEqual(groups.map((g) => g.title), ['curl', 'Google Chrome', 'ls']);
    assert.deepEqual(groups[1].apps.map((a) => a.name), ['b', 'c']);
    assert.equal(groups[1].detail, '/Applications/Google Chrome.app');
  });

  test('programs with the same name in different folders stay apart', () => {
    const groups = groupApps([inst('x', '/a/tool', 'none'), inst('y', '/b/tool', 'none')], 'app');
    assert.deepEqual(groups.map((g) => g.detail), ['/a/tool', '/b/tool']);
  });

  test('empty profiles do not appear, and an unknown profile still shows its instance', () => {
    const groups = groupApps([inst('x', '/bin/ls', 'gone')], 'profile', profiles);
    assert.deepEqual(groups.map((g) => g.title), ['gone']);
  });

  test('names programs without their path or .app', () => {
    assert.equal(appLabel('/Applications/Visual Studio Code.app'), 'Visual Studio Code');
    assert.equal(appLabel('/Applications/Foo.app/'), 'Foo');
    assert.equal(appLabel('/usr/bin/curl'), 'curl');
  });
});

describe('instances outlive a SandGate restart', () => {
  const setup = (t) => {
    const dir = tmp();
    const fake = path.join(dir, 'fake-sandbox-exec');
    fs.writeFileSync(fake, '#!/bin/sh\nshift 2\nexec "$@"\n', { mode: 0o755 });
    const store = new Store(path.join(dir, 'data'));
    const starts = new Map();
    const processStart = async (pid) => starts.get(pid) ?? `started-${pid}`;
    const manager = (over = {}) => new AppManager({ store, gates: { on() {}, isOpen: () => false }, controllerSocket: () => '', sandboxExec: fake, processStart, watchMs: 40, ...over });
    const add = (script, over = {}) => {
      const a = { ...validateApp({ name: 'x', command: '/bin/sh', args: ['-c', script], network: 'none', isolateHome: false }), ...over };
      store.data.apps.push(a);
      return a;
    };
    const pids = [];
    t.after(() => { for (const p of pids) { try { process.kill(-p, 'SIGKILL'); } catch { /* gone */ } } });
    return { store, manager, add, starts, pids, logOf: (a) => fs.readFileSync(path.join(store.logDir, `${a.id}.log`), 'utf8') };
  };
  const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
  const until = async (fn, ms = 4000) => { const s = Date.now(); while (!fn() && Date.now() - s < ms) await sleep(20); return fn(); };
  const LONG = 'echo hello; exec sleep 60';

  test('releasing leaves it running, and the next manager adopts and can stop it', async (t) => {
    const { manager, add, pids, logOf } = setup(t);
    const a = add(LONG);
    const first = manager();
    await first.start(a.id);
    const { pid } = first.snapshot(a);
    pids.push(pid);
    await until(() => logOf(a).includes('hello'));
    await first.release();
    assert.equal(alive(pid), true, 'release must not stop instances');

    const second = manager();
    await second.adopt();
    assert.equal(second.isRunning(a.id), true);
    assert.equal(second.snapshot(a).pid, pid);
    await second.stop(a.id);
    assert.equal(await until(() => !alive(pid)), true);
    assert.equal(second.isRunning(a.id), false);
    assert.equal(second.snapshot(a).lastExit.unknown, true);
    await second.release();
  });

  test('it keeps logging with nobody holding a pipe', async (t) => {
    const { manager, add, pids, logOf } = setup(t);
    const a = add('sleep 0.3; echo after-release; exec sleep 60');
    const m = manager();
    await m.start(a.id);
    pids.push(m.snapshot(a).pid);
    await m.release();
    assert.equal(await until(() => logOf(a).includes('after-release')), true);
  });

  test('an adopted instance that exits is noticed', async (t) => {
    const { manager, add, pids } = setup(t);
    const a = add(LONG);
    const first = manager();
    await first.start(a.id);
    const { pid } = first.snapshot(a);
    pids.push(pid);
    await first.release();
    const second = manager();
    await second.adopt();
    process.kill(-pid, 'SIGKILL');
    assert.equal(await until(() => !second.isRunning(a.id)), true);
    assert.equal(second.snapshot(a).lastExit.unknown, true);
    await second.release();
  });

  test('a reused process id is not adopted, and is left alone', async (t) => {
    const { manager, add, pids, starts } = setup(t);
    const a = add(LONG);
    const first = manager();
    await first.start(a.id);
    const { pid } = first.snapshot(a);
    pids.push(pid);
    await first.release();
    starts.set(pid, 'some other process');
    const second = manager();
    await second.adopt();
    assert.equal(second.isRunning(a.id), false);
    assert.equal(alive(pid), true);
    await second.release();
  });

  test('a recorded instance that died meanwhile just shows as stopped', async (t) => {
    const { manager, add, store } = setup(t);
    const a = add(LONG);
    const dead = execFileSync('/bin/sh', ['-c', 'sh -c "exit 0" & echo $!'], { encoding: 'utf8' }).trim();
    await until(() => !alive(Number(dead)));
    fs.writeFileSync(path.join(store.dir, 'runs.json'), JSON.stringify({ [a.id]: { pid: Number(dead), startedAt: 1, started: `started-${dead}` } }));
    const m = manager();
    await m.adopt();
    assert.equal(m.isRunning(a.id), false);
    assert.equal(m.snapshot(a).lastExit.unknown, true);
    await m.release();
  });

  test('its own child still reports a real exit code', async (t) => {
    const { manager, add } = setup(t);
    const a = add('exit 3');
    const m = manager();
    await m.start(a.id);
    assert.equal(await until(() => !m.isRunning(a.id)), true);
    assert.equal(m.snapshot(a).lastExit.code, 3);
    await m.release();
  });

  test('stopAll still stops everything, and leaves nothing to adopt', async (t) => {
    const { manager, add, pids } = setup(t);
    const a = add(LONG);
    const m = manager();
    await m.start(a.id);
    const { pid } = m.snapshot(a);
    pids.push(pid);
    await m.stopAll();
    assert.equal(await until(() => !alive(pid)), true);
    const next = manager();
    await next.adopt();
    assert.equal(next.isRunning(a.id), false);
    await next.release();
  });

  test('a gate port comes back on the same port', async (t) => {
    const { manager, add, pids } = setup(t);
    const srv = net.createServer();
    const port = await listen(srv);
    await new Promise((r) => srv.close(r));
    const a = add(LONG, { network: 'gate', node: 'n', port });
    const first = manager();
    await first.start(a.id);
    pids.push(first.snapshot(a).pid);
    await first.release();
    const second = manager();
    await second.adopt();
    const connected = await new Promise((resolve) => {
      const c = net.connect(port, '127.0.0.1', () => { c.destroy(); resolve(true); });
      c.on('error', () => resolve(false));
    });
    assert.equal(connected, true);
    await second.release();
  });

  test('long logs are capped without stopping the instance', async (t) => {
    const { manager, add, pids, logOf, store } = setup(t);
    const a = add('i=0; while [ $i -lt 400 ]; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; i=$((i+1)); done; exec sleep 60');
    const m = manager({ logLimit: 500 });
    await m.start(a.id);
    const { pid } = m.snapshot(a);
    pids.push(pid);
    assert.equal(await until(() => fs.existsSync(path.join(store.logDir, `${a.id}.log.old`))), true);
    assert.ok(logOf(a).length < 20000);
    assert.equal(alive(pid), true);
    await m.release();
  });

  test('removing the service stops recorded instances, but not a reused process id', async (t) => {
    const { manager, add, pids, starts, store } = setup(t);
    const a = add(LONG);
    const b = add(LONG);
    const m = manager();
    await m.start(a.id);
    await m.start(b.id);
    const pa = m.snapshot(a).pid;
    const pb = m.snapshot(b).pid;
    pids.push(pa, pb);
    await m.release();
    starts.set(pb, 'some other process');
    const processStart = async (pid) => starts.get(pid) ?? `started-${pid}`;
    assert.equal(await stopRecordedInstances(store, { processStart }), 1);
    assert.equal(await until(() => !alive(pa)), true);
    assert.equal(alive(pb), true);
    assert.equal(fs.existsSync(path.join(store.dir, 'runs.json')), false);
  });

  test('the service keeps launchd from cleaning up its instances', () => {
    const plist = buildPlist({ node: '/n', entry: '/a/bin/x.js', logFile: '/l', home: '/h' });
    assert.match(plist, /<key>AbandonProcessGroup<\/key><true\/>/);
  });
});

describe('running without the sandbox', () => {
  const base = { name: 'x', command: '/bin/sh', node: 'n' };

  test('is off by default, and an edit keeps the choice', () => {
    const a = validateApp(base);
    assert.equal(a.unsandboxed, false);
    assert.equal(a.isolateHome, true);
    const on = validateApp({ ...base, unsandboxed: true });
    assert.equal(on.unsandboxed, true);
    assert.equal(validateApp(base, on).unsandboxed, true);
  });

  test('uses the real home, since a moved one would hide the keychain', () => {
    const a = validateApp({ ...base, unsandboxed: true, isolateHome: true });
    assert.equal(a.isolateHome, false);
    assert.equal(buildEnv(a, 1, { HOME: '/Users/t' }, '/inst').HOME, '/Users/t');
  });

  test('refuses to look like it blocks the network', () => {
    assert.throws(() => validateApp({ name: 'x', command: '/bin/sh', network: 'none', unsandboxed: true }), /无法禁止联网/);
  });

  test('never drops both layers: sandbox-only flags go when the sandbox goes', () => {
    const args = ['--user-data-dir={data}/p', '--no-sandbox', '--use-mock-keychain', '--lang=en-US'];
    assert.deepEqual(instanceArgs({ args, port: 1, unsandboxed: true }), ['--user-data-dir={data}/p', '--lang=en-US']);
    assert.deepEqual(instanceArgs({ args, port: 1, unsandboxed: false }), args);
  });

  test('still drops the proxy flag when following Clash', () => {
    assert.deepEqual(instanceArgs({ args: ['--proxy-server=x:{port}', '--a'], port: null, unsandboxed: true }), ['--a']);
  });

  test('runs without sandbox-exec, is adopted, and can be stopped', async (t) => {
    const dir = tmp();
    const store = new Store(path.join(dir, 'data'));
    const processStart = async (pid) => `started-${pid}`;
    const manager = () => new AppManager({ store, gates: { on() {}, isOpen: () => false }, controllerSocket: () => '', sandboxExec: '/nonexistent/sandbox-exec', processStart, watchMs: 40 });
    const a = validateApp({ name: 'x', command: '/bin/sh', network: 'open', unsandboxed: true, args: ['-c', 'echo "args:$*"; echo "home:$HOME"; exec sleep 60', 'sh', '--no-sandbox', '--keep', '--use-mock-keychain'] });
    store.data.apps.push(a);
    const first = manager();
    await first.start(a.id);
    const { pid } = first.snapshot(a);
    t.after(() => { try { process.kill(-pid, 'SIGKILL'); } catch { /* gone */ } });
    const log = () => fs.readFileSync(path.join(store.logDir, `${a.id}.log`), 'utf8');
    for (let i = 0; i < 100 && !log().includes('home:'); i++) await sleep(20);
    assert.match(log(), /args:--keep\n/);
    assert.ok(log().includes(`home:${process.env.HOME}`));
    assert.match(first.profileFor(a), /不套沙盒/);
    await first.release();
    const second = manager();
    await second.adopt();
    assert.equal(second.snapshot(a).pid, pid);
    await second.stopAll();
  });

  test('the self-test says there is nothing to escape from', async () => {
    const store = new Store(path.join(tmp(), 'data'));
    const a = validateApp({ name: 'x', command: '/bin/sh', network: 'open', unsandboxed: true });
    store.data.apps.push(a);
    const m = new AppManager({ store, gates: { on() {}, isOpen: () => false }, controllerSocket: () => '', sandboxExec: '/nonexistent/sandbox-exec' });
    const r = await m.verify(a.id);
    assert.deepEqual(r.results.map((x) => x.id), ['unsandboxed']);
    await m.release();
  });

  test('instances saved before this option stay sandboxed', () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ apps: [{ id: 'a', name: 'a', command: '/bin/ls', args: [], network: 'none' }] }));
    assert.equal(new Store(dir).data.apps[0].unsandboxed, false);
  });
});

describe('service priority', () => {
  // Instances inherit the job's class. Background held Chrome at 12 fps, against 122 with Interactive.
  test('runs as Interactive, since instances inherit its class', () => {
    const source = fs.readFileSync(path.join(import.meta.dirname, '../src/service.js'), 'utf8');
    assert.match(source, /<key>ProcessType<\/key><string>Interactive<\/string>/);
  });
});

describe('leak self-test', () => {
  test('nscurl counts as blocked only with a failure message, since it always exits 0', () => {
    const denied = 'Load failed with error: Error Domain=NSPOSIXErrorDomain Code=1 "Operation not permitted"';
    assert.equal(nscurlBlocked(0, denied), true);
    assert.equal(nscurlBlocked(0, ''), false, 'a successful load prints nothing on stderr');
    assert.equal(nscurlBlocked(0, 'some new error format'), false, 'an unknown format raises an alarm');
    assert.equal(nscurlBlocked(71, ''), true);
  });
});
