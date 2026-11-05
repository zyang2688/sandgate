import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { GatePort } from './gateport.js';
import { buildEnv, buildProfile, expandVars } from './profile.js';

const exec = promisify(execFile);
const NSCURL = '/usr/bin/nscurl';

/**
 * nscurl exits 0 even when the load fails and reports the failure only on stderr.
 * Anything without that message counts as a leak, so an unknown format raises an alarm.
 */
export function nscurlBlocked(code, stderr) {
  return code !== 0 || stderr.includes('Load failed');
}
const SANDBOX_EXEC = '/usr/bin/sandbox-exec';
const usesPort = (app) => ['gate', 'rules'].includes(app.network);
const LOG_LIMIT = 10 * 1024 * 1024;
const TAIL_BYTES = 64 * 1024;

/** `/Applications/Foo.app` → the executable inside, since a bundle cannot be exec'd. */
export async function resolveCommand(command) {
  if (!command.endsWith('.app')) return command;
  const plist = path.join(command, 'Contents/Info.plist');
  const { stdout } = await exec('/usr/bin/plutil', ['-extract', 'CFBundleExecutable', 'raw', plist]);
  return path.join(command, 'Contents/MacOS', stdout.trim());
}

class LogFile {
  constructor(file) {
    this.file = file;
    this.#open();
  }

  #open() {
    this.size = fs.existsSync(this.file) ? fs.statSync(this.file).size : 0;
    if (this.size > LOG_LIMIT) this.#rotate();
    this.fd = fs.openSync(this.file, 'a', 0o600);
  }

  #rotate() {
    if (this.fd !== undefined) fs.closeSync(this.fd);
    fs.renameSync(this.file, `${this.file}.old`);
    this.fd = fs.openSync(this.file, 'a', 0o600);
    this.size = 0;
  }

  write(data) {
    if (this.fd === undefined) return;
    if (this.size + data.length > LOG_LIMIT) this.#rotate();
    fs.writeSync(this.fd, data);
    this.size += data.length;
  }

  close() {
    if (this.fd !== undefined) fs.closeSync(this.fd);
    this.fd = undefined;
  }
}

export class AppManager {
  constructor({ store, gates, controllerSocket }) {
    this.store = store;
    this.gates = gates;
    this.controllerSocket = controllerSocket;
    this.runs = new Map();
    this.ports = new Map();
    this.lastExit = new Map();
    gates.on('close', (node) => {
      for (const [id, gp] of this.ports) {
        if (this.find(id)?.node === node) gp.dropAll();
      }
    });
  }

  find(id) { return this.store.data.apps.find((a) => a.id === id); }
  isRunning(id) { return this.runs.has(id); }

  profileFor(app) {
    return buildProfile(app, {
      port: app.port,
      sandgateDir: this.store.dir,
      instancesDir: this.store.instancesDir,
      instanceHome: this.store.instanceHome(app.id),
      controllerSocket: this.controllerSocket(),
    });
  }

  #writeProfile(app) {
    const file = path.join(this.store.profileDir, `${app.id}.sb`);
    fs.writeFileSync(file, this.profileFor(app), { mode: 0o600 });
    return file;
  }

  async #ensurePort(app) {
    if (!usesPort(app) || this.ports.has(app.id)) return;
    const { id } = app;
    // Both read live state, so changing a stopped instance's node takes effect here.
    const gp = new GatePort({
      port: app.port,
      isOpen: () => this.gates.isOpen(this.find(id)?.node),
      upstreamPort: () => this.store.data.gate.listeners[this.find(id)?.node],
    });
    await gp.listen();
    this.ports.set(id, gp);
  }

  async start(id) {
    const app = this.find(id);
    if (!app) throw new Error('应用不存在');
    if (this.runs.has(id)) throw new Error('应用已在运行');
    await this.#ensurePort(app);
    const profile = this.#writeProfile(app);
    const command = await resolveCommand(app.command);
    const home = this.store.instanceHome(id);
    this.#prepareDataDir(app);
    const vars = { port: app.port, home: app.isolateHome ? home : process.env.HOME, data: home };
    // An instance following Clash's rules has no port, so a preset's proxy flag does not apply.
    const args = app.args.filter((a) => app.port || !a.includes('{port}')).map((a) => expandVars(a, vars));
    const log = new LogFile(path.join(this.store.logDir, `${id}.log`));
    log.write(Buffer.from(`\n=== ${new Date().toISOString()} start ${command} ===\n`));

    const child = spawn(SANDBOX_EXEC, ['-f', profile, command, ...args], {
      cwd: app.cwd || (app.isolateHome ? home : undefined),
      env: buildEnv(app, app.port, process.env, home),
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true, // own process group, so stop reaches every descendant
    });
    const run = { child, startedAt: Date.now(), log };
    this.runs.set(id, run);
    child.stdout.on('data', (d) => log.write(d));
    child.stderr.on('data', (d) => log.write(d));
    child.once('error', (e) => log.write(Buffer.from(`[sandgate] 启动失败: ${e.message}\n`)));
    child.once('close', (code, signal) => {
      clearTimeout(run.killTimer);
      this.runs.delete(id);
      log.write(Buffer.from(`=== exit code=${code} signal=${signal} ===\n`));
      log.close();
      this.lastExit.set(id, { code, signal, at: Date.now() });
    });
  }

  stop(id) {
    const run = this.runs.get(id);
    if (!run) return Promise.resolve();
    return new Promise((resolve) => {
      run.child.once('close', () => resolve());
      this.#signal(run, 'SIGTERM');
      run.killTimer = setTimeout(() => this.#signal(run, 'SIGKILL'), 5000);
    });
  }

  #signal(run, sig) {
    try { process.kill(-run.child.pid, sig); } catch { /* already gone */ }
  }

  /** A shared-data instance gets a directory only if it asks for one through {data}. */
  #prepareDataDir(app) {
    const home = this.store.instanceHome(app.id);
    const usesData = [...app.args, ...Object.values(app.env)].some((v) => v.includes('{data}'));
    if (app.isolateHome || usesData) fs.mkdirSync(home, { recursive: true, mode: 0o700 });
    if (app.isolateHome) fs.mkdirSync(path.join(home, 'tmp'), { recursive: true, mode: 0o700 });
  }

  /** Removes the definition along with the instance's data directory. */
  async remove(id) {
    if (this.runs.has(id)) throw new Error('请先停止应用');
    await this.releasePort(id);
    const apps = this.store.data.apps;
    const i = apps.findIndex((a) => a.id === id);
    if (i < 0) throw new Error('应用不存在');
    apps.splice(i, 1);
    this.store.save();
    fs.rmSync(path.join(this.store.profileDir, `${id}.sb`), { force: true });
    try {
      fs.rmSync(this.store.instanceHome(id), { recursive: true, force: true });
    } catch (e) {
      throw new Error(`实例已删除，但数据目录没能删除：${e.message}`);
    }
  }

  /** Ends an instance's current connections; its next ones use the latest rules. */
  dropConnections(id) {
    this.ports.get(id)?.dropAll();
  }

  async releasePort(id) {
    const gp = this.ports.get(id);
    if (gp) {
      this.ports.delete(id);
      await gp.close();
    }
  }

  tail(id) {
    const file = path.join(this.store.logDir, `${id}.log`);
    if (!fs.existsSync(file)) return '';
    const { size } = fs.statSync(file);
    const len = Math.min(size, TAIL_BYTES);
    const buf = Buffer.alloc(len);
    const fd = fs.openSync(file, 'r');
    try { fs.readSync(fd, buf, 0, len, size - len); } finally { fs.closeSync(fd); }
    return buf.toString('utf8');
  }

  /**
   * Attempts real escapes from inside this instance's profile. Most probes pass by
   * *failing*, so the profile must first be shown to apply: otherwise a broken
   * sandbox-exec (exit 71) would report every denial as a pass.
   */
  async verify(id) {
    const app = this.find(id);
    if (!app) throw new Error('应用不存在');
    await this.#ensurePort(app);
    const profile = this.#writeProfile(app);
    const gateOpen = this.gates.isOpen(app.node);
    this.#prepareDataDir(app);
    const writeProbe = path.join(os.homedir(), `.sandgate-probe-${id}`);
    const runInBox = async (cmd, ...args) => {
      try {
        const { stderr } = await exec(SANDBOX_EXEC, ['-f', profile, cmd, ...args], { timeout: 15000, env: buildEnv({ ...app, network: 'none', isolateHome: false, env: {} }, null) });
        return { code: 0, stderr };
      } catch (e) {
        return { code: typeof e.code === 'number' ? e.code : -1, stderr: String(e.stderr ?? '') };
      }
    };
    const inBox = async (cmd, ...args) => (await runInBox(cmd, ...args)).code;

    const applied = await inBox('/usr/bin/true');
    if (applied !== 0) {
      return { ok: false, gateOpen, results: [{
        id: 'applied', label: '沙盒配置能否加载', ok: false,
        detail: `sandbox-exec 退出码 ${applied}。退出码 71 表示已在另一层沙盒内运行；请从普通终端启动 SandGate。`,
      }] };
    }

    const curl = ['-s', '-o', '/dev/null', '--max-time', '5'];
    // Instances following rules reach the network on purpose, so only their files are tested.
    const pinned = !['open', 'rules'].includes(app.network);
    const denials = [
      ...(pinned ? [
        ['direct-ip', '直连公网 IP', '/usr/bin/curl', ...curl, '--noproxy', '*', 'https://223.5.5.5'],
        ['direct-dns', '直连域名（含本地 DNS）', '/usr/bin/curl', ...curl, '--noproxy', '*', 'https://www.baidu.com'],
        ['udp', 'UDP 发往 223.5.5.5:53', '/usr/bin/nc', '-u', '-z', '-w', '2', '223.5.5.5', '53'],
        ['broker', '系统网络框架 (nscurl)', NSCURL, 'https://www.apple.com'],
      ] : []),
      ['token', '读取 SandGate 令牌', '/bin/cat', this.store.tokenPath],
      ['peers', '列出其他实例的目录', '/bin/ls', this.store.instancesDir],
    ];
    if (app.isolateHome) {
      denials.push(
        ['real-home', '读取真实用户目录', '/bin/ls', os.homedir()],
        ['real-home-write', '写入真实用户目录', '/usr/bin/touch', writeProbe],
      );
    }
    const listener = this.store.data.gate.listeners[app.node];
    if (listener && pinned) {
      denials.push(['listener', `绕过闸门直连 listener ${listener}`, '/usr/bin/curl', ...curl, '-x', `http://127.0.0.1:${listener}`, 'http://cp.cloudflare.com/generate_204']);
    }
    const results = [{ id: 'applied', label: '沙盒配置能否加载', ok: true, detail: '已加载' }];
    for (const [pid, label, cmd, ...args] of denials) {
      const { code, stderr } = await runInBox(cmd, ...args);
      const blocked = cmd === NSCURL ? nscurlBlocked(code, stderr) : code !== 0;
      results.push({ id: pid, label, ok: blocked, detail: blocked ? `已拦截 (退出码 ${code})` : '泄漏：操作成功了' });
    }
    fs.rmSync(writeProbe, { force: true });
    if (usesPort(app)) {
      const code = await inBox('/usr/bin/curl', ...curl, '-x', `http://127.0.0.1:${app.port}`, 'http://cp.cloudflare.com/generate_204');
      results.push({
        id: 'via-gate',
        label: gateOpen ? '经闸门访问（闸门开，应成功）' : '经闸门访问（闸门关，应失败）',
        ok: gateOpen ? code === 0 : code !== 0,
        detail: code === 0 ? '请求成功' : `请求失败 (退出码 ${code})`,
      });
    }
    return { ok: results.every((r) => r.ok), gateOpen, results };
  }

  snapshot(app) {
    const run = this.runs.get(app.id);
    const gp = this.ports.get(app.id);
    return {
      ...app,
      running: Boolean(run),
      pid: run?.child.pid ?? null,
      startedAt: run?.startedAt ?? null,
      lastExit: this.lastExit.get(app.id) ?? null,
      gateOpen: this.gates.isOpen(app.node),
      conns: gp?.active ?? 0,
      stats: gp?.stats ?? { up: 0, down: 0, accepted: 0, refused: 0 },
    };
  }

  async stopAll() {
    await Promise.all([...this.runs.keys()].map((id) => this.stop(id)));
    await Promise.all([...this.ports.keys()].map((id) => this.releasePort(id)));
  }
}
