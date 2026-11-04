import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { GatePort } from './gateport.js';
import { buildEnv, buildProfile, expandVars } from './profile.js';

const exec = promisify(execFile);
const SANDBOX_EXEC = '/usr/bin/sandbox-exec';
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
    if (app.network !== 'gate' || this.ports.has(app.id)) return;
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
    if (app.isolateHome) fs.mkdirSync(home, { recursive: true, mode: 0o700 });
    const vars = { port: app.port, home: app.isolateHome ? home : process.env.HOME };
    const args = app.args.map((a) => expandVars(a, vars));
    const log = new LogFile(path.join(this.store.logDir, `${id}.log`));
    log.write(Buffer.from(`\n=== ${new Date().toISOString()} start ${command} ===\n`));

    const child = spawn(SANDBOX_EXEC, ['-f', profile, command, ...args], {
      cwd: app.cwd || undefined,
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

  /** Removes the definition. The instance's data directory is left for the user to delete. */
  async remove(id) {
    if (this.runs.has(id)) throw new Error('请先停止应用');
    await this.releasePort(id);
    const apps = this.store.data.apps;
    const i = apps.findIndex((a) => a.id === id);
    if (i < 0) throw new Error('应用不存在');
    apps.splice(i, 1);
    this.store.save();
    fs.rmSync(path.join(this.store.profileDir, `${id}.sb`), { force: true });
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
    const inBox = async (cmd, ...args) => {
      try {
        await exec(SANDBOX_EXEC, ['-f', profile, cmd, ...args], { timeout: 15000, env: buildEnv({ ...app, network: 'none', isolateHome: false, env: {} }, null) });
        return 0;
      } catch (e) {
        return typeof e.code === 'number' ? e.code : -1;
      }
    };

    const applied = await inBox('/usr/bin/true');
    if (applied !== 0) {
      return { ok: false, gateOpen, results: [{
        id: 'applied', label: '沙盒配置能否加载', ok: false,
        detail: `sandbox-exec 退出码 ${applied}。退出码 71 表示已在另一层沙盒内运行；请从普通终端启动 SandGate。`,
      }] };
    }

    const curl = ['-s', '-o', '/dev/null', '--max-time', '5'];
    const denials = [
      ['direct-ip', '直连公网 IP', '/usr/bin/curl', ...curl, '--noproxy', '*', 'https://223.5.5.5'],
      ['direct-dns', '直连域名（含本地 DNS）', '/usr/bin/curl', ...curl, '--noproxy', '*', 'https://www.baidu.com'],
      ['udp', 'UDP 发往 223.5.5.5:53', '/usr/bin/nc', '-u', '-z', '-w', '2', '223.5.5.5', '53'],
      ['broker', '系统网络框架 (nscurl)', '/usr/bin/nscurl', 'https://www.apple.com'],
      ['token', '读取 SandGate 令牌', '/bin/cat', this.store.tokenPath],
    ];
    const listener = this.store.data.gate.listeners[app.node];
    if (listener) {
      denials.push(['listener', `绕过闸门直连 listener ${listener}`, '/usr/bin/curl', ...curl, '-x', `http://127.0.0.1:${listener}`, 'http://cp.cloudflare.com/generate_204']);
    }
    const results = [{ id: 'applied', label: '沙盒配置能否加载', ok: true, detail: '已加载' }];
    for (const [pid, label, cmd, ...args] of denials) {
      const code = await inBox(cmd, ...args);
      results.push({ id: pid, label, ok: code !== 0, detail: code !== 0 ? `已拦截 (退出码 ${code})` : '泄漏：操作成功了' });
    }
    if (app.network === 'gate') {
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
