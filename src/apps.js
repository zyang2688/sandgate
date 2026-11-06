import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { GatePort } from './gateport.js';
import { KEYCHAIN_TOOL, buildEnv, buildProfile, canonical, expandVars } from './profile.js';

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

// These stand in for what the outer sandbox takes away. Without that sandbox they would
// only switch off the program's own protection, leaving no layer at all.
const SANDBOX_ONLY_ARGS = new Set(['--no-sandbox', '--use-mock-keychain']);

/** The final argument list: drops flags that do not apply to how this instance runs. */
export function instanceArgs(app) {
  return app.args
    .filter((a) => app.port || !a.includes('{port}'))
    .filter((a) => !app.unsandboxed || !SANDBOX_ONLY_ARGS.has(a));
}
/** Moves `from` into `to`, keeping both where names clash: the moved one gets `.from-<tag>`. */
function mergeInto(from, to, tag, notes) {
  for (const name of fs.readdirSync(from)) {
    const src = path.join(from, name);
    const dst = path.join(to, name);
    const dstStat = fs.lstatSync(dst, { throwIfNoEntry: false });
    if (!dstStat) { fs.renameSync(src, dst); continue; }
    if (dstStat.isDirectory() && fs.lstatSync(src).isDirectory()) { mergeInto(src, dst, tag, notes); continue; }
    const kept = `${dst}.from-${tag}`;
    fs.renameSync(src, kept);
    notes.push(`${dst} 两边都有，实例的那份放在 ${kept}`);
  }
  fs.rmdirSync(from);
}

/**
 * Makes each path in a clone's HOME a link to the same path in your home, so both see one
 * copy (Claude Code's transcripts and memory, for tools that read ~/.claude). What the clone
 * already had is kept: a directory is merged across, and a file moves across if yours has
 * none, or else stays beside the link as `<name>.sandgate-bak`.
 */
export function linkHomePaths(home, rels, { realHome = os.homedir(), tag = 'instance' } = {}) {
  const notes = [];
  for (const rel of rels) {
    const inside = path.join(home, rel);
    const real = path.join(realHome, rel);
    let st = fs.lstatSync(inside, { throwIfNoEntry: false });
    if (st?.isSymbolicLink() && fs.readlinkSync(inside) === real) continue;
    if (st?.isSymbolicLink()) { fs.rmSync(inside); st = undefined; }
    const realSt = fs.statSync(real, { throwIfNoEntry: false });
    // Nothing on either side yet: linked on a later start, once the program has made it.
    if (!st && !realSt) continue;
    const isDir = st ? st.isDirectory() : realSt.isDirectory();
    if (realSt && realSt.isDirectory() !== isDir) {
      notes.push(`${real} 和实例里的 ${rel} 一个是文件一个是目录，没有链接`);
      continue;
    }
    fs.mkdirSync(path.dirname(inside), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.dirname(real), { recursive: true, mode: 0o700 });
    if (isDir) {
      if (!realSt) fs.mkdirSync(real, { mode: 0o700 });
      if (st) mergeInto(inside, real, tag, notes);
    } else if (st && !realSt) {
      fs.renameSync(inside, real);
    } else if (st) {
      fs.renameSync(inside, `${inside}.sandgate-bak`);
      notes.push(`${rel} 改用你的那份，实例原来的留在 ${inside}.sandgate-bak`);
    }
    fs.symlinkSync(real, inside);
  }
  return notes;
}

const LOG_LIMIT = 10 * 1024 * 1024;
const WATCH_MS = 2000;
const TAIL_BYTES = 64 * 1024;

/** `/Applications/Foo.app` → the executable inside, since a bundle cannot be exec'd. */
export async function resolveCommand(command) {
  if (!command.endsWith('.app')) return command;
  const plist = path.join(command, 'Contents/Info.plist');
  const { stdout } = await exec('/usr/bin/plutil', ['-extract', 'CFBundleExecutable', 'raw', plist]);
  return path.join(command, 'Contents/MacOS', stdout.trim());
}

/** Survives PID reuse: a recorded instance only counts as ours if its start time still matches. */
async function psStartTime(pid) {
  try {
    const { stdout } = await exec('/bin/ps', ['-o', 'lstart=', '-p', String(pid)]);
    return stdout.trim();
  } catch {
    return '';
  }
}

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

const runsFile = (store) => path.join(store.dir, 'runs.json');

function readRuns(store) {
  try {
    return JSON.parse(fs.readFileSync(runsFile(store), 'utf8'));
  } catch {
    return {};
  }
}

const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

function signalGroup(pid, sig) {
  try { process.kill(-pid, sig); } catch { /* already gone */ }
}

/**
 * Stops instances recorded by a SandGate that is no longer running, for removing the
 * service. A process whose start time changed is someone else's and is left alone.
 */
export async function stopRecordedInstances(store, { processStart = psStartTime, graceMs = 5000 } = {}) {
  const records = Object.values(readRuns(store));
  const ours = [];
  for (const r of records) {
    if (isAlive(r.pid) && r.started && (await processStart(r.pid)) === r.started) ours.push(r.pid);
  }
  for (const pid of ours) signalGroup(pid, 'SIGTERM');
  const deadline = Date.now() + graceMs;
  while (ours.some(isAlive) && Date.now() < deadline) await sleep(100);
  for (const pid of ours.filter(isAlive)) signalGroup(pid, 'SIGKILL');
  fs.rmSync(runsFile(store), { force: true });
  return ours.length;
}

export class AppManager {
  constructor({ store, gates, controllerSocket, sandboxExec = SANDBOX_EXEC, processStart = psStartTime, watchMs = WATCH_MS, logLimit = LOG_LIMIT }) {
    Object.assign(this, { store, gates, controllerSocket, sandboxExec, processStart, watchMs, logLimit });
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
  get homeDir() { return this.realHome ?? os.homedir(); }
  isRunning(id) { return this.runs.has(id); }

  profileFor(app) {
    if (app.unsandboxed) return ';; 这个实例不套沙盒，没有沙盒配置。程序能读写你的文件，网络也不由系统强制。\n';
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

  async ensurePort(app) {
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
    await this.ensurePort(app);
    const profile = app.unsandboxed ? null : this.#writeProfile(app);
    const command = await resolveCommand(app.command);
    const home = this.store.instanceHome(id);
    this.#prepareDataDir(app);
    const vars = { port: app.port, home: app.isolateHome ? home : process.env.HOME, data: home };
    const args = instanceArgs(app).map((a) => expandVars(a, vars));
    const logPath = this.#logPath(id);
    fs.appendFileSync(logPath, `\n=== ${new Date().toISOString()} start ${command} ===\n`, { mode: 0o600 });
    // The instance writes to the file itself, so it keeps logging while SandGate restarts.
    const logFd = fs.openSync(logPath, 'a', 0o600);

    const [file, argv] = app.unsandboxed ? [command, args] : [this.sandboxExec, ['-f', profile, command, ...args]];
    const child = spawn(file, argv, {
      cwd: app.cwd || (app.isolateHome ? home : undefined),
      env: buildEnv(app, app.port, process.env, home),
      stdio: ['ignore', logFd, logFd],
      detached: true, // own process group, so stop reaches every descendant and it outlives SandGate
    });
    fs.closeSync(logFd);
    child.unref();
    const run = { pid: child.pid, startedAt: Date.now(), started: '', waiters: [] };
    this.runs.set(id, run);
    child.once('error', (e) => fs.appendFileSync(logPath, `[sandgate] 启动失败: ${e.message}\n`));
    child.once('close', (code, signal) => this.#finish(id, run, { code, signal, at: Date.now() }));
    this.#watch();
    if (child.pid) run.started = await this.processStart(child.pid);
    this.#saveRuns();
  }

  /**
   * What a terminal needs to run this instance itself, keeping its own TTY, directory and
   * arguments. Several can run at once and SandGate is not their parent, so they are not
   * recorded as running; their gate port stays up while SandGate does.
   */
  async terminalLaunch(id, cwd = '') {
    const app = this.find(id);
    if (!app) throw new Error('应用不存在');
    await this.ensurePort(app);
    const linkNotes = this.#prepareDataDir(app);
    const home = this.store.instanceHome(id);
    // A clone that hides your home folder gets the directory it was started in, unless that
    // directory is the home folder itself or above it, which would reveal all of it.
    const realHome = canonical(os.homedir());
    const dir = cwd ? canonical(cwd) : '';
    const reveals = dir && (dir === realHome || realHome.startsWith(`${dir}/`) || dir === '/');
    const launched = { ...app, cwd: dir && !reveals ? dir : app.cwd };
    return {
      app: launched,
      command: await resolveCommand(app.command),
      sandboxExec: app.unsandboxed ? null : this.sandboxExec,
      profile: app.unsandboxed ? null : this.profileFor(launched),
      home,
      port: app.port,
      gateOpen: !usesPort(app) || this.gates.isOpen(app.node),
      cwdShared: Boolean(dir && !reveals),
      linkNotes,
    };
  }

  #logPath(id) {
    return path.join(this.store.logDir, `${id}.log`);
  }

  #saveRuns() {
    const records = Object.fromEntries([...this.runs].filter(([, r]) => r.pid).map(([id, r]) => [id, { pid: r.pid, startedAt: r.startedAt, started: r.started }]));
    const tmp = `${runsFile(this.store)}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(records), { mode: 0o600 });
    fs.renameSync(tmp, runsFile(this.store));
  }

  #finish(id, run, exit) {
    if (this.runs.get(id) !== run) return;
    clearTimeout(run.killTimer);
    this.runs.delete(id);
    this.lastExit.set(id, exit);
    const how = exit.unknown ? '退出码未知（实例是重启后接管的）' : `exit code=${exit.code} signal=${exit.signal}`;
    try { fs.appendFileSync(this.#logPath(id), `=== ${how} ===\n`); } catch { /* the instance may have been deleted */ }
    this.#saveRuns();
    for (const resolve of run.waiters) resolve();
  }

  /** Picks up instances a previous SandGate left running, after checking they are the same processes. */
  async adopt() {
    for (const [id, r] of Object.entries(readRuns(this.store))) {
      const app = this.find(id);
      if (!app) continue;
      const started = isAlive(r.pid) ? await this.processStart(r.pid) : '';
      if (!started || started !== r.started) {
        this.lastExit.set(id, { code: null, signal: null, at: Date.now(), unknown: true });
        continue;
      }
      this.runs.set(id, { pid: r.pid, startedAt: r.startedAt, started, waiters: [], adopted: true });
      try {
        await this.ensurePort(app);
      } catch (e) {
        console.error(`实例 ${app.name} 的闸门端口无法恢复：${e.message}`);
      }
    }
    this.#saveRuns();
    if (this.runs.size) this.#watch();
  }

  /** An adopted instance is not our child, so no exit event arrives. Logs are capped here too. */
  #watch() {
    this.watcher ??= setInterval(() => this.#checkRuns(), this.watchMs);
    this.watcher.unref();
  }

  #checkRuns() {
    for (const [id, run] of this.runs) {
      if (run.adopted && !isAlive(run.pid)) {
        this.#finish(id, run, { code: null, signal: null, at: Date.now(), unknown: true });
        continue;
      }
      this.#capLog(id);
    }
  }

  /** Instances append with O_APPEND, so truncating is safe while they keep writing. */
  #capLog(id) {
    const file = this.#logPath(id);
    try {
      if (fs.statSync(file).size <= this.logLimit) return;
      fs.copyFileSync(file, `${file}.old`);
      fs.truncateSync(file, 0);
    } catch { /* no log yet */ }
  }

  stop(id) {
    const run = this.runs.get(id);
    if (!run) return Promise.resolve();
    return new Promise((resolve) => {
      run.waiters.push(resolve);
      signalGroup(run.pid, 'SIGTERM');
      run.killTimer = setTimeout(() => signalGroup(run.pid, 'SIGKILL'), 5000);
      run.killTimer.unref?.();
      if (run.adopted) this.#checkRuns();
    });
  }

  /**
   * A shared-data instance gets a directory only if it asks for one through {data} or links
   * paths into it. Its links live there too: with CLAUDE_CONFIG_DIR={data}/.claude, the
   * instance's `.claude/projects` is the one Claude Code uses, and it points at yours.
   */
  #prepareDataDir(app) {
    const home = this.store.instanceHome(app.id);
    const links = app.linkedPaths ?? [];
    const usesData = [...app.args, ...Object.values(app.env)].some((v) => v.includes('{data}'));
    if (app.isolateHome || usesData || links.length) fs.mkdirSync(home, { recursive: true, mode: 0o700 });
    if (app.isolateHome) fs.mkdirSync(path.join(home, 'tmp'), { recursive: true, mode: 0o700 });
    const seesHome = !app.unsandboxed && (!app.isolateHome || app.homeVisible);
    return seesHome ? linkHomePaths(home, links, { realHome: this.homeDir, tag: app.id }) : [];
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

  /**
   * Empties the instance's data directory but keeps the instance, so its next start is like
   * a first launch. Data a shared-data program keeps in your home folder is not touched.
   */
  clearData(id) {
    if (!this.find(id)) throw new Error('应用不存在');
    if (this.runs.has(id)) throw new Error('请先停止应用');
    fs.rmSync(this.store.instanceHome(id), { recursive: true, force: true });
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
    await this.ensurePort(app);
    if (app.unsandboxed) return this.#verifyUnsandboxed(app);
    const profile = this.#writeProfile(app);
    const gateOpen = this.gates.isOpen(app.node);
    this.#prepareDataDir(app);
    const writeProbe = path.join(os.homedir(), `.sandgate-probe-${id}`);
    const runInBox = async (cmd, ...args) => {
      try {
        const { stderr } = await exec(this.sandboxExec, ['-f', profile, cmd, ...args], { timeout: 15000, env: buildEnv({ ...app, network: 'none', isolateHome: false, env: {} }, null) });
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
    denials.push(['keychain', '运行钥匙串工具 (security)', KEYCHAIN_TOOL, 'list-keychains']);
    if (app.isolateHome && !app.homeVisible) {
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

  /** There is nothing to escape from, so this says so rather than reporting passes. */
  async #verifyUnsandboxed(app) {
    const gateOpen = this.gates.isOpen(app.node);
    const results = [{ id: 'unsandboxed', label: '沙盒', ok: true, detail: '这个实例不套沙盒，文件和网络都不受 SandGate 限制，所以没有越权操作可测' }];
    if (usesPort(app)) {
      let code = 0;
      try {
        await exec('/usr/bin/curl', ['-s', '-o', '/dev/null', '--max-time', '5', '-x', `http://127.0.0.1:${app.port}`, 'http://cp.cloudflare.com/generate_204'], { timeout: 15000 });
      } catch (e) {
        code = typeof e.code === 'number' ? e.code : -1;
      }
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
      pid: run?.pid ?? null,
      startedAt: run?.startedAt ?? null,
      lastExit: this.lastExit.get(app.id) ?? null,
      gateOpen: this.gates.isOpen(app.node),
      conns: gp?.active ?? 0,
      stats: gp?.stats ?? { up: 0, down: 0, accepted: 0, refused: 0 },
    };
  }

  async stopAll() {
    await Promise.all([...this.runs.keys()].map((id) => this.stop(id)));
    await this.release();
  }

  /** Lets go without stopping anything, so a restarted SandGate can adopt the instances. */
  async release() {
    clearInterval(this.watcher);
    this.watcher = null;
    await Promise.all([...this.ports.keys()].map((id) => this.releasePort(id)));
  }
}
