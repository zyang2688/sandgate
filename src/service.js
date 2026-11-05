import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const LAUNCHCTL = '/bin/launchctl';
const ENTRY = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'sandgate.js');
export const LABEL = 'com.sandgate.daemon';
const POLL_MS = 250;
const UNLOAD_TIMEOUT_MS = 30000;
const BOOTSTRAP_BUSY = 5; // launchctl's exit code while the old service is still going away
const BOOTSTRAP_ATTEMPTS = 8;
const BOOTSTRAP_RETRY_MS = 1000;

const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/**
 * A per-user LaunchAgent. It restarts only after a crash: a clean exit means someone
 * stopped it on purpose. launchd's minimal environment also means no proxy variables
 * reach the daemon or the sandboxed apps it starts.
 */
export function buildPlist({ node, entry, logFile, home, sandgateHome }) {
  const env = { HOME: home, PATH: '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin' };
  if (sandgateHome) env.SANDGATE_HOME = sandgateHome;
  const envXml = Object.entries(env).map(([k, v]) => `    <key>${xml(k)}</key><string>${xml(v)}</string>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array><string>${xml(node)}</string><string>${xml(entry)}</string></array>
  <key>WorkingDirectory</key><string>${xml(path.dirname(path.dirname(entry)))}</string>
  <key>EnvironmentVariables</key><dict>
${envXml}
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>AbandonProcessGroup</key><true/>
  <key>StandardOutPath</key><string>${xml(logFile)}</string>
  <key>StandardErrorPath</key><string>${xml(logFile)}</string>
</dict></plist>
`;
}

/** The link carries the login token, so it is only shown to a person at a terminal. */
export function startMessage({ url, isTTY, tokenPath }) {
  if (isTTY) return `SandGate 已启动\n\n  打开: ${url}\n\n令牌保存在 ${tokenPath}（Ctrl-C 退出，会同时停止所有沙盒应用）`;
  return `SandGate 已启动: ${url.split('#')[0]}（登录链接可用 sandgate.js url 查看）`;
}

export class ServiceManager {
  constructor({
    store,
    home = os.homedir(),
    uid = process.getuid(),
    node = process.execPath,
    entry = ENTRY,
    run = (args) => exec(LAUNCHCTL, args),
    sandgateHome = process.env.SANDGATE_HOME,
    sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  }) {
    Object.assign(this, { store, home, uid, node, entry, run, sandgateHome, sleep });
    this.plistPath = path.join(home, 'Library/LaunchAgents', `${LABEL}.plist`);
    this.domain = `gui/${uid}`;
    this.target = `${this.domain}/${LABEL}`;
  }

  /**
   * bootout returns before launchd has finished tearing the service down, and a
   * bootstrap during that window fails with error 5. The daemon's graceful stop can
   * take a while, and launchd only kills it after 20 seconds, so this waits past that.
   */
  async #waitUnloaded() {
    for (let waited = 0; waited < UNLOAD_TIMEOUT_MS; waited += POLL_MS) {
      try {
        await this.run(['print', this.target]);
      } catch {
        return;
      }
      await this.sleep(POLL_MS);
    }
    throw new Error('等待旧服务退出超时，请稍后重试');
  }

  async #bootstrap() {
    for (let attempt = 1; ; attempt++) {
      try {
        await this.run(['bootstrap', this.domain, this.plistPath]);
        return;
      } catch (e) {
        if (e.code !== BOOTSTRAP_BUSY || attempt >= BOOTSTRAP_ATTEMPTS) {
          throw new Error(`launchd 加载失败：${String(e.stderr ?? e.message).trim().split('\n')[0]}`);
        }
        await this.sleep(BOOTSTRAP_RETRY_MS);
      }
    }
  }

  async install() {
    fs.mkdirSync(path.dirname(this.plistPath), { recursive: true });
    const plist = buildPlist({
      node: this.node,
      entry: this.entry,
      logFile: path.join(this.store.logDir, 'daemon.log'),
      home: this.home,
      sandgateHome: this.sandgateHome,
    });
    await this.run(['bootout', this.target]).catch(() => {}); // not loaded yet is fine
    await this.#waitUnloaded();
    fs.writeFileSync(this.plistPath, plist, { mode: 0o644 });
    await this.#bootstrap();
  }

  async uninstall() {
    await this.run(['bootout', this.target]).catch(() => {});
    await this.#waitUnloaded();
    fs.rmSync(this.plistPath, { force: true });
  }

  async status() {
    const installed = fs.existsSync(this.plistPath);
    let loaded = false;
    let pid = null;
    try {
      const { stdout } = await this.run(['print', this.target]);
      loaded = true;
      const m = stdout.match(/^\s*pid = (\d+)/m);
      pid = m ? Number(m[1]) : null;
    } catch { /* not loaded */ }
    return { installed, loaded, pid, plistPath: this.plistPath };
  }
}
