#!/usr/bin/env node
import path from 'node:path';
import { Store } from '../src/config.js';
import { Sandgate } from '../src/daemon.js';
import { ServiceManager, startMessage } from '../src/service.js';
import { stopRecordedInstances } from '../src/apps.js';
import { api, commandDir, findInstance, installZshrc, launchSpec, uninstallZshrc, writeAliases } from '../src/terminal.js';

const USAGE = `用法:
  sandgate.js                     在当前终端运行
  sandgate.js url                 显示登录链接
  sandgate.js service install     安装为后台服务，登录后自动运行
  sandgate.js service uninstall   移除后台服务
  sandgate.js service status      查看后台服务状态
  sandgate.js alias install       让 ~/.zshrc 加载实例的终端命令（在实例设置里填“终端命令”）
  sandgate.js alias uninstall     从 ~/.zshrc 移除，原来的别名恢复生效
  sandgate.js alias show          显示每个终端命令指向哪个实例
  sandgate.js alias use <实例> [命令]  把终端命令改为指向这个实例（实例可以是名称、名称的一部分或 ID），用来切换账号
  sandgate-run <实例> [参数...]    在当前终端里运行实例`;

const loginUrl = (store) => `http://127.0.0.1:${store.data.uiPort}/#token=${store.token}`;

async function runDaemon() {
  const app = new Sandgate();
  let url;
  try {
    ({ url } = await app.start());
  } catch (e) {
    if (e.code !== 'EADDRINUSE') throw e;
    console.error(`端口 ${app.store.data.uiPort} 已被占用。如果 SandGate 已在后台运行，用 sandgate.js url 查看登录链接。`);
    process.exit(1);
  }
  console.log(startMessage({ url, isTTY: Boolean(process.stdout.isTTY), tokenPath: app.store.tokenPath }));

  let stopping = false;
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, async () => {
      if (stopping) process.exit(1);
      stopping = true;
      // launchd restarts the service with SIGTERM, and instances should outlive that.
      // Ctrl-C in a terminal means the user is finished with them.
      await app.stop({ keepInstances: sig === 'SIGTERM' });
      process.exit(0);
    });
  }
}

async function runService(action) {
  const store = new Store();
  const service = new ServiceManager({ store });
  const failed = (e) => {
    console.error(e.message);
    process.exit(1);
  };
  switch (action) {
    case 'install':
      await service.install().catch(failed);
      console.log(`已安装，并已在后台启动，登录后会自动运行。\n\n  打开: ${loginUrl(store)}\n\n移除: node bin/sandgate.js service uninstall`);
      return;
    case 'uninstall':
      await service.uninstall().catch(failed);
      await stopRecordedInstances(store);
      console.log('已移除后台服务，运行中的实例已停止。配置和数据保留在原处。');
      return;
    case 'status': {
      const s = await service.status();
      const state = !s.installed ? '未安装' : !s.loaded ? '已安装，但未加载' : s.pid ? `运行中，进程 ${s.pid}` : '已加载，当前未运行';
      console.log(state);
      return;
    }
    default:
      console.error(USAGE);
      process.exit(2);
  }
}

/** Prints the command for bin/sandgate-run to exec. Anything for the user goes to stderr. */
async function runLaunch(name) {
  if (!name) {
    console.error(USAGE);
    process.exit(2);
  }
  try {
    const { command, warnings } = await launchSpec(new Store(), name);
    for (const w of warnings) console.error(w);
    process.stdout.write(command);
  } catch (e) {
    console.error(`SandGate：${e.message}`);
    process.exit(78);
  }
}

async function useAlias(store, target, name) {
  if (!target) throw new Error('用法: sandgate.js alias use <实例名称或 ID> [命令名]');
  const { apps } = await api(store, 'GET', '/api/state');
  const app = findInstance(apps, target);
  const names = [...new Set(apps.filter((a) => a.alias).map((a) => a.alias))];
  const alias = name || (names.length === 1 ? names[0] : '');
  if (!alias) throw new Error(names.length ? `有多个终端命令（${names.join('、')}），请写明要改哪一个` : '还没有终端命令，请写明命令名');
  const r = await api(store, 'POST', `/api/apps/${app.id}/alias`, { alias });
  console.log(`终端命令 ${r.alias} 现在指向「${app.name}」${r.movedFrom ? `（原来指向「${r.movedFrom}」）` : ''}。新启动的 ${r.alias} 进这个实例，已在运行的会话不受影响。`);
}

async function runAlias(action) {
  const store = new Store();
  switch (action) {
    case 'install': {
      const r = installZshrc(store);
      console.log(r.changed ? `已在 ${r.zshrc} 末尾加入 SandGate 的别名（原文件备份为 .zshrc.sandgate-bak）。` : `${r.zshrc} 里已经有了，别名文件已更新。`);
      for (const s of r.shadowed) console.log(`  第 ${s.line} 行的 ${s.text} 会被 SandGate 的 ${s.name} 覆盖；移除 SandGate 的别名后它恢复生效。`);
      console.log('\n新开的终端生效；当前终端运行 source ~/.zshrc。');
      return;
    }
    case 'uninstall':
      console.log(uninstallZshrc() ? '已从 ~/.zshrc 移除。新开的终端里原来的别名恢复生效。' : '~/.zshrc 里没有 SandGate 的内容。');
      return;
    case 'show': {
      writeAliases(store);
      const held = store.data.apps.filter((a) => a.alias);
      if (!held.length) console.log('还没有终端命令。在实例设置里填“终端命令”。');
      for (const a of held) console.log(`${a.alias} → 「${a.name}」(${a.id})\n  可执行文件: ${path.join(commandDir(store), a.alias)}`);
      return;
    }
    case 'use':
      try {
        await useAlias(store, process.argv[4] ?? '', process.argv[5] ?? '');
      } catch (e) {
        console.error(e.message);
        process.exit(1);
      }
      return;
    default:
      console.error(USAGE);
      process.exit(2);
  }
}

const [command, action] = process.argv.slice(2);
if (!command) await runDaemon();
else if (command === 'launch') await runLaunch(action);
else if (command === 'alias') await runAlias(action);
else if (command === 'url') console.log(loginUrl(new Store()));
else if (command === 'service') await runService(action);
else {
  console.error(USAGE);
  process.exit(2);
}
