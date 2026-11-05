#!/usr/bin/env node
import { Store } from '../src/config.js';
import { Sandgate } from '../src/daemon.js';
import { ServiceManager, startMessage } from '../src/service.js';
import { stopRecordedInstances } from '../src/apps.js';

const USAGE = `用法:
  sandgate.js                     在当前终端运行
  sandgate.js url                 显示登录链接
  sandgate.js service install     安装为后台服务，登录后自动运行
  sandgate.js service uninstall   移除后台服务
  sandgate.js service status      查看后台服务状态`;

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

const [command, action] = process.argv.slice(2);
if (!command) await runDaemon();
else if (command === 'url') console.log(loginUrl(new Store()));
else if (command === 'service') await runService(action);
else {
  console.error(USAGE);
  process.exit(2);
}
