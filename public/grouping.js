const FOLLOW_TITLE = '跟随 Clash 规则';
const NONE_TITLE = '完全禁网';

/** `/Applications/Google Chrome.app` → `Google Chrome`; `/usr/bin/curl` → `curl`. */
export function appLabel(command) {
  const base = String(command).replace(/\/+$/, '').split('/').pop();
  return base.replace(/\.app$/i, '') || String(command);
}

function byProfile(apps, netProfiles) {
  const titles = new Map([['follow', FOLLOW_TITLE], ...netProfiles.map((p) => [p.id, p.name]), ['none', NONE_TITLE]]);
  const order = [...titles.keys()];
  const keyOf = (a) => a.netProfile || (a.network === 'none' ? 'none' : a.network === 'open' ? 'follow' : a.node);
  const rank = (k) => { const i = order.indexOf(k); return i < 0 ? order.length : i; };
  return { keyOf, titleOf: (k) => titles.get(k) ?? k, detailOf: () => '', compare: (x, y) => rank(x) - rank(y) };
}

function byCommand() {
  return {
    keyOf: (a) => a.command,
    titleOf: appLabel,
    detailOf: (k) => k,
    compare: (x, y) => appLabel(x).localeCompare(appLabel(y), 'zh-CN') || x.localeCompare(y),
  };
}

/** Groups instances for display. Only groups with instances appear, each listing its instances in order. */
export function groupApps(apps, mode, netProfiles = []) {
  const { keyOf, titleOf, detailOf, compare } = mode === 'app' ? byCommand() : byProfile(apps, netProfiles);
  const groups = new Map();
  for (const a of apps) {
    const key = keyOf(a);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(a);
  }
  return [...groups.keys()].sort(compare).map((key) => ({
    key,
    title: titleOf(key),
    detail: detailOf(key),
    apps: groups.get(key),
    running: groups.get(key).filter((a) => a.running).length,
  }));
}
