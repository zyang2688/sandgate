#!/bin/bash
# One-shot feasibility test: can pf pass only root-owned traffic on the physical NIC?
# Changes nothing on disk. Rules live in a temporary anchor and are removed when the
# script ends, or after 40 seconds at the latest. Utun traffic is never filtered.
#
# Usage: sudo bash scripts/pf-probe.sh [interface]   (default en0)
# Note:  the en0 checks send direct, non-proxied HTTPS requests to AliDNS (223.5.5.5).
#        It is an IP literal because TUN fake-ip DNS answers do not route via en0, and
#        any HTTP status counts as reachable: only connectivity matters here.
set -u

# This probe's `user root` rule uses the code path that deadlocked the kernel on
# 2026-11-04. Passing once showed that matching works, not that it is safe.
echo "pf-probe 已停用：它的 user 规则可能导致内核死锁。详见 README。" >&2
exit 2

IFACE="${1:-en0}"
ANCHOR="com.apple/sandgate-probe"
TARGET="https://223.5.5.5"
PROXY="http://127.0.0.1:7890"
PROXY_URL="http://cp.cloudflare.com/generate_204"
CURL=(/usr/bin/curl -s -o /dev/null --max-time 5)

[ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] \
  || { echo "请用 sudo 从普通用户运行"; exit 2; }
[[ "$IFACE" =~ ^[a-z]+[0-9]+$ ]] || { echo "接口名无效: $IFACE"; exit 2; }
/sbin/ifconfig "$IFACE" 2>/dev/null | grep -q 'inet ' || { echo "$IFACE 没有 IPv4 地址，请指定实际联网的网卡"; exit 2; }

as_user() { /usr/bin/sudo -u "$SUDO_USER" "$@"; }

# Each check prints its own line and sets RESULT to pass or fail.
check() { # label expected(ok|blocked) command...
  local label=$1 expected=$2 got=blocked rc=0
  shift 2
  "$@" || rc=$?
  [ "$rc" = 0 ] && got=ok
  if [ "$got" = "$expected" ]; then RESULT=pass; else RESULT=fail; fi
  printf '  [%s] %s：实际 %s（curl 退出码 %s），预期 %s\n' "$RESULT" "$label" "$got" "$rc" "$expected"
}

echo "1) 加载规则前的基线"
check "普通用户从 $IFACE 直连" ok as_user "${CURL[@]}" --interface "$IFACE" --noproxy '*' "$TARGET"
if [ "$RESULT" != pass ]; then
  echo "结论：无法判断。加规则前直连就不通，请确认网卡是否选对。"
  exit 1
fi

TOKEN=""
rollback() {
  /sbin/pfctl -a "$ANCHOR" -F all >/dev/null 2>&1
  [ -n "$TOKEN" ] && /sbin/pfctl -X "$TOKEN" >/dev/null 2>&1
  TOKEN=""
}
trap rollback EXIT INT TERM

TOKEN=$(/sbin/pfctl -E 2>&1 | awk '/[Tt]oken/{print $NF}')
if ! printf '%s\n' \
  'pass out quick proto udp from any port 68 to any port 67 no state' \
  "pass out quick on $IFACE proto { tcp udp } user root no state" \
  "block drop out quick on $IFACE all" | /sbin/pfctl -a "$ANCHOR" -f - 2>/dev/null; then
  echo "结论：规则加载失败。"
  exit 1
fi

# Safety net in case this script gets stuck. It is independent of the trap above.
( sleep 40; /sbin/pfctl -a "$ANCHOR" -F all >/dev/null 2>&1; [ -n "$TOKEN" ] && /sbin/pfctl -X "$TOKEN" >/dev/null 2>&1 ) &
TIMER=$!
sleep 1

echo "2) 加载规则后（最多 40 秒，之后自动撤销）"
check "普通用户从 $IFACE 直连（模拟 TUN 消失后回落）" blocked as_user "${CURL[@]}" --interface "$IFACE" --noproxy '*' "$TARGET"; A=$RESULT
check "root 从 $IFACE 直连" ok "${CURL[@]}" --interface "$IFACE" --noproxy '*' "$TARGET"; B=$RESULT
check "普通用户走默认路由（经 TUN）" ok as_user "${CURL[@]}" --noproxy '*' "$PROXY_URL"; C=$RESULT
check "经 Clash 端口出网（核心自身未被拦）" ok as_user "${CURL[@]}" -x "$PROXY" "$PROXY_URL"; D=$RESULT
check "普通用户经 TUN 访问国内目标" ok as_user "${CURL[@]}" --noproxy '*' "$TARGET"; E=$RESULT

kill "$TIMER" 2>/dev/null
rollback
trap - EXIT INT TERM
echo "规则已撤销。"

echo
if [ "$A$B$C$D$E" = passpasspasspasspass ]; then
  echo "结论：可行。pf 能按用户区分流量，Clash 核心在拦截下仍可出网。"
elif [ "$A" != pass ]; then
  echo "结论：普通用户没被拦住。pf 规则没有生效，或 user 匹配不可用，不能采用这个方案。"
elif [ "$D" != pass ] || [ "$C" != pass ] || [ "$E" != pass ]; then
  echo "结论：Clash 核心的流量也被拦了。核心可能不是以 root 运行，需要另找办法区分。"
else
  echo "结论：root 的流量没被放行。user root 匹配不可靠，不能采用这个方案。"
fi
