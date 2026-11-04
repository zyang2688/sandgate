#!/bin/bash
# Whole-Mac protection with pf: physical NICs may only reach allow-listed destinations.
# When Clash stops and routes fall back to a NIC, foreign destinations are dropped.
#
# Rules must never match on `user` or `group`. On 2026-11-04 such rules deadlocked the
# kernel: they make the packet path block on the TCP pcbinfo lock via pf_socket_lookup,
# and the watchdog then panicked the machine. Matching on addresses avoids that path.
#
#   trial [seconds]   load temporarily and follow allow-list updates (default 1800)
#   uninstall         remove the rules and release pf; also the emergency recovery
#   status            show current state
#   render            print the rules (no root needed)
#   check <dir>       validate allow-list files (no root needed)
#   install           disabled until a long trial has shown the rules are safe
#
# A reboot also clears everything: nothing here persists across one.
# Option: ALLOW_LAN (1) passes the local subnet, link-local and multicast.
set -u

ANCHOR="com.apple/sandgate"
LABEL="com.sandgate.pf"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
INSTALLED="/usr/local/sbin/sandgate-pf"
ENV_FILE="/usr/local/etc/sandgate-pf.env"
TOKEN_FILE="/var/run/sandgate-pf.token"
PFCTL=/sbin/pfctl
AWK=/usr/bin/awk
LISTS="nodes dns cn extra"
MAX_TRIAL=86400
SYNC_SECONDS=30

ALLOW_LAN="${ALLOW_LAN:-1}"

validate_options() {
  [[ "$ALLOW_LAN" =~ ^[01]$ ]] || { echo "ALLOW_LAN 只能是 0 或 1" >&2; exit 2; }
}

physical_interfaces() {
  /usr/sbin/networksetup -listallhardwareports 2>/dev/null \
    | $AWK '/^Device: en[0-9]+$/{print $2}'
}

# Rules are per-interface rather than default-deny, so virtual links (AirDrop,
# Docker bridges) and the TUN device itself stay untouched.
render() {
  local ifaces="$*"
  [ -n "$ifaces" ] || ifaces=$(physical_interfaces | /usr/bin/tr '\n' ' ')
  [ -n "${ifaces// /}" ] || { echo "找不到物理网卡" >&2; return 1; }
  local list
  for list in $LISTS; do
    if [ -n "${TABLE_DIR:-}" ]; then
      echo "table <sg_$list> persist file \"$TABLE_DIR/$list.txt\""
    else
      echo "table <sg_$list> persist"
    fi
  done
  echo "# DHCP, so the Mac can still join a network"
  echo "pass out quick proto udp from any port 68 to any port 67 no state"
  local i
  for i in $ifaces; do
    echo "# $i: selected nodes"
    echo "pass out quick on $i inet to <sg_nodes> no state"
    echo "# $i: only mihomo's bootstrap DNS; plaintext lookups elsewhere reveal domains"
    echo "pass out quick on $i inet proto { tcp udp } to <sg_dns> port 53 no state"
    echo "block drop out quick on $i proto { tcp udp } to any port 53"
    if [ "$ALLOW_LAN" = 1 ]; then
      echo "# $i: local network. Parentheses resolve at match time, for idle NICs and DHCP"
      echo "pass out quick on $i to ($i:network) no state"
      echo "pass out quick on $i inet to { 169.254.0.0/16 224.0.0.0/4 } no state"
      echo "pass out quick on $i inet6 to { fe80::/10 ff00::/8 } no state"
    fi
    echo "# $i: Clash DIRECT destinations"
    echo "pass out quick on $i inet to <sg_cn> no state"
    echo "pass out quick on $i inet to <sg_extra> no state"
    echo "# $i: everything else"
    echo "block drop out quick on $i all"
  done
}

# These files are written by a non-root process and widen a firewall, so they are
# validated strictly. Anything unexpected rejects the whole file. A broad prefix could
# otherwise allow the whole internet, so the limits below are the security boundary.
clean_list() { # name src dst
  local name=$1 src=$2 dst=$3 min_prefix max_lines min_lines=0 hosts_only=0
  case "$name" in
    nodes) hosts_only=1; min_prefix=32; max_lines=64; min_lines=1 ;;
    dns) hosts_only=1; min_prefix=32; max_lines=8 ;;
    cn) min_prefix=8; max_lines=30000; min_lines=1000 ;;
    extra) min_prefix=8; max_lines=256 ;;
    *) echo "未知列表: $name" >&2; return 1 ;;
  esac
  [ -f "$src" ] && [ ! -L "$src" ] || { echo "$name: 文件不存在: $src" >&2; return 1; }
  $AWK -v min_prefix="$min_prefix" -v max_lines="$max_lines" -v min_lines="$min_lines" -v hosts_only="$hosts_only" -v name="$name" '
    function bad(msg) { printf "%s 第 %d 行无效（%s）\n", name, NR, msg > "/dev/stderr"; failed = 1; exit 1 }
    /^$/ { next }
    {
      line = $0
      if (line !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) bad("格式")
      n = split(line, parts, "/")
      if (hosts_only && n != 1) bad("只允许单个 IP")
      prefix = (n == 2) ? parts[2] + 0 : 32
      if (prefix < min_prefix || prefix > 32) bad("前缀过宽")
      split(parts[1], octets, ".")
      for (o = 1; o <= 4; o++) if (octets[o] + 0 > 255) bad("地址")
      if (octets[1] + 0 == 0 || octets[1] + 0 == 127 || octets[1] + 0 >= 224) bad("保留地址")
      count++
      print line
    }
    END {
      if (failed) exit 1
      if (count + 0 < min_lines) { printf "%s 条目过少：%d，至少需要 %d\n", name, count + 0, min_lines > "/dev/stderr"; exit 1 }
      if (count + 0 > max_lines) { printf "%s 条目过多：%d，最多 %d\n", name, count + 0, max_lines > "/dev/stderr"; exit 1 }
    }
  ' "$src" > "$dst"
}

clean_all() { # src_dir dst_dir
  local list
  for list in $LISTS; do
    clean_list "$list" "$1/$list.txt" "$2/$list.txt" || return 1
  done
}

count_lines() { $AWK 'END{print NR}' "$1"; }

check() {
  [ -d "${1:-}" ] || { echo "用法: check <目录>" >&2; exit 2; }
  local tmp list
  tmp=$(/usr/bin/mktemp -d) || exit 1
  if clean_all "$1" "$tmp"; then
    for list in $LISTS; do echo "$list: $(count_lines "$tmp/$list.txt") 条"; done
    /bin/rm -rf "$tmp"
  else
    /bin/rm -rf "$tmp"
    exit 1
  fi
}

need_root() {
  [ "$(/usr/bin/id -u)" = 0 ] || { echo "需要 sudo" >&2; exit 2; }
}

pf_release() {
  $PFCTL -a "$ANCHOR" -F all >/dev/null 2>&1
  $PFCTL -a "$ANCHOR" -F Tables >/dev/null 2>&1
  if [ -s "$TOKEN_FILE" ]; then
    $PFCTL -X "$(/bin/cat "$TOKEN_FILE")" >/dev/null 2>&1
    /bin/rm -f "$TOKEN_FILE"
  fi
}

lists_dir() {
  [[ "${SUDO_USER:-}" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*$ ]] && [ "$SUDO_USER" != root ] \
    || { echo "请用 sudo 从普通用户运行" >&2; exit 2; }
  local home
  home=$(/usr/bin/dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | $AWK '{print $2}')
  [ -n "$home" ] || { echo "找不到用户目录" >&2; exit 2; }
  echo "$home/.sandgate/pf"
}

fingerprint() { # dir
  local list
  for list in $LISTS; do /sbin/md5 -q "$1/$list.txt" 2>/dev/null; done
}

# pfctl only runs when a list really changed, and each table swap is atomic.
sync_tables() { # src tmp
  local list
  clean_all "$1" "$2" || { echo "$(/bin/date +%T) 列表无效，继续使用当前规则"; return 1; }
  for list in $LISTS; do
    $PFCTL -a "$ANCHOR" -t "sg_$list" -T replace -f "$2/$list.txt" >/dev/null 2>&1 \
      || { echo "$(/bin/date +%T) 更新 sg_$list 失败"; return 1; }
  done
  echo "$(/bin/date +%T) 已更新：节点 $(count_lines "$2/nodes.txt") 个，国内网段 $(count_lines "$2/cn.txt") 条"
}

trial() {
  need_root
  validate_options
  local secs="${1:-1800}"
  [[ "$secs" =~ ^[0-9]+$ ]] && [ "$secs" -ge 1 ] && [ "$secs" -le "$MAX_TRIAL" ] \
    || { echo "时长需为 1 到 $MAX_TRIAL 秒" >&2; exit 2; }
  [ -f "$PLIST" ] && { echo "检测到旧版安装，请先运行 uninstall" >&2; exit 2; }

  local src tmp seen
  src=$(lists_dir)
  tmp=$(/usr/bin/mktemp -d /var/run/sandgate-pf.XXXXXX) || exit 1
  clean_all "$src" "$tmp" || { echo "请先在 SandGate 的「配置」页选好放行节点，并保持 SandGate 运行" >&2; /bin/rm -rf "$tmp"; exit 1; }

  TABLE_DIR="$tmp" render > "$tmp/rules.conf" || { /bin/rm -rf "$tmp"; exit 1; }
  if /usr/bin/grep -Eq '\b(user|group)\b' "$tmp/rules.conf"; then
    echo "规则中出现了 user 或 group，拒绝加载" >&2
    /bin/rm -rf "$tmp"
    exit 1
  fi
  $PFCTL -n -a "$ANCHOR" -f "$tmp/rules.conf" || { echo "规则语法检查失败" >&2; /bin/rm -rf "$tmp"; exit 1; }
  $PFCTL -a "$ANCHOR" -f "$tmp/rules.conf" 2>/dev/null || { echo "规则加载失败" >&2; /bin/rm -rf "$tmp"; exit 1; }
  $PFCTL -E 2>&1 | $AWK '/[Tt]oken/{print $NF}' > "$TOKEN_FILE"
  /bin/chmod 600 "$TOKEN_FILE"

  # Independent of this shell, so a killed script or closed terminal still rolls back.
  ( /bin/sleep "$((secs + 5))"; pf_release ) &
  # Global on purpose: the EXIT trap runs after this function's locals are gone.
  TRIAL_TIMER=$!
  TRIAL_TMP=$tmp
  trap 'kill "$TRIAL_TIMER" 2>/dev/null; pf_release; /bin/rm -rf "$TRIAL_TMP"' EXIT
  trap 'exit 130' INT TERM HUP

  cat <<EOF
规则已加载，${secs} 秒后自动撤销（Ctrl-C 可提前撤销）。
放行：节点 $(count_lines "$tmp/nodes.txt") 个，DNS $(count_lines "$tmp/dns.txt") 个，国内网段 $(count_lines "$tmp/cn.txt") 条，额外 $(count_lines "$tmp/extra.txt") 条。

如果系统变慢或断网，运行 sudo bash scripts/sandgate-pf.sh uninstall。万一卡住，直接重启，规则不会保留。
EOF

  seen=$(fingerprint "$src")
  local end=$(( $(/bin/date +%s) + secs )) current
  while [ "$(/bin/date +%s)" -lt "$end" ]; do
    /bin/sleep "$SYNC_SECONDS"
    current=$(fingerprint "$src")
    if [ "$current" != "$seen" ] && sync_tables "$src" "$tmp"; then
      seen=$current
    fi
  done
  echo "时间到，正在撤销。"
}

uninstall() {
  need_root
  /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1
  pf_release
  /bin/rm -f "$PLIST" "$INSTALLED" "$ENV_FILE"
  echo "已移除。"
}

status() {
  need_root
  [ -f "$PLIST" ] && echo "launchd: 已安装" || echo "launchd: 未安装"
  $PFCTL -s info 2>/dev/null | /usr/bin/grep -E '^Status'
  local list
  for list in $LISTS; do
    echo "sg_$list: $($PFCTL -a "$ANCHOR" -t "sg_$list" -T show 2>/dev/null | $AWK 'END{print NR}') 条"
  done
  echo "当前规则："
  $PFCTL -a "$ANCHOR" -s rules 2>/dev/null
}

case "${1:-}" in
  render) validate_options; shift; render "$@" ;;
  check) shift; check "${1:-}" ;;
  trial) shift; trial "${1:-1800}" ;;
  install)
    echo "install 暂未开放：新规则要先通过长时间试运行，才能跨重启生效。详见 README。" >&2
    exit 2
    ;;
  uninstall) uninstall ;;
  status) status ;;
  *) /usr/bin/sed -n '2,17p' "$0" | /usr/bin/sed 's/^# \{0,1\}//'; exit 2 ;;
esac
