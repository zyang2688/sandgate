#!/bin/bash
# Whole-Mac protection with pf: physical NICs may only reach allow-listed destinations.
# When Clash stops and routes fall back to a NIC, foreign destinations are dropped.
#
# Rules must never match on `user` or `group`. On 2026-11-04 such rules deadlocked the
# kernel: they make the packet path block on the TCP pcbinfo lock via pf_socket_lookup,
# and the watchdog then panicked the machine. Matching on addresses avoids that path.
#
#   install           load at every boot and follow allow-list updates
#   uninstall         remove everything and release pf; also the emergency recovery
#   trial [seconds]   load temporarily and follow allow-list updates (default 1800)
#   status            show current state
#   render            print the rules (no root needed)
#   check <dir>       validate allow-list files (no root needed)
#
# The installed daemon loads the rules once when it starts. After that pfctl runs only
# when a list changes or a new NIC appears, plus brief checks for the first 10 minutes.
# Rules stay in place when the daemon stops, so a crash cannot open a leak.
#
# After an install a reboot no longer clears the rules. As a substitute, if two boots in
# a row end uncleanly within 10 minutes, the daemon stops loading rules until the next
# install, so a panic loop cannot lock the machine out.
#
# Option: ALLOW_LAN (1) passes the local subnet, link-local and multicast.
set -u

ANCHOR="com.apple/sandgate"
LABEL="com.sandgate.pf"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
INSTALLED="/usr/local/sbin/sandgate-pf"
ENV_FILE="/usr/local/etc/sandgate-pf.env"
TOKEN_FILE="/var/run/sandgate-pf.token"
STATE_DIR="/var/db/sandgate-pf"
LOG_FILE="/var/log/sandgate-pf.log"
PFCTL=/sbin/pfctl
AWK=/usr/bin/awk
LISTS="nodes dns cn extra"
MAX_TRIAL=86400
SYNC_SECONDS=30
STABLE_SECONDS=600
MAX_FAILED_BOOTS=2

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

load_rules() { # dir [ifaces...]
  local dir=$1
  shift
  TABLE_DIR="$dir" render "$@" > "$dir/rules.conf" || return 1
  if /usr/bin/grep -Eq '\b(user|group)\b' "$dir/rules.conf"; then
    echo "规则中出现了 user 或 group，拒绝加载" >&2
    return 1
  fi
  $PFCTL -n -a "$ANCHOR" -f "$dir/rules.conf" || { echo "规则语法检查失败" >&2; return 1; }
  $PFCTL -a "$ANCHOR" -f "$dir/rules.conf" 2>/dev/null || { echo "规则加载失败" >&2; return 1; }
}

enable_pf() {
  $PFCTL -E 2>&1 | $AWK '/[Tt]oken/{print $NF}' > "$TOKEN_FILE"
  /bin/chmod 600 "$TOKEN_FILE"
}

note() { echo "$(/bin/date '+%F %T') $*"; }

boot_id() { /usr/sbin/sysctl -n kern.boottime | $AWK '{gsub(",", "", $4); print $4}'; }

# `failed` counts boots that have neither run for STABLE_SECONDS nor stopped cleanly.
# Returns non-zero when rules must not be loaded.
boot_guard() {
  local id failed
  if [ -f "$STATE_DIR/tripped" ]; then
    note "连续异常重启后已停止加载规则，全机防护未生效。确认系统稳定后重新运行 install。"
    return 1
  fi
  id=$(boot_id)
  [ "$(/bin/cat "$STATE_DIR/boot" 2>/dev/null)" = "$id" ] && return 0
  failed=$(/bin/cat "$STATE_DIR/failed" 2>/dev/null)
  [[ "$failed" =~ ^[0-9]+$ ]] || failed=0
  if [ "$failed" -ge "$MAX_FAILED_BOOTS" ]; then
    : > "$STATE_DIR/tripped"
    note "连续 $failed 次开机后未能稳定运行，已停止加载规则，全机防护未生效。确认系统稳定后重新运行 install。"
    return 1
  fi
  echo "$((failed + 1))" > "$STATE_DIR/failed"
  echo "$id" > "$STATE_DIR/boot"
}

read_env() {
  [ -f "$ENV_FILE" ] || { note "缺少 $ENV_FILE"; exit 1; }
  ALLOW_LAN=$(/usr/bin/sed -n 's/^ALLOW_LAN=//p' "$ENV_FILE")
  LISTS_DIR=$(/usr/bin/sed -n 's/^LISTS_DIR=//p' "$ENV_FILE")
  validate_options
  [[ "$LISTS_DIR" == /* ]] || { note "$ENV_FILE 中的 LISTS_DIR 无效"; exit 1; }
}

# com.apple.pfctl also loads /etc/pf.conf at boot and may run after this daemon. Without
# its anchor line, or with pf left disabled, loaded rules would silently do nothing.
verify_loaded() { # lists_dir ifaces...
  local dir=$1
  shift
  if ! $PFCTL -s rules 2>/dev/null | /usr/bin/grep -Fq 'anchor "com.apple/*"'; then
    note "主规则集还没有 com.apple 锚点，加载 /etc/pf.conf"
    $PFCTL -f /etc/pf.conf >/dev/null 2>&1
  fi
  if ! $PFCTL -a "$ANCHOR" -s rules 2>/dev/null | /usr/bin/grep -q .; then
    note "规则不在了，重新加载"
    load_rules "$dir" "$@"
  fi
  if ! $PFCTL -s info 2>/dev/null | /usr/bin/grep -q 'Status: Enabled'; then
    note "pf 未启用，重新启用"
    enable_pf
  fi
}

daemon_stop() {
  [ -n "${SLEEP_PID:-}" ] && kill "$SLEEP_PID" 2>/dev/null
  { echo 0 > "$STATE_DIR/failed"; } 2>/dev/null
  note "收到停止信号，规则保持不变"
  exit 0
}

# Started by launchd. Never releases pf: only uninstall does that.
run() {
  need_root
  read_env
  /bin/mkdir -p "$STATE_DIR/lists" "$STATE_DIR/next"
  /bin/chmod 700 "$STATE_DIR"
  boot_guard || exit 0
  trap daemon_stop TERM INT HUP

  # Tables load from `lists`. New data is validated in `next` first, because a failed
  # validation leaves partial files behind and a later NIC reload reads `lists`.
  local lists="$STATE_DIR/lists" next="$STATE_DIR/next"
  local seen current loaded="" now added i
  seen=$(fingerprint "$LISTS_DIR")
  if clean_all "$LISTS_DIR" "$next"; then
    /bin/cp "$next"/*.txt "$lists"/
  elif clean_all "$lists" "$next"; then
    note "放行列表不可用，使用上次的有效列表"
  else
    note "没有可用的放行列表，全机防护未生效"
    exit 1
  fi

  # networksetup can come up empty this early in boot.
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    loaded=$(physical_interfaces | /usr/bin/tr '\n' ' ')
    [ -n "${loaded// /}" ] && break
    /bin/sleep 5
  done
  [ -n "${loaded// /}" ] || { note "找不到物理网卡，全机防护未生效"; exit 1; }

  load_rules "$lists" $loaded || { note "加载失败，全机防护未生效"; exit 1; }
  [ -s "$TOKEN_FILE" ] || enable_pf
  note "规则已加载：网卡 ${loaded}，节点 $(count_lines "$lists/nodes.txt") 个，国内网段 $(count_lines "$lists/cn.txt") 条"

  local started stable=0
  started=$(/bin/date +%s)
  while :; do
    /bin/sleep "$SYNC_SECONDS" &
    SLEEP_PID=$!
    wait "$SLEEP_PID"

    current=$(fingerprint "$LISTS_DIR")
    if [ "$current" != "$seen" ]; then
      # Recorded even on failure: the current tables stay, and the next change retries.
      seen=$current
      sync_tables "$LISTS_DIR" "$next" && /bin/cp "$next"/*.txt "$lists"/
    fi

    # Only additions matter. A removed NIC's rules are harmless, and a replugged adapter
    # should not cause reloads.
    now=$(physical_interfaces | /usr/bin/tr '\n' ' ')
    added=""
    for i in $now; do
      case " $loaded " in *" $i "*) ;; *) added="$added $i" ;; esac
    done
    if [ -n "$added" ] && load_rules "$lists" $loaded $added; then
      loaded="$loaded $added"
      note "发现新网卡，已重新加载：$loaded"
    fi

    if [ "$stable" = 0 ]; then
      verify_loaded "$lists" $loaded
      if [ "$(( $(/bin/date +%s) - started ))" -ge "$STABLE_SECONDS" ]; then
        stable=1
        echo 0 > "$STATE_DIR/failed"
        note "已稳定运行"
      fi
    fi
  done
}

render_plist() {
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$INSTALLED</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>$LOG_FILE</string>
  <key>StandardErrorPath</key><string>$LOG_FILE</string>
</dict>
</plist>
EOF
}

stop_daemon() {
  /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1
  local i
  for i in {1..20}; do
    /bin/launchctl print "system/$LABEL" >/dev/null 2>&1 || return 0
    /bin/sleep 0.5
  done
}

# A directory a normal user can write to would let them replace what root runs at boot.
root_owned_dir() {
  [ -d "$1" ] || /usr/bin/install -d -o root -g wheel -m 755 "$1" || return 1
  [ "$(/usr/bin/stat -f %u "$1")" = 0 ] || { echo "$1 不属于 root，拒绝安装" >&2; return 1; }
}

do_install() {
  need_root
  validate_options
  if [ -s "$TOKEN_FILE" ] && [ ! -f "$PLIST" ]; then
    echo "试运行还在进行，请先结束它（Ctrl-C 或 uninstall）" >&2
    exit 2
  fi

  local src tmp self i
  src=$(lists_dir) || exit 2
  self="${BASH_SOURCE[0]}"
  root_owned_dir /usr/local/sbin && root_owned_dir /usr/local/etc || exit 1

  # Everything is checked before the old installation is touched.
  tmp=$(/usr/bin/mktemp -d /var/run/sandgate-pf.XXXXXX) || exit 1
  clean_all "$src" "$tmp" || { echo "请先在 SandGate 的「配置」页选好放行节点，并保持 SandGate 运行" >&2; /bin/rm -rf "$tmp"; exit 1; }
  TABLE_DIR="$tmp" render > "$tmp/rules.conf" || { /bin/rm -rf "$tmp"; exit 1; }
  $PFCTL -n -a "$ANCHOR" -f "$tmp/rules.conf" || { echo "规则语法检查失败" >&2; /bin/rm -rf "$tmp"; exit 1; }
  render_plist > "$tmp/daemon.plist"
  /usr/bin/plutil -lint -s "$tmp/daemon.plist" || { /bin/rm -rf "$tmp"; exit 1; }

  stop_daemon
  [ "$self" -ef "$INSTALLED" ] || /usr/bin/install -o root -g wheel -m 755 "$self" "$INSTALLED" || { /bin/rm -rf "$tmp"; exit 1; }
  printf 'ALLOW_LAN=%s\nLISTS_DIR=%s\n' "$ALLOW_LAN" "$src" > "$ENV_FILE"
  /usr/sbin/chown root:wheel "$ENV_FILE"
  /bin/chmod 644 "$ENV_FILE"
  /bin/rm -rf "$STATE_DIR"
  /usr/bin/install -o root -g wheel -m 644 "$tmp/daemon.plist" "$PLIST" || { /bin/rm -rf "$tmp"; exit 1; }
  /bin/rm -rf "$tmp"

  local ok=0
  for i in {1..8}; do
    if /bin/launchctl bootstrap system "$PLIST" 2>/dev/null; then ok=1; break; fi
    /bin/sleep 1
  done
  [ "$ok" = 1 ] || { echo "launchd 加载失败，请运行 uninstall 后重试" >&2; exit 1; }

  for i in {1..20}; do
    $PFCTL -a "$ANCHOR" -s rules 2>/dev/null | /usr/bin/grep -q . && break
    /bin/sleep 0.5
  done
  if ! $PFCTL -a "$ANCHOR" -s rules 2>/dev/null | /usr/bin/grep -q .; then
    echo "服务已安装，但规则没有加载。日志：$LOG_FILE" >&2
    exit 1
  fi

  cat <<EOF
已安装，规则已加载，之后每次开机都会自动加载。放行列表和新网卡由后台服务跟随。

注意：重启不会再清除规则。
- 撤销：sudo $INSTALLED uninstall
- 查看状态：sudo $INSTALLED status
- 日志：$LOG_FILE

连续两次开机都在 ${STABLE_SECONDS} 秒内异常结束时，服务会停止加载规则，防止反复崩溃。
EOF
}

trial() {
  need_root
  validate_options
  local secs="${1:-1800}"
  [[ "$secs" =~ ^[0-9]+$ ]] && [ "$secs" -ge 1 ] && [ "$secs" -le "$MAX_TRIAL" ] \
    || { echo "时长需为 1 到 $MAX_TRIAL 秒" >&2; exit 2; }
  [ -f "$PLIST" ] && { echo "已经安装，无需试运行。要试运行请先运行 uninstall" >&2; exit 2; }

  local src tmp seen
  src=$(lists_dir)
  tmp=$(/usr/bin/mktemp -d /var/run/sandgate-pf.XXXXXX) || exit 1
  clean_all "$src" "$tmp" || { echo "请先在 SandGate 的「配置」页选好放行节点，并保持 SandGate 运行" >&2; /bin/rm -rf "$tmp"; exit 1; }

  load_rules "$tmp" || { /bin/rm -rf "$tmp"; exit 1; }
  enable_pf

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
  stop_daemon
  pf_release
  /bin/rm -f "$PLIST" "$INSTALLED" "$ENV_FILE"
  /bin/rm -rf "$STATE_DIR"
  echo "已移除。"
}

status() {
  need_root
  [ -f "$PLIST" ] && echo "launchd: 已安装" || echo "launchd: 未安装"
  /bin/launchctl print "system/$LABEL" >/dev/null 2>&1 && echo "服务: 已加载" || echo "服务: 未加载"
  [ -f "$STATE_DIR/tripped" ] && echo "异常重启保护已触发，规则不会加载。确认系统稳定后重新运行 install。"
  $PFCTL -s info 2>/dev/null | /usr/bin/grep -E '^Status'
  local list
  for list in $LISTS; do
    echo "sg_$list: $($PFCTL -a "$ANCHOR" -t "sg_$list" -T show 2>/dev/null | $AWK 'END{print NR}') 条"
  done
  echo "当前规则："
  $PFCTL -a "$ANCHOR" -s rules 2>/dev/null
}

# Sourcing defines the functions without running anything; the tests rely on this.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0

case "${1:-}" in
  render) validate_options; shift; render "$@" ;;
  check) shift; check "${1:-}" ;;
  trial) shift; trial "${1:-1800}" ;;
  install) do_install ;;
  run) run ;;
  uninstall) uninstall ;;
  status) status ;;
  *) $AWK 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 2 ;;
esac
