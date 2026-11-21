// 文件职责：封装脱离终端会话的 POSIX 原子替换脚本（launchDetachedSwapper），保障替换失败自动回滚不失联。
package tailscale

import (
	"cmp"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// launchDetachedSwapper spawns an isolated POSIX /bin/sh process (Setsid=true) that performs:
// grace delay -> stop old daemon -> same-fs mv backup & swap -> start new daemon -> health gate -> cleanup/rollback.
func launchDetachedSwapper(paths UpgradePaths, pre *UpgradePreflight, combined bool, force bool, graceDelaySec, healthTimeoutSec int, toVersion string) (int, error) {
	paths = paths.withDefaults()
	if err := os.MkdirAll(filepath.Dir(paths.LogFile), 0755); err != nil {
		return 0, fmt.Errorf("mkdir log dir: %w", err)
	}
	logF, err := os.OpenFile(paths.LogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return 0, fmt.Errorf("open upgrade log file: %w", err)
	}
	defer logF.Close()

	nowTime := time.Now().UTC()
	startedAt := nowTime.Format(time.RFC3339)

	initialState := &UpgradeState{
		Phase:                UpgradePhaseSwapping,
		FromVersion:          cmp.Or(pre.CurrentVersion, "unknown"),
		ToVersion:            toVersion,
		Arch:                 pre.Arch,
		Combined:             combined,
		Force:                force,
		StartedAt:            startedAt,
		UpdatedAt:            startedAt,
		FlashFreeBeforeBytes: pre.FlashFreeBytes,
		Message:              fmt.Sprintf("已脱离父进程接管，正在原子切换 Tailscale (%s -> %s)...", cmp.Or(pre.CurrentVersion, "unknown"), toVersion),
	}
	if err := WriteUpgradeState(paths, initialState); err != nil {
		return 0, err
	}

	boolFlag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}

	args := []string{
		"-c", posixDetachedSwapperScript, "--",
		paths.InstallDir,
		pre.InitSystem,
		paths.InitScript,
		paths.SystemdUnit,
		paths.SocketPath,
		paths.StateFile,
		paths.LockFile,
		boolFlag(combined),
		cmp.Or(pre.CurrentVersion, "unknown"),
		toVersion,
		pre.Arch,
		boolFlag(force),
		boolFlag(pre.TailscaleRunning),
		strconv.Itoa(graceDelaySec),
		strconv.Itoa(healthTimeoutSec),
		startedAt,
		strconv.FormatUint(pre.FlashFreeBytes, 10),
	}

	cmd := exec.Command("/bin/sh", args...)
	cmd.Stdin = nil
	cmd.Stdout = logF
	cmd.Stderr = logF
	detachCmdAttrs(cmd)

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start detached swapper: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	return pid, nil
}

// Strict POSIX sh (BusyBox ash + Debian dash/bash compatible):
// - All parameters injected positionally ($1..$17, shift 9 -> no hardcoded strings).
// - Zero /tmp binary copies: pure same-filesystem mv swap & atomic rollback.
const posixDetachedSwapperScript = `umask 077
INSTALL_DIR=$1; INIT_SYSTEM=$2; INIT_SCRIPT=$3; SYSTEMD_UNIT=$4
SOCKET_PATH=$5; STATE_FILE=$6; LOCK_FILE=$7; COMBINED=$8
FROM_VER=$9; shift 9
TO_VER=$1; ARCH=$2; FORCE=$3; WAS_RUNNING=$4
GRACE_SEC=$5; HEALTH_TIMEOUT=$6; STARTED_AT=$7; FREE_BEFORE=$8

if [ -f "$LOCK_FILE" ]; then
  _old=$(cat "$LOCK_FILE" 2>/dev/null || true)
  if [ -n "$_old" ] && kill -0 "$_old" 2>/dev/null; then
    echo "[ABORT] Another tailscale swapper is active (PID $_old)"
    exit 1
  fi
fi
printf '%s\n' "$$" > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

json_esc() {
  printf '%s' "$1" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

get_free_bytes() {
  _kb=$(df -Pk "$INSTALL_DIR" 2>/dev/null | awk 'NR==2{print $4}')
  case "$_kb" in
    ''|*[!0-9]*) printf '0' ;;
    *) awk -v kb="$_kb" 'BEGIN { printf "%.0f", kb * 1024 }' ;;
  esac
}

write_state() {
  _phase=$1
  _msg=$(json_esc "$2")
  _err=$(json_esc "$3")
  _rb=$4
  _fin=$5
  _free_after=$6
  _now=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' "$STARTED_AT")
  _comb_json=false
  [ "$COMBINED" = "1" ] && _comb_json=true
  _force_json=false
  [ "$FORCE" = "1" ] && _force_json=true
  cat > "${STATE_FILE}.tmp.$$" <<EOF
{"phase":"$_phase","fromVersion":"$(json_esc "$FROM_VER")","toVersion":"$(json_esc "$TO_VER")","arch":"$(json_esc "$ARCH")","combined":$_comb_json,"force":$_force_json,"startedAt":"$(json_esc "$STARTED_AT")","updatedAt":"$_now","finishedAt":"$_fin","flashFreeBeforeBytes":$FREE_BEFORE,"flashFreeAfterBytes":$_free_after,"message":"$_msg","error":"$_err","rolledBack":$_rb,"swapperPid":$$}
EOF
  chmod 600 "${STATE_FILE}.tmp.$$" 2>/dev/null || true
  mv -f "${STATE_FILE}.tmp.$$" "$STATE_FILE"
}

is_tailscaled_running() {
  if command -v pidof >/dev/null 2>&1; then
    pidof tailscaled >/dev/null 2>&1
    return $?
  fi
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -f "$INSTALL_DIR/tailscaled" >/dev/null 2>&1
    return $?
  fi
  if command -v ps >/dev/null 2>&1; then
    ps 2>/dev/null | grep -q '[t]ailscaled'
    return $?
  fi
  return 0
}

stop_tailscaled() {
  if [ "$INIT_SYSTEM" = "procd" ]; then
    "$INIT_SCRIPT" stop >/dev/null 2>&1 || true
  else
    systemctl stop "$SYSTEMD_UNIT" >/dev/null 2>&1 || true
  fi
  _w=0
  while [ "$_w" -lt 5 ]; do
    if ! is_tailscaled_running; then
      rm -f "$SOCKET_PATH"
      return 0
    fi
    sleep 1
    _w=$((_w + 1))
  done
  if command -v killall >/dev/null 2>&1; then
    killall -9 tailscaled >/dev/null 2>&1 || true
  fi
  sleep 1
  rm -f "$SOCKET_PATH"
  return 0
}

start_tailscaled() {
  if [ "$INIT_SYSTEM" = "procd" ]; then
    "$INIT_SCRIPT" start
  else
    systemctl start "$SYSTEMD_UNIT"
  fi
}

do_rollback() {
  _reason=$1
  echo "[ROLLBACK] Triggering automatic rollback: $_reason"
  if [ "$INIT_SYSTEM" = "procd" ] && command -v logread >/dev/null 2>&1; then
    logread -e tailscale 2>/dev/null | tail -n 15 || true
  elif command -v journalctl >/dev/null 2>&1; then
    journalctl -u "$SYSTEMD_UNIT" -n 15 --no-pager 2>/dev/null || true
  fi
  stop_tailscaled || true
  rm -f "$INSTALL_DIR/.tailscaled.new" "$INSTALL_DIR/.tailscale.new" "$INSTALL_DIR/.tailscale.lnk"
  if [ -L "$INSTALL_DIR/.tailscaled.bak" ] || [ -e "$INSTALL_DIR/.tailscaled.bak" ]; then
    mv -f "$INSTALL_DIR/.tailscaled.bak" "$INSTALL_DIR/tailscaled" || true
  fi
  if [ -L "$INSTALL_DIR/.tailscale.bak" ] || [ -e "$INSTALL_DIR/.tailscale.bak" ]; then
    mv -f "$INSTALL_DIR/.tailscale.bak" "$INSTALL_DIR/tailscale" || true
  fi
  start_tailscaled || true
  _rk=0
  _recovered=0
  while [ "$_rk" -lt 15 ]; do
    if [ -S "$SOCKET_PATH" ]; then
      _st=$("$INSTALL_DIR/tailscale" --socket="$SOCKET_PATH" status --json 2>/dev/null || true)
      if [ "$WAS_RUNNING" = "1" ]; then
        if printf '%s' "$_st" | grep -q '"BackendState"[[:space:]]*:[[:space:]]*"Running"'; then
          _recovered=1
          break
        fi
      elif printf '%s' "$_st" | grep -q '"BackendState"'; then
        _recovered=1
        break
      fi
    fi
    sleep 1
    _rk=$((_rk + 1))
  done
  _free_after=$(get_free_bytes)
  _fin=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' "$STARTED_AT")
  if [ "$_recovered" = "1" ]; then
    write_state "rolled_back" "新版启动或连通性校验失败，已自动回滚至旧版本 v$FROM_VER 并恢复在线" "$_reason" "true" "$_fin" "$_free_after"
  else
    write_state "rolled_back" "已自动还原旧版本 v$FROM_VER，服务仍在恢复中" "$_reason" "true" "$_fin" "$_free_after"
  fi
  echo "[ROLLBACK] Finished (recovered=$_recovered)"
  exit 1
}

echo "[INFO] Detached swapper started (PID $$): $FROM_VER -> $TO_VER (init=$INIT_SYSTEM combined=$COMBINED force=$FORCE)"
if [ "$GRACE_SEC" -gt 0 ] 2>/dev/null; then
  echo "[INFO] Waiting ${GRACE_SEC}s grace window so caller responses flush cleanly..."
  sleep "$GRACE_SEC"
fi

write_state "swapping" "正在停止旧版服务并执行同分区原子替换..." "" "false" "" "0"
stop_tailscaled

echo "[INFO] Backing up old binaries and swapping new binaries atomically..."
rm -f "$INSTALL_DIR/.tailscaled.bak" "$INSTALL_DIR/.tailscale.bak" "$INSTALL_DIR/.tailscale.lnk"
if [ -L "$INSTALL_DIR/tailscaled" ] || [ -e "$INSTALL_DIR/tailscaled" ]; then
  mv -f "$INSTALL_DIR/tailscaled" "$INSTALL_DIR/.tailscaled.bak" || do_rollback "failed to backup old tailscaled"
fi
if [ -L "$INSTALL_DIR/tailscale" ] || [ -e "$INSTALL_DIR/tailscale" ]; then
  mv -f "$INSTALL_DIR/tailscale" "$INSTALL_DIR/.tailscale.bak" || do_rollback "failed to backup old tailscale"
fi

mv -f "$INSTALL_DIR/.tailscaled.new" "$INSTALL_DIR/tailscaled" || do_rollback "failed to move .tailscaled.new into place"
chmod 755 "$INSTALL_DIR/tailscaled" 2>/dev/null || true

if [ "$COMBINED" = "1" ]; then
  ln -sf tailscaled "$INSTALL_DIR/.tailscale.lnk" || do_rollback "failed to create tailscale symlink"
  mv -f "$INSTALL_DIR/.tailscale.lnk" "$INSTALL_DIR/tailscale" || do_rollback "failed to install tailscale symlink"
else
  mv -f "$INSTALL_DIR/.tailscale.new" "$INSTALL_DIR/tailscale" || do_rollback "failed to move .tailscale.new into place"
  chmod 755 "$INSTALL_DIR/tailscale" 2>/dev/null || true
fi

echo "[INFO] Starting new tailscaled via $INIT_SYSTEM..."
if ! start_tailscaled; then
  do_rollback "service start command failed"
fi

write_state "verifying" "新版已启动，正在执行 ${HEALTH_TIMEOUT}s 健康门禁校验..." "" "false" "" "0"

_i=0
_ok=0
_idle_ok=0
while [ "$_i" -lt "$HEALTH_TIMEOUT" ]; do
  if [ -S "$SOCKET_PATH" ]; then
    _st=$("$INSTALL_DIR/tailscale" --socket="$SOCKET_PATH" status --json 2>/dev/null || true)
    if [ "$WAS_RUNNING" = "1" ]; then
      if printf '%s' "$_st" | grep -q '"BackendState"[[:space:]]*:[[:space:]]*"Running"'; then
        _ok=1
        break
      fi
    else
      if printf '%s' "$_st" | grep -q '"BackendState"'; then
        _idle_ok=$((_idle_ok + 1))
        if [ "$_idle_ok" -ge 2 ]; then
          _ok=1
          break
        fi
      fi
    fi
  elif [ "$_i" -ge 4 ] && ! is_tailscaled_running; then
    do_rollback "new tailscaled process exited unexpectedly during startup"
  fi
  sleep 1
  _i=$((_i + 1))
done

if [ "$_ok" != "1" ]; then
  do_rollback "health gate timed out after ${HEALTH_TIMEOUT}s without healthy BackendState"
fi

_actual_ver=$("$INSTALL_DIR/tailscale" version 2>/dev/null | head -n 1 || printf '%s' "$TO_VER")
echo "[SUCCESS] Health gate passed (version=$_actual_ver); removing backup binaries..."
rm -f "$INSTALL_DIR/.tailscaled.bak" "$INSTALL_DIR/.tailscale.bak" "$INSTALL_DIR/.tailscaled.new" "$INSTALL_DIR/.tailscale.new" "$INSTALL_DIR/.tailscale.lnk"

_free_after=$(get_free_bytes)
_fin=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' "$STARTED_AT")
if [ "$FORCE" = "1" ] && [ "$FROM_VER" = "$_actual_ver" ]; then
  _done_msg="已完成 Tailscale v$_actual_ver 零失联强制重刷并恢复健康"
else
  _done_msg="已零失联安全升级 Tailscale: $FROM_VER -> $_actual_ver"
fi
write_state "succeeded" "$_done_msg" "" "false" "$_fin" "$_free_after"
echo "[SUCCESS] $_done_msg (flash_free=${_free_after}B)"
exit 0
`
