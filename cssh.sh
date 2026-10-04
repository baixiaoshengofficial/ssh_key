#!/bin/bash
# SSH public-key setup. Bash and standard Linux/OpenSSH tools only.

# Personal login keys. Add or replace public keys here; never put private keys here.
SSH_KEYS=(
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHua9naEXdxy5o6aWweI0p4+79mkUyn+gyquxZ1dm6dV dev@baixiaosheng"
)

usage() {
  cat <<'HELP'
用法: bash cssh.sh [append|replace]
默认 replace：授权脚本中的 SSH_KEYS 公钥，注释其他公钥。
append：追加内置公钥，保留已有公钥及其访问限制。
两种模式均启用公钥登录、关闭密码和键盘交互登录，仅管理 root 账号。
HELP
}

fail() { printf '失败: %s\n' "$*" >&2; exit 1; }

check_path() {
  local path=$1 kind=$2 owner mode links permissions
  [[ $path != *$'\n'* && $path != *$'\r'* && ! -L $path ]] || fail "不安全的路径: $path"
  if [[ $kind == directory ]]; then
    [[ -d $path ]] || fail "不是目录: $path"
  else
    [[ -f $path ]] || fail "不是普通文件: $path"
  fi
  IFS=' ' read -r owner mode links < <(stat -c '%u %a %h' -- "$path")
  [[ $owner == "$ROOT_UID" ]] || fail "路径所有者错误: $path"
  permissions=$((8#$mode))
  (( (permissions & 0022) == 0 )) || fail "路径可被其他用户写入: $path"
  [[ $kind == directory || $links == 1 ]] || fail "拒绝硬链接: $path"
}

check_parents() {
  local path=$1 parent owner mode permissions
  parent=$(dirname -- "$path")
  while :; do
    [[ -d $parent && ! -L $parent ]] || fail "不安全的父目录: $parent"
    IFS=' ' read -r owner mode < <(stat -c '%u %a' -- "$parent")
    [[ $owner == 0 || $owner == "$ROOT_UID" ]] || fail "父目录所有者错误: $parent"
    permissions=$((8#$mode))
    if (( permissions & 0022 )); then
      [[ $owner == 0 ]] && (( permissions & 01000 )) || fail "父目录可被其他用户修改: $parent"
    fi
    [[ $parent != / ]] || break
    parent=$(dirname -- "$parent")
  done
}

# Read only options/type/blob; comments need not have balanced quotes.
key_fields() {
  local text=$1 char token='' quoted=0 escaped=0 index
  KEY_FIELDS=()
  for ((index=0; index<${#text}; index++)); do
    char=${text:index:1}
    if [[ $char == ' ' || $char == $'\t' || $char == $'\r' ]]; then
      if (( ! quoted )); then
        if [[ -n $token ]]; then
          KEY_FIELDS+=("$token"); token=''
          ((${#KEY_FIELDS[@]} < 3)) || break
        fi
        continue
      fi
    fi
    token+=$char
    if (( escaped )); then
      escaped=0
    elif [[ $char == '\' ]] && (( quoted )); then
      escaped=1
    elif [[ $char == '"' ]]; then
      quoted=$((1-quoted))
    fi
  done
  [[ -z $token || ${#KEY_FIELDS[@]} -ge 3 ]] || KEY_FIELDS+=("$token")
  return 0
}

identify_key() {
  local text=$1 index type blob canonical result
  KEY_ID='' KEY_FINGERPRINT=''
  [[ $text =~ ^[[:space:]]*(#|$) ]] && return 1
  key_fields "$text"
  for index in 0 1; do
    ((${#KEY_FIELDS[@]} > index+1)) || continue
    type=${KEY_FIELDS[index]} blob=${KEY_FIELDS[index+1]}
    [[ $type =~ ^[A-Za-z0-9@._+-]+$ && $blob =~ ^[A-Za-z0-9+/]+=*$ ]] || continue
    [[ $type == ssh-* || $type == ecdsa-* || $type == sk-* ]] || continue
    printf '%s %s\n' "$type" "$blob" > "$WORK/key-check.pub" || fail '无法写入公钥校验文件'
    result=$(timeout 30 ssh-keygen -l -E sha256 -f "$WORK/key-check.pub" 2>/dev/null) || continue
    read -r _ KEY_FINGERPRINT _ <<< "$result"
    [[ $KEY_FINGERPRINT == SHA256:* ]] || continue
    canonical=$(printf '%s' "$blob" | base64 -d 2>/dev/null | base64 -w 0) || continue
    KEY_ID="$type:$canonical"
    return 0
  done
  return 1
}

load_keys() {
  local line first
  KEYS=() KEY_IDS=() FINGERPRINTS=()
  declare -A seen=()
  for line in "${SSH_KEYS[@]}"; do
    [[ $line != *$'\n'* ]] || fail 'SSH_KEYS 每个元素必须是一行公钥'
    line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    identify_key "$line" || fail 'SSH_KEYS 必须填写有效公钥，不能填写私钥'
    read -r first _ <<< "$line"
    [[ $first == "${KEY_FIELDS[0]}" && $KEY_ID == "$first:"* ]] || fail '公钥输入不能包含授权 options'
    if [[ -z ${seen["$KEY_ID"]+yes} ]]; then
      seen["$KEY_ID"]=1
      KEYS+=("$line") KEY_IDS+=("$KEY_ID") FINGERPRINTS+=("$KEY_FINGERPRINT")
    fi
  done
  ((${#KEYS[@]})) || fail 'SSH_KEYS 没有有效公钥；不会修改服务器'
}

# Parse sshd keywords including quoted keywords and optional '=' separators.
config_directive() {
  local text=$1 rest
  KEYWORD='' ARGUMENTS=''
  text=${text#"${text%%[!$' \t\r']*}"}
  [[ -n $text && $text != \#* ]] || return 0
  if [[ $text == \"* ]]; then
    rest=${text:1}
    [[ $rest == *\"* ]] || fail 'SSH 配置关键字引号未闭合'
    KEYWORD=${rest%%\"*}
    rest=${rest#*\"}
    [[ -z $rest || ${rest:0:1} == '=' || ${rest:0:1} == ' ' || ${rest:0:1} == $'\t' || ${rest:0:1} == $'\r' ]] || fail '不支持的配置关键字引用形式'
  else
    KEYWORD=${text%%[=$' \t\r']*}
    [[ $KEYWORD != *\"* ]] || fail '不支持的配置关键字引用形式'
    rest=${text:${#KEYWORD}}
  fi
  rest=${rest#"${rest%%[!$' \t\r']*}"}
  if [[ $rest == =* ]]; then
    rest=${rest:1}
    rest=${rest#"${rest%%[!$' \t\r']*}"}
  fi
  KEYWORD=${KEYWORD,,}
  ARGUMENTS=$rest
}

include_arguments() {
  local text=$1 char quote='' token='' started=0 index
  INCLUDE_ARGS=()
  for ((index=0; index<${#text}; index++)); do
    char=${text:index:1}
    if [[ -z $quote ]]; then
      [[ $char != '#' || $started == 1 ]] || break
      if [[ $char == ' ' || $char == $'\t' || $char == $'\r' ]]; then
        if (( started )); then INCLUDE_ARGS+=("$token"); token=''; started=0; fi
        continue
      fi
      if [[ $char == '"' || $char == "'" ]]; then quote=$char; started=1; continue; fi
    elif [[ $char == "$quote" ]]; then
      quote=''; continue
    fi
    [[ $char != '\' && $char != '[' && $char != ']' ]] || fail 'Include 使用不支持的转义或括号通配符'
    token+=$char; started=1
  done
  [[ -z $quote ]] || fail 'Include 引号未闭合'
  if (( started )); then INCLUDE_ARGS+=("$token"); fi
  for token in "${INCLUDE_ARGS[@]}"; do
    [[ -n $token && $token != '~'* ]] || fail 'Include 使用不支持的路径'
  done
}

inspect_config() {
  local file=$1 depth=${2:-0} line pattern child
  local -a patterns=() matches=()
  local IFS=''
  (( depth < 32 )) || fail 'Include 嵌套过深'
  check_parents "$file"
  check_path "$file" file
  file=$(realpath -ms -- "$file")
  [[ -z ${SCAN_STACK["$file"]+yes} ]] || fail "循环 Include: $file"
  SCAN_STACK["$file"]=1
  while IFS= read -r line || [[ -n $line ]]; do
    config_directive "$line"
    case $KEYWORD in
      match) HAS_MATCH=1 ;;
      include)
        include_arguments "$ARGUMENTS"
        patterns=("${INCLUDE_ARGS[@]}")
        for pattern in "${patterns[@]}"; do
          [[ $pattern == /* ]] || pattern="$CONFIG_DIR/$pattern"
          # Intentional pathname expansion with word splitting disabled; never eval.
          matches=( $pattern )
          for child in "${matches[@]}"; do inspect_config "$child" "$((depth+1))"; done
        done
        ;;
    esac
  done < "$file"
  unset 'SCAN_STACK[$file]'
}

build_keys() {
  local line index last_byte
  declare -A allowed=() present=()
  for index in "${!KEY_IDS[@]}"; do allowed["${KEY_IDS[index]}"]=1; done
  : > "$WORK/new-keys"
  if [[ $MODE == append ]]; then cat -- "$WORK/original-keys" > "$WORK/new-keys"; fi
  while IFS= read -r line || [[ -n $line ]]; do
    if identify_key "$line" && [[ -n ${allowed["$KEY_ID"]+yes} ]]; then
      present["$KEY_ID"]=1
      [[ $MODE != replace ]] || printf '%s\n' "$line" >> "$WORK/new-keys"
    elif [[ $MODE == replace ]]; then
      if [[ $line =~ ^[[:space:]]*(#|$) ]]; then
        printf '%s\n' "$line" >> "$WORK/new-keys"
      else
        printf '# %s # Disabled by SSH key replace mode\n' "$line" >> "$WORK/new-keys"
      fi
    fi
  done < "$WORK/original-keys"
  for index in "${!KEY_IDS[@]}"; do
    if [[ -z ${present["${KEY_IDS[index]}"]+yes} ]]; then
      if [[ -s $WORK/new-keys ]]; then
        last_byte=$(tail -c 1 "$WORK/new-keys" | od -An -tu1)
        if [[ ${last_byte//[[:space:]]/} != 10 ]]; then printf '\n' >> "$WORK/new-keys"; fi
      fi
      printf '%s\n' "${KEYS[index]}" >> "$WORK/new-keys"
    fi
  done
}

build_config() {
  awk -v state="$WORK/hardened" '
    function bad() { print "SSH 配置中的 cssh 管理块损坏" > "/dev/stderr"; error=1; exit 1 }
    /^# BEGIN cssh managed configuration\r?$/ { if (inside) bad(); inside=1; next }
    /^# END cssh managed configuration\r?$/ { if (!inside) bad(); inside=0; next }
    inside {
      sub(/\r$/, "")
      if ($0 != "PubkeyAuthentication yes" && $0 != "PasswordAuthentication no" && $0 != "KbdInteractiveAuthentication no") bad()
      if ($0 == "PasswordAuthentication no" || $0 == "KbdInteractiveAuthentication no") hardened=1
      next
    }
    { print }
    END { if (inside) bad(); if (!error) print hardened+0 > state }
  ' "$WORK/original-config" > "$WORK/config-rest" || fail '无法生成 SSH 配置'
  {
    printf '%s\n' '# BEGIN cssh managed configuration' 'PubkeyAuthentication yes'
    if [[ $DISABLE_PASSWORD == 1 || $(cat "$WORK/hardened") == 1 ]]; then
      printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no'
    fi
    printf '%s\n' '# END cssh managed configuration'
    cat -- "$WORK/config-rest"
  } > "$WORK/new-config"
}

validate_config() { timeout 30 "$SSHD_BIN" -t -f "$1"; }

verify_policy() {
  local config=$1 context name value path expanded found
  local -a contexts=('') paths=()
  local -A policy=()
  contexts+=("$CONNECTION_CONTEXT")
  for context in "${contexts[@]}"; do
    if [[ -n $context ]]; then
      timeout 30 "$SSHD_BIN" -T -f "$config" -C "$context" > "$WORK/effective" || fail '无法读取 SSH 生效策略'
    else
      timeout 30 "$SSHD_BIN" -T -f "$config" > "$WORK/effective" || fail '无法读取 SSH 生效策略'
    fi
    policy=()
    while read -r name value; do policy["$name"]=$value; done < "$WORK/effective"
    [[ ${policy[pubkeyauthentication]:-} == yes ]] || fail 'SSH 策略未启用公钥认证'
    case ${policy[permitrootlogin]:-} in yes|prohibit-password|without-password) ;; *) fail '策略不允许 root 普通公钥登录' ;; esac
    read -r -a paths <<< "${policy[authorizedkeysfile]:-}"
    found=0
    for path in "${paths[@]}"; do
      expanded=${path//%h/$ACCOUNT_HOME}; expanded=${expanded//%u/$ACCOUNT_NAME}; expanded=${expanded//%U/$ROOT_UID}
      [[ $expanded == /* ]] || expanded="$ACCOUNT_HOME/$expanded"
      [[ $expanded != "$KEY_FILE" ]] || found=1
    done
    (( found )) || fail 'sshd 未使用本脚本管理的 authorized_keys'
    if [[ $DISABLE_PASSWORD == 1 ]]; then
      [[ ${policy[passwordauthentication]:-} == no && ${policy[kbdinteractiveauthentication]:-} == no ]] || fail '密码或键盘交互认证仍然开启'
      case ${policy[authenticationmethods]:-} in any|publickey) ;; *) fail 'AuthenticationMethods 要求其他认证步骤' ;; esac
    fi
  done
}

prepare_service() {
  local unit
  for unit in ssh sshd; do
    if command -v systemctl >/dev/null && timeout 15 systemctl is-active --quiet "$unit.service" 2>/dev/null; then
      RELOAD_COMMAND=(systemctl reload "$unit.service"); return 0
    fi
    if command -v service >/dev/null && timeout 15 service "$unit" status >/dev/null 2>&1; then
      RELOAD_COMMAND=(service "$unit" reload); return 0
    fi
  done
  fail '未找到运行中的 SSH 服务；不会修改配置'
}

reload_service() { timeout 30 "${RELOAD_COMMAND[@]}"; }

install_staged_file() {
  local source=$1 target=$2 mode=$3 staged
  staged=$(mktemp "$(dirname -- "$target")/.cssh-stage.XXXXXXXXXX") || return 1
  STAGING_FILES+=("$staged")
  cat -- "$source" > "$staged" && chmod "$mode" "$staged" && mv -fT -- "$staged" "$target"
}

atomic_install() { install_staged_file "$@"; }

save_backup() {
  local source=$1 target=$2
  BACKUP_RESULT=$(mktemp "$target.bak.XXXXXXXXXX") || fail "无法创建备份: $target"
  cat -- "$source" > "$BACKUP_RESULT" || fail "无法写入备份: $target"
  chmod 600 "$BACKUP_RESULT"
}

cleanup() {
  local status=$? recovery=0 staged
  trap - EXIT INT TERM
  set +e
  if [[ ${TRANSACTION_ACTIVE:-0} == 1 ]]; then
    atomic_install "$CONFIG_BACKUP" "$SSHD_CONFIG" "$CONFIG_MODE" || recovery=1
    if [[ $HAD_KEYS == 1 ]]; then
      atomic_install "$KEY_BACKUP" "$KEY_FILE" "$KEY_MODE" || recovery=1
    else
      rm -f -- "$KEY_FILE" || recovery=1
    fi
    for staged in "${STAGING_FILES[@]}"; do rm -f -- "$staged" || recovery=1; done
    if [[ $HAD_DIRECTORY == 1 ]]; then
      chmod "$DIRECTORY_MODE" "$SSH_DIR" || recovery=1
    else
      if [[ -d $SSH_DIR ]]; then rmdir -- "$SSH_DIR" || recovery=1; fi
    fi
    reload_service || recovery=1
    if (( recovery )); then
      printf '回滚未完全成功，请使用备份恢复: %s %s\n' "$CONFIG_BACKUP" "$KEY_BACKUP" >&2
    else
      printf '原公钥和 SSH 配置已恢复，并已重载。\n' >&2
    fi
    (( status != 0 )) || status=1
  fi
  for staged in "${STAGING_FILES[@]}"; do rm -f -- "$staged"; done
  [[ -z ${WORK:-} ]] || rm -rf -- "$WORK"
  exit "$status"
}

apply_changes() {
  local lock candidate source_ip local_ip local_port source_port extra
  SSH_DIR="$ACCOUNT_HOME/.ssh" KEY_FILE="$ACCOUNT_HOME/.ssh/authorized_keys"
  CONFIG_DIR=$(dirname -- "$SSHD_CONFIG")
  check_path "$ACCOUNT_HOME" directory; check_parents "$ACCOUNT_HOME"
  check_path "$CONFIG_DIR" directory; check_parents "$SSHD_CONFIG"
  check_path "$SSHD_CONFIG" file
  lock="$CONFIG_DIR/.cssh.lock"
  if [[ ! -e $lock && ! -L $lock ]]; then
    (set -o noclobber; : > "$lock") || fail '无法安全创建锁文件'
  fi
  check_path "$lock" file
  [[ $(stat -c %a -- "$lock") == 600 ]] || fail '锁文件权限必须为 600'
  exec {LOCK_FD}<> "$lock"
  flock -n "$LOCK_FD" || fail '另一个 cssh 操作正在运行'
  HAD_DIRECTORY=0 HAD_KEYS=0 KEY_BACKUP=''
  if [[ -e $SSH_DIR || -L $SSH_DIR ]]; then
    check_path "$SSH_DIR" directory; HAD_DIRECTORY=1; DIRECTORY_MODE=$(stat -c %a -- "$SSH_DIR")
  fi
  : > "$WORK/original-keys"
  if [[ -e $KEY_FILE || -L $KEY_FILE ]]; then
    check_path "$KEY_FILE" file; HAD_KEYS=1; KEY_MODE=$(stat -c %a -- "$KEY_FILE")
    cat -- "$KEY_FILE" > "$WORK/original-keys"
  fi
  CONFIG_MODE=$(stat -c %a -- "$SSHD_CONFIG")
  cat -- "$SSHD_CONFIG" > "$WORK/original-config"
  HAS_MATCH=0
  declare -gA SCAN_STACK=()
  inspect_config "$SSHD_CONFIG"
  [[ $DISABLE_PASSWORD != 1 || $HAS_MATCH == 0 ]] || fail '配置或 Include 存在 Match；请手动审查条件策略'
  build_keys; build_config
  source_ip=127.0.0.1 local_ip=127.0.0.1 local_port=22
  if [[ -n ${SSH_CONNECTION:-} ]]; then
    read -r source_ip source_port local_ip local_port extra <<< "$SSH_CONNECTION"
    [[ -z $extra && $source_ip =~ ^[0-9A-Fa-f:.]+$ && $local_ip =~ ^[0-9A-Fa-f:.]+$ && $source_port =~ ^[0-9]{1,5}$ && $local_port =~ ^[0-9]{1,5}$ ]] || fail 'SSH_CONNECTION 格式无效'
    (( 10#$local_port > 0 && 10#$local_port <= 65535 )) || fail 'SSH_CONNECTION 端口无效'
  fi
  CONNECTION_CONTEXT="user=$ACCOUNT_NAME,host=$source_ip,addr=$source_ip,laddr=$local_ip,lport=$local_port"
  candidate=$(mktemp "$CONFIG_DIR/.cssh-check.XXXXXXXXXX")
  STAGING_FILES+=("$candidate")
  cat -- "$WORK/new-config" > "$candidate"
  validate_config "$candidate" || fail '候选 SSH 配置无效'
  verify_policy "$candidate"
  prepare_service
  if [[ $HAD_KEYS == 1 ]]; then save_backup "$WORK/original-keys" "$KEY_FILE"; KEY_BACKUP=$BACKUP_RESULT; fi
  save_backup "$WORK/original-config" "$SSHD_CONFIG"; CONFIG_BACKUP=$BACKUP_RESULT
  printf '备份: %s %s\n' "$CONFIG_BACKUP" "$KEY_BACKUP"
  TRANSACTION_ACTIVE=1
  if [[ $HAD_DIRECTORY == 0 ]]; then mkdir -m 700 -- "$SSH_DIR"; fi
  chmod 700 "$SSH_DIR"
  atomic_install "$WORK/new-keys" "$KEY_FILE" 600 || fail '公钥写入失败'
  atomic_install "$WORK/new-config" "$SSHD_CONFIG" "$CONFIG_MODE" || fail 'SSH 配置写入失败'
  validate_config "$SSHD_CONFIG" || fail 'SSH 配置校验失败'
  verify_policy "$SSHD_CONFIG"
  reload_service || fail 'SSH 服务重载失败'
  TRANSACTION_ACTIVE=0
  printf '完成: %s；公钥指纹:\n' "$MODE"
  printf '  %s\n' "${FINGERPRINTS[@]}"
  printf '请保持当前连接，在新窗口测试公钥登录。\n'
}

main() {
  set -Eeuo pipefail
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
  umask 077
  unset GLOBIGNORE
  shopt -s nullglob
  shopt -u dotglob nocaseglob failglob extglob globstar
  (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )) || fail '需要 Bash 4.4+'
  MODE=${1:-replace} DISABLE_PASSWORD=1
  STAGING_FILES=() RELOAD_COMMAND=()
  WORK='' TRANSACTION_ACTIVE=0
  local dependency passwd_line
  (($# <= 1)) || fail '用法: bash cssh.sh [append|replace]'
  case $MODE in
    append|replace) ;;
    -h|--help) usage; return 0 ;;
    *) fail "未知模式: $MODE" ;;
  esac
  (( EUID == 0 && UID == 0 )) || fail '必须以 root 运行；未修改任何文件'
  for dependency in ssh-keygen sshd timeout flock mktemp stat getent realpath base64 awk cat chmod mv dirname tail od rm mkdir rmdir; do
    command -v "$dependency" >/dev/null || fail "缺少系统工具: $dependency"
  done
  ROOT_UID=0 SSHD_CONFIG=/etc/ssh/sshd_config
  passwd_line=$(getent passwd 0) || fail '无法读取 root 账号信息'
  IFS=: read -r ACCOUNT_NAME _ _ _ _ ACCOUNT_HOME _ <<< "$passwd_line"
  [[ $ACCOUNT_NAME =~ ^[A-Za-z0-9_.-]+$ && $ACCOUNT_HOME == /* && $ACCOUNT_HOME != / && $ACCOUNT_HOME != *[[:space:]]* ]] || fail '不支持的 root 账号或家目录'
  SSHD_BIN=$(command -v sshd)
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  WORK=$(mktemp -d /tmp/cssh.XXXXXXXXXX)
  load_keys
  apply_changes
}

# A piped script has no BASH_SOURCE entry; sourced files remain library-only.
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]:-} == "$0" ]]; then main "$@"; fi
