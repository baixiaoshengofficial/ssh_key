#!/bin/bash

set -e

MODE="${1:-append}"

if [[ "$MODE" != "append" && "$MODE" != "replace" ]]; then
  echo "用法: $0 [append|replace]"
  echo ""
  echo "append  : 新增模式，只添加本次公钥，不处理其他公钥"
  echo "replace : 覆盖模式，只保留本次公钥，其他公钥会被注释掉"
  exit 1
fi

# 创建 .ssh 目录及权限
setup_ssh_directory() {
  local ssh_dir="$HOME/.ssh"
  local key_file="$ssh_dir/authorized_keys"

  if [ ! -d "$ssh_dir" ]; then
    echo "📂 创建 .ssh 目录..."
    mkdir -p "$ssh_dir"
  fi

  chmod 0700 "$ssh_dir"

  if [ ! -f "$key_file" ]; then
    echo "📝 创建 authorized_keys 文件..."
    touch "$key_file"
  fi

  chmod 0600 "$key_file"
}

# 添加 SSH 公钥到 authorized_keys，如果不存在
add_ssh_key_if_not_exists() {
  local ssh_key="$1"
  local key_file="$HOME/.ssh/authorized_keys"

  if grep -qxF "$ssh_key" "$key_file"; then
    echo "✅ SSH 公钥已存在: ${ssh_key:0:30}..."
  else
    echo "$ssh_key" >> "$key_file"
    chmod 0600 "$key_file"
    echo "✅ 已添加 SSH 公钥: ${ssh_key:0:30}..."
  fi
}

# 覆盖模式：注释掉除本次允许公钥以外的其他公钥
replace_authorized_keys() {
  local key_file="$HOME/.ssh/authorized_keys"
  local backup_file="$key_file.bak.$(date +%Y%m%d_%H%M%S)"
  local allowed_keys_file="/tmp/allowed_ssh_keys.$$"

  cp "$key_file" "$backup_file"
  echo "📦 已备份 authorized_keys 到: $backup_file"

  printf "%s\n" "${SSH_KEYS[@]}" > "$allowed_keys_file"

  awk -v allowed_file="$allowed_keys_file" '
    BEGIN {
      while ((getline line < allowed_file) > 0) {
        allowed[line] = 1
      }
      close(allowed_file)
    }

    /^[[:space:]]*$/ {
      print $0
      next
    }

    /^[[:space:]]*#/ {
      print $0
      next
    }

    {
      if (allowed[$0]) {
        print $0
      } else if ($1 ~ /^ssh-(rsa|dss|ecdsa|ed25519)$/ || $1 ~ /^ecdsa-sha2-nistp(256|384|521)$/) {
        print "# " $0 " # Disabled by SSH key replace mode"
      } else {
        print "# " $0 " # Invalid Key Format"
      }
    }
  ' "$backup_file" > "$key_file"

  rm -f "$allowed_keys_file"
  chmod 0600 "$key_file"

  echo "🧹 覆盖模式：已注释除本次允许公钥以外的其他 SSH 公钥。"
}

# 新增模式：只注释无效行，不影响其他有效公钥
clean_invalid_keys_only() {
  local key_file="$HOME/.ssh/authorized_keys"
  local backup_file="$key_file.bak.$(date +%Y%m%d_%H%M%S)"

  cp "$key_file" "$backup_file"
  echo "📦 已备份 authorized_keys 到: $backup_file"

  awk '
    /^[[:space:]]*$/ {
      print $0
      next
    }

    /^[[:space:]]*#/ {
      print $0
      next
    }

    {
      if ($1 ~ /^ssh-(rsa|dss|ecdsa|ed25519)$/ || $1 ~ /^ecdsa-sha2-nistp(256|384|521)$/) {
        print $0
      } else {
        print "# " $0 " # Invalid Key Format"
      }
    }
  ' "$backup_file" > "$key_file"

  chmod 0600 "$key_file"

  echo "🧹 新增模式：已注释格式不正确的 SSH 公钥，其他有效公钥保持不变。"
}

# 修改 /etc/ssh/sshd_config 启用公钥登录，禁用密码登录
configure_sshd() {
  local sshd_config="/etc/ssh/sshd_config"

  if [ ! -w "$sshd_config" ]; then
    echo "❌ 无法写入 $sshd_config，请以 root 权限运行。"
    exit 1
  fi

  sed -i '/^#*[[:space:]]*PubkeyAuthentication[[:space:]]/d' "$sshd_config"
  echo "PubkeyAuthentication yes" >> "$sshd_config"
  echo "✅ 启用公钥登录"

  sed -i '/^#*[[:space:]]*PasswordAuthentication[[:space:]]/d' "$sshd_config"
  echo "PasswordAuthentication no" >> "$sshd_config"
  echo "🚫 禁用密码登录"

  sed -i '/^#*[[:space:]]*KbdInteractiveAuthentication[[:space:]]/d' "$sshd_config"
  echo "KbdInteractiveAuthentication no" >> "$sshd_config"
  echo "🚫 禁用键盘交互登录"

  if sshd -t; then
    echo "✅ sshd 配置检测通过"
  else
    echo "❌ sshd 配置检测失败，未重启 SSH"
    exit 1
  fi

  if systemctl list-unit-files | grep -q '^ssh\.service'; then
    systemctl restart ssh && echo "🔄 SSH 服务已重启" || echo "⚠️ SSH 重启失败"
  elif systemctl list-unit-files | grep -q '^sshd\.service'; then
    systemctl restart sshd && echo "🔄 SSH 服务已重启" || echo "⚠️ SSH 重启失败"
  elif command -v service >/dev/null; then
    service ssh restart && echo "🔄 SSH 服务已重启" || echo "⚠️ SSH 重启失败"
  else
    echo "⚠️ 找不到 SSH 服务重启方式，请手动重启"
  fi
}

main() {
  setup_ssh_directory

  SSH_KEYS=(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHua9naEXdxy5o6aWweI0p4+79mkUyn+gyquxZ1dm6dV dev@baixiaosheng"
  )

  echo "当前模式: $MODE"

  if [[ "$MODE" == "replace" ]]; then
    replace_authorized_keys
  else
    clean_invalid_keys_only
  fi

  for key in "${SSH_KEYS[@]}"; do
    add_ssh_key_if_not_exists "$key"
  done

  configure_sshd
}

main
