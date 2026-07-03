#!/bin/bash

# 添加 SSH 公钥到 authorized_keys（如果不存在）
add_ssh_key_if_not_exists() {
  local ssh_key="$1"
  local key_file="$HOME/.ssh/authorized_keys"

  if grep -qxF "$ssh_key" "$key_file"; then
    echo "✅ SSH 公钥已存在: ${ssh_key:0:30}..."
  else
    echo "$ssh_key" >> "$key_file"
    echo "✅ 已添加 SSH 公钥: ${ssh_key:0:30}..."
  fi
}

# 创建 .ssh 目录及权限
setup_ssh_directory() {
  local ssh_dir="$HOME/.ssh"
  local key_file="$ssh_dir/authorized_keys"

  if [ ! -d "$ssh_dir" ]; then
    echo "📂 创建 .ssh 目录..."
    mkdir -p "$ssh_dir"
    chmod 0700 "$ssh_dir"
  fi

  if [ ! -f "$key_file" ]; then
    echo "📝 创建 authorized_keys 文件..."
    touch "$key_file"
    chmod 0600 "$key_file"
  fi
}

# 注释无效 SSH 公钥行
clean_authorized_keys() {
  local key_file="$HOME/.ssh/authorized_keys"
  local backup_file="$key_file.bak"

  cp "$key_file" "$backup_file"

  awk '{
    if ($1 ~ /^(#|ssh-(rsa|dss|ecdsa|ed25519))/) {
      print $0
    } else {
      print "#" $0 " # Invalid Key Format"
    }
  }' "$backup_file" > "$key_file"

  echo "🧹 已注释格式不正确的 SSH 公钥。"
}

# 修改 /etc/ssh/sshd_config 启用公钥登录，禁用密码登录
configure_sshd() {
  local sshd_config="/etc/ssh/sshd_config"

  if [ ! -w "$sshd_config" ]; then
    echo "❌ 无法写入 $sshd_config，请以 root 权限运行。"
    exit 1
  fi

  sed -i '/^#*PubkeyAuthentication /d' "$sshd_config"
  echo "PubkeyAuthentication yes" >> "$sshd_config"
  echo "✅ 启用公钥登录"

  sed -i '/^#*PasswordAuthentication /d' "$sshd_config"
  echo "PasswordAuthentication no" >> "$sshd_config"
  echo "🚫 禁用密码登录"

  # 重启 SSH 服务
  if systemctl list-units --type=service | grep -q ssh; then
    systemctl restart ssh && echo "🔄 SSH 服务已重启" || echo "⚠️ SSH 重启失败"
  elif command -v service >/dev/null; then
    service ssh restart && echo "🔄 SSH 服务已重启" || echo "⚠️ SSH 重启失败"
  else
    echo "⚠️ 找不到 SSH 服务重启方式，请手动重启"
  fi
}

# 主函数
main() {
  setup_ssh_directory
  clean_authorized_keys

  # 把你自己的公钥放到这里，多设备共用就是共用同一个公钥
  SSH_KEYS=(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHua9naEXdxy5o6aWweI0p4+79mkUyn+gyquxZ1dm6dV dev@baixiaosheng"
  )

  for key in "${SSH_KEYS[@]}"; do
    add_ssh_key_if_not_exists "$key"
  done

  configure_sshd
}

main
