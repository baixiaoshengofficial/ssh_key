# cssh.sh

一键配置 SSH 公钥登录脚本。

该脚本用于快速初始化服务器 SSH 登录方式，支持自动添加指定 SSH 公钥，并可选择：

* **覆盖模式 replace**：只保留脚本内置的公钥，其他公钥会被注释掉
* **新增模式 append**：只添加脚本内置的公钥，不影响已有有效公钥

默认模式为 **replace 覆盖模式**。

---

## 功能特性

* 自动创建 `~/.ssh` 目录
* 自动创建 `~/.ssh/authorized_keys`
* 自动设置正确权限

  * `~/.ssh`：`700`
  * `authorized_keys`：`600`
* 自动备份原始 `authorized_keys`
* 支持添加指定 SSH 公钥
* 支持注释无效 SSH 公钥行
* 支持覆盖模式，只保留指定公钥
* 自动启用 SSH 公钥登录
* 自动禁用 SSH 密码登录
* 自动禁用键盘交互登录
* 自动检测 `sshd_config` 配置是否正确
* 自动重启 SSH 服务

---

## 快速使用

### 默认覆盖模式

默认执行时使用 `replace` 模式。

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh | bash
```

等价于：

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh | bash -s -- replace
```

覆盖模式会：

* 保留脚本中配置的 SSH 公钥
* 注释掉 `authorized_keys` 中其他有效公钥
* 注释掉格式不正确的无效行
* 不会直接删除旧公钥

---

## 新增模式

如果只想添加脚本中的公钥，不影响已有公钥，可以使用 `append` 模式：

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh | bash -s -- append
```

新增模式会：

* 添加脚本中配置的 SSH 公钥
* 保留已有有效公钥
* 注释掉格式不正确的无效行

---

## 参数说明

```bash
bash cssh.sh [append|replace]
```

| 参数        | 说明                       |
| --------- | ------------------------ |
| `replace` | 覆盖模式，只保留脚本中的公钥，其他公钥会被注释掉 |
| `append`  | 新增模式，只添加脚本中的公钥，不影响其他有效公钥 |

如果不传参数，默认使用：

```bash
replace
```

---

## 推荐用法

### 首次初始化服务器

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh | bash
```

### 临时只追加公钥

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh | bash -s -- append
```

### 下载后执行

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh -o cssh.sh
chmod +x cssh.sh
./cssh.sh
```

指定新增模式：

```bash
./cssh.sh append
```

指定覆盖模式：

```bash
./cssh.sh replace
```

---

## 修改 SSH 公钥

打开 `cssh.sh`，找到以下部分：

```bash
SSH_KEYS=(
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHua9naEXdxy5o6aWweI0p4+79mkUyn+gyquxZ1dm6dV dev@baixiaosheng"
)
```

替换成你自己的 SSH 公钥即可。

如果需要配置多个公钥，可以这样写：

```bash
SSH_KEYS=(
  "ssh-ed25519 AAAAxxxxxx user1@device1"
  "ssh-ed25519 AAAAyyyyyy user2@device2"
  "ssh-rsa AAAAzzzzzz user3@device3"
)
```

---

## 覆盖模式说明

覆盖模式不会直接删除旧公钥，而是将旧公钥注释掉。

例如原来有：

```bash
ssh-ed25519 AAAAoldkey old@device
```

执行覆盖模式后会变成：

```bash
# ssh-ed25519 AAAAoldkey old@device # Disabled by SSH key replace mode
```

这样做的好处是：

* 避免误删
* 方便审计
* 可以手动恢复旧公钥

---

## 备份说明

每次执行脚本都会自动备份原来的 `authorized_keys`。

备份文件格式：

```bash
~/.ssh/authorized_keys.bak.年月日_时分秒
```

示例：

```bash
/root/.ssh/authorized_keys.bak.20260703_152846
```

---

## 恢复备份

如果 SSH 登录异常，可以在当前未断开的 SSH 会话中恢复：

```bash
cp ~/.ssh/authorized_keys.bak.20260703_152846 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
systemctl restart ssh
```

如果系统使用的是 `sshd` 服务：

```bash
systemctl restart sshd
```

---

## 安全提醒

执行脚本前，建议保留一个当前 SSH 连接窗口不要关闭。

执行完成后，新开一个终端测试是否可以正常通过公钥登录：

```bash
ssh -i ~/.ssh/your_private_key root@your_server_ip
```

确认新窗口可以登录后，再关闭旧窗口。

---

## 脚本行为

脚本会修改 `/etc/ssh/sshd_config`，并写入以下配置：

```bash
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
```

这表示：

* 启用公钥登录
* 禁用密码登录
* 禁用键盘交互登录

修改后脚本会执行：

```bash
sshd -t
```

只有当 SSH 配置检测通过后，才会重启 SSH 服务。

---

## 常见问题

### 为什么我执行 replace 还是 append？

通过管道执行脚本时，参数必须传给 `bash`，不能直接跟在 `curl` 后面。

错误写法：

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh replace | bash
```

正确写法：

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh | bash -s -- replace
```

不过当前脚本默认就是 `replace`，所以可以直接执行：

```bash
curl -fsSL https://raw.githubusercontent.com/jokerknight/ssh_key/refs/heads/main/cssh.sh | bash
```

---

### 会不会删除我的旧公钥？

不会。

覆盖模式下，旧公钥只会被注释掉，不会被删除。

---

### 支持 Debian / Ubuntu 吗？

支持常见 Debian / Ubuntu 系统。

脚本会尝试重启以下 SSH 服务：

```bash
ssh
sshd
```

如果系统不支持 `systemctl`，会尝试使用：

```bash
service ssh restart
```

---

### 执行脚本需要 root 吗？

推荐使用 root 执行。

因为脚本需要修改：

```bash
/etc/ssh/sshd_config
```

普通用户通常没有权限修改该文件。

---

## License

MIT
