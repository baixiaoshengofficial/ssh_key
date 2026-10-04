# SSH 公钥登录配置

为当前 root 账号安装自己提供的 SSH 公钥。默认 `append`，保留已有记录、密钥限制、密码登录和键盘交互登录。脚本不包含预设授权公钥。

## 获取代码

使用本仓库，并 checkout 到你已审查的完整提交 ID，再阅读源码后执行。不要直接执行远程下载流，也不要只下载 `cssh.sh`；它需要同目录下的 `cssh.py`。

```bash
git clone https://github.com/baixiaoshengofficial/ssh_key.git
cd ssh_key
# 将 REVIEWED_COMMIT 替换为你已审查的完整提交 ID
git checkout --detach REVIEWED_COMMIT
```

依赖：Bash、Python 3.9+（只使用标准库）、OpenSSH 的 `ssh-keygen` 和 `sshd`，以及 systemd 或支持 `reload` 的 SysV SSH 服务。使用标准 `/etc/ssh/sshd_config` 配置路径，以 root 运行。账号与家目录来自系统账户数据库，不使用 `$HOME` 选择目标。

## 先追加并验证

把自己的 **公钥** 上传到服务器（例如 `/root/login.pub`），私钥留在客户端。公钥文件可以包含多个普通公钥，每行一个，也可以包含空行和注释；不能包含私钥或带 options 的授权记录。

```bash
sudo bash cssh.sh --key-file /root/login.pub
# 等价于：sudo bash cssh.sh append --key-file /root/login.pub
```

脚本验证每把公钥，打印 SHA256 指纹，启用公钥认证，并重载 SSH 服务。新增模式保留所有已有行，包括 `from=`、`command=`、`restrict`、FIDO 密钥和证书；同一公钥即使注释不同也不会重复添加，更不会绕过现有限制。

保留当前 SSH 连接，在客户端新开终端，使用对应私钥测试：

```bash
ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no -i ~/.ssh/your_private_key root@your_server_ip
```

必须确认确实通过这把新钥匙登录成功。脚本中的指纹确认是你的人工确认，不能代替登录测试，也不证明你持有对应私钥。

## 替换旧钥匙或关闭密码登录

只有新钥匙登录测试成功后，才使用以下操作。把 `SHA256:YOUR_VERIFIED_FINGERPRINT` 替换为已测试公钥的真实指纹（可以用 `ssh-keygen -lf /root/login.pub` 查看）。

```bash
# 注释其他公钥，保留本次公钥的现有限制；仍保留密码认证策略
sudo bash cssh.sh replace --key-file /root/login.pub \
    --confirm-fingerprint SHA256:YOUR_VERIFIED_FINGERPRINT

# 保留其他公钥，关闭密码与键盘交互登录
sudo bash cssh.sh append --key-file /root/login.pub --disable-password \
    --confirm-fingerprint SHA256:YOUR_VERIFIED_FINGERPRINT
```

也可以在 `replace` 时加 `--disable-password`。没有提供本次公钥的已测试指纹时，危险操作会中止。

## 配置与恢复

- 在配置文件最前面写入标记块，使全局设置优先于后续 `Include`；保留原配置的其他内容。重复执行 `append` 不会撤销此前关闭密码的设置。
- 修改前对候选配置执行 `sshd -t` 和 `sshd -T`，检查全局默认值及当前连接对应的 root 认证策略、root 登录权限和公钥文件位置。
- **存在任何 `Match`（包括被 Include 的文件）时拒绝自动关闭密码。** 条件策略需要管理员单独审查。默认追加模式保留这些策略；它不会宣称已修改所有用户或所有来源的条件规则。
- `Include` 支持普通路径、引号、`*` 和 `?` 通配符。含反斜杠、括号通配符或波浪号路径时中止，避免脚本与 sshd 解析出不同的文件集合。
- 关闭密码时，拒绝要求额外认证步骤的 `AuthenticationMethods`，以免破坏多因素认证或导致无法登录。
- 拒绝符号链接、硬链接、错误所有者和其他用户可写的目标路径。操作使用独占锁、安全临时文件和原子替换。
- 公钥和主配置分别保存唯一备份；`.ssh` 设置为 `700`，`authorized_keys` 和备份为 `600`。
- 修改、校验或服务重载失败时恢复公钥与主配置，并尝试重新加载原配置；任何回滚异常均以失败状态报告，并列出备份位置。使用 `reload`，不主动重启服务。

备份位置会在执行结果中打印。必要时通过保留的 SSH 会话或服务器控制台恢复：

```bash
# 替换为输出中的实际备份文件；不要复制此占位名称直接运行
cp /root/.ssh/authorized_keys.bak.ACTUAL_SUFFIX /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
cp /etc/ssh/sshd_config.bak.ACTUAL_SUFFIX /etc/ssh/sshd_config
sshd -t && systemctl reload ssh
# sshd.service 系统使用 systemctl reload sshd
```

自动回滚覆盖执行期间可捕获的错误与 SIGINT/SIGTERM。断电、磁盘故障或 SIGKILL 可能使自动回滚无法完成，需要通过备份和控制台恢复。脚本只管理当前 root 账号；不会迁移其他账号的公钥。

## 测试

```bash
bash -n cssh.sh
python3 -m unittest discover -s tests -v
```

测试只使用临时目录；配置测试调用真实 `sshd -t/-T`，服务操作由测试对象替代。需要 root 的 SSH 登录集成测试仅在本机回环地址启动独立测试服务，使用临时主机钥匙和客户端钥匙，不修改系统 SSH 服务或配置。

## License

MIT
