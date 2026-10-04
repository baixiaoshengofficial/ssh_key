# SSH 公钥登录一键脚本

个人使用的纯 Bash 脚本。公钥硬编码在 `cssh.sh` 顶部的 `SSH_KEYS` 中，可以配置多把公钥。

**其他人使用前务必将 `SSH_KEYS` 替换为自己的 `.pub` 公钥，并确保持有对应私钥。保留作者公钥会授权作者的私钥登录你的 root 账号；默认运行还会关闭密码登录，可能导致你无法登录。不要填写或上传私钥。**

## 使用

在 root 终端一键下载并运行：

```bash
curl -fsSL https://raw.githubusercontent.com/baixiaoshengofficial/ssh_key/refs/heads/main/cssh.sh | bash
```

默认 `replace`：授权内置公钥，注释其他公钥，启用公钥登录，关闭密码和键盘交互登录。

只追加内置公钥、保留已有公钥及其限制：

```bash
curl -fsSL https://raw.githubusercontent.com/baixiaoshengofficial/ssh_key/refs/heads/main/cssh.sh | bash -s -- append
```

`append` 同样会关闭密码和键盘交互登录。

已下载脚本时，直接运行 `bash cssh.sh` 或 `bash cssh.sh append`。

其他人请先下载，修改公钥后再运行：

```bash
curl -fsSL https://raw.githubusercontent.com/baixiaoshengofficial/ssh_key/refs/heads/main/cssh.sh -o cssh.sh
```

编辑 `cssh.sh` 顶部的 `SSH_KEYS`，替换为自己的公钥，再执行 `bash cssh.sh`。

## 注意

- 执行前确认你持有内置公钥对应的私钥；保留当前 SSH 连接，新窗口登录成功后再关闭。
- 自动备份公钥和 SSH 配置；修改或重载失败会尝试恢复，备份路径会在输出中显示。
- 配置存在 `Match` 或要求额外认证步骤时中止，避免误改条件策略或锁死登录。

需要 Linux、Bash 4.4+、OpenSSH 和支持重载的 SSH 服务，配置路径为 `/etc/ssh/sshd_config`。

## 测试

```bash
bash tests/run.sh
```

MIT License
