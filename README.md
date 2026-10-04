# SSH 公钥登录配置

为服务器的 **root 账号** 添加自己的 SSH 公钥，默认保留旧公钥和密码登录。

需要 Bash、Python 3.9+、OpenSSH，以及支持重载的 SSH 服务。

## 快速使用

### 1. 下载代码

```bash
git clone https://github.com/baixiaoshengofficial/ssh_key.git
cd ssh_key
```

先查看源码再执行。`cssh.sh` 和 `cssh.py` 需要放在同一目录。

### 2. 添加公钥

将自己的 `.pub` 公钥文件上传到服务器，例如 `/root/login.pub`。**私钥留在客户端。**

```bash
sudo bash cssh.sh --key-file /root/login.pub
```

可以在公钥文件中放多把公钥，每行一把。已有公钥及其访问限制会保留。

### 3. 测试登录

保留当前连接，在客户端新开终端测试，替换下面的私钥路径和服务器 IP：

```bash
ssh -o PreferredAuthentications=publickey -o IdentitiesOnly=yes \
    -i ~/.ssh/id_ed25519 root@服务器IP
```

## 可选操作

**确认新公钥能登录后再执行。** 将 `SHA256:你的指纹` 替换为添加公钥时输出的已测试指纹。

```bash
# 关闭密码和键盘交互登录，保留所有公钥
sudo bash cssh.sh --key-file /root/login.pub --disable-password \
    --confirm-fingerprint SHA256:你的指纹

# 停用其他公钥，只保留本次提供的公钥
sudo bash cssh.sh replace --key-file /root/login.pub \
    --confirm-fingerprint SHA256:你的指纹
```

需要同时替换公钥并关闭密码时，在 `replace` 命令中加 `--disable-password`。

## 注意

- 完成新窗口登录测试前，不要关闭原 SSH 连接；指纹确认不能代替登录测试。
- 存在 `Match` 条件配置或依赖密码的多因素认证时，脚本会拒绝自动关闭密码，需要手动处理。
- 脚本会备份公钥和 SSH 配置，输出备份路径；修改或重载失败会尝试回滚。断电或强制终止时，可通过服务器控制台用备份恢复。

## 测试

```bash
bash -n cssh.sh
python3 -m unittest discover -s tests -v
```

MIT License
