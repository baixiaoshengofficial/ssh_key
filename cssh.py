#!/usr/bin/env python3
"""Install explicitly supplied SSH public keys with a reversible configuration update."""

import argparse
import base64
import contextlib
import dataclasses
import fcntl
import glob
import ipaddress
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile


class SafetyError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class Account:
    name: str
    uid: int
    home: Path


@dataclasses.dataclass(frozen=True)
class PublicKey:
    line: str
    identity: tuple
    fingerprint: str


BEGIN = "# BEGIN cssh managed configuration"
END = "# END cssh managed configuration"
CONFIG = Path("/etc/ssh/sshd_config")


def checked_path(path, uid, directory=False):
    """Reject links and paths writable by another account before privileged access."""
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != uid:
        raise SafetyError(f"不安全的路径类型或所有者: {path}")
    if info.st_mode & 0o022 or (not directory and info.st_nlink != 1):
        raise SafetyError(f"路径可被其他用户写入或存在硬链接: {path}")
    return info


def read_checked(path, uid):
    checked_path(path, uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_mode & 0o022:
            raise SafetyError(f"文件在读取时发生变化: {path}")
        return stream.read()


def checked_parents(path, uid):
    # A root-owned sticky directory (e.g. /tmp) protects existing owned entries.
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}:
            raise SafetyError(f"不安全的父目录: {parent}")
        if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise SafetyError(f"父目录可被其他用户修改: {parent}")


def key_identity(line):
    """Find a key after the optional, possibly quoted authorized_keys options."""
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    try:
        # Only tokenize options/type/blob. Comments are arbitrary text, not shell
        # syntax, and an unmatched quote in a comment must not hide restrictions.
        fields = []
        token = []
        quoted = escaped = False
        for char in line:
            if char.isspace() and not quoted:
                if token:
                    fields.append("".join(token))
                    token = []
                    if len(fields) == 3:
                        break
            else:
                token.append(char)
                if escaped:
                    escaped = False
                elif char == "\\" and quoted:
                    escaped = True
                elif char == '"':
                    quoted = not quoted
        if token and len(fields) < 3:
            fields.append("".join(token))
        for index in (0, 1):
            if len(fields) <= index + 1:
                continue
            key_type, encoded = fields[index:index + 2]
            try:
                blob = base64.b64decode(encoded, validate=True)
            except ValueError:
                continue
            if len(blob) < 4:
                continue
            length = int.from_bytes(blob[:4], "big")
            if blob[4:4 + length] == key_type.encode("ascii"):
                return key_type, base64.b64encode(blob).decode("ascii")
    except (ValueError, UnicodeError):
        pass
    return None


def run_command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SafetyError(f"命令执行失败: {args[0]}: {error}") from error
    if result.returncode:
        raise SafetyError(f"命令执行失败: {shlex.join(map(str, args))}\n{result.stderr.strip()}")
    return result.stdout


def load_public_keys(path):
    if not path.is_file():
        raise SafetyError("--key-file 必须是公钥文本文件")
    keys = []
    seen = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        identity = key_identity(line)
        fields = line.split()
        if not identity or fields[0] != identity[0]:
            raise SafetyError("输入必须是普通 SSH 公钥，不能是私钥或带 options 的记录")
        with tempfile.TemporaryDirectory(prefix="cssh-key-check-") as temp:
            single = Path(temp) / "key.pub"
            single.write_text(line + "\n", encoding="utf-8")
            single.chmod(0o600)
            output = run_command(["ssh-keygen", "-l", "-E", "sha256", "-f", str(single)])
        fingerprint = output.split()[1]
        if not fingerprint.startswith("SHA256:"):
            raise SafetyError("无法验证公钥指纹")
        if identity not in seen:
            seen.add(identity)
            keys.append(PublicKey(line, identity, fingerprint))
    if not keys:
        raise SafetyError("没有提供有效公钥；不会修改服务器")
    return keys


def build_authorized_keys(original, keys, mode):
    allowed = {key.identity for key in keys}
    existing = set()
    output = []
    for line in original.decode("utf-8", errors="surrogateescape").splitlines():
        identity = key_identity(line)
        if identity in allowed:
            existing.add(identity)
        if mode == "replace" and line.strip() and not line.lstrip().startswith("#") and identity not in allowed:
            output.append("# " + line + " # Disabled by SSH key replace mode")
        else:
            # Keep all existing lines and restrictions in append mode.
            output.append(line)
    additions = [key.line for key in keys if key.identity not in existing]
    if mode == "append":
        if not additions:
            return original
        separator = b"\n" if original and not original.endswith(b"\n") else b""
        return original + separator + ("\n".join(additions) + "\n").encode("utf-8")
    output.extend(additions)
    return ("\n".join(output) + "\n").encode("utf-8", errors="surrogateescape")


def include_arguments(text):
    """Accept quoted paths and token-boundary comments without shell expansion."""
    # Escaped glob syntax and POSIX bracket classes differ between glob engines.
    # Refuse these forms instead of silently inspecting a different file set.
    if "\\" in text or "[" in text or "]" in text:
        raise SafetyError("Include 使用了不支持的转义或括号通配符；请手动审查")
    quote = None
    boundary = True
    for index, char in enumerate(text):
        if not quote and boundary and char == "#":
            text = text[:index]
            break
        if char in "\"'":
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
        boundary = char in " \t" and quote is None
    lexer = shlex.shlex(text, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    arguments = list(lexer)
    if any(arg.startswith("~") for arg in arguments):
        raise SafetyError("Include 使用了不支持的波浪号路径；请手动审查")
    return arguments


def inspect_config(path, uid, visited=None, depth=0):
    """Inspect Includes conservatively; refuse conditional password hardening."""
    if depth > 32:
        raise SafetyError("Include 嵌套过深")
    visited = set() if visited is None else visited
    path = Path(os.path.abspath(path))
    if path in visited:
        raise SafetyError(f"循环的 Include: {path}")
    visited.add(path)
    has_match = False
    checked_parents(path, uid)
    for line in read_checked(path, uid).decode("utf-8").splitlines():
        # Match sshd's optional '=' separator, but don't parse unrelated options.
        directive = re.match(r'^[ \t\r]*(?:"([^"\r]*)"|([^\s=#]+))(?:[ \t\r]*=[ \t\r]*|[ \t\r]+)(.*)$', line)
        if not directive:
            if line.lstrip().startswith('"'):
                raise SafetyError(f"不支持的配置关键字引用形式: {path}")
            continue
        quoted_keyword, plain_keyword, arguments = directive.groups()
        if plain_keyword and '"' in plain_keyword:
            raise SafetyError(f"不支持的配置关键字引用形式: {path}")
        keyword = quoted_keyword if quoted_keyword is not None else plain_keyword
        keyword = keyword.lower()
        if keyword == "match":
            has_match = True
        elif keyword == "include":
            try:
                patterns = include_arguments(arguments)
            except ValueError as error:
                raise SafetyError(f"无法安全解析 Include: {path}") from error
            for pattern in patterns:
                # OpenSSH resolves relative Includes against /etc/ssh.
                if not os.path.isabs(pattern):
                    pattern = str(CONFIG.parent / pattern)
                for included in sorted(glob.glob(pattern)):
                    has_match = inspect_config(Path(included), uid, visited, depth + 1) or has_match
    visited.remove(path)
    return has_match


def build_config(original, disable_password):
    lines = original.decode("utf-8").splitlines(keepends=True)
    retained = []
    inside = False
    hardened = False
    for line in lines:
        if line.rstrip("\r\n") == BEGIN:
            if inside:
                raise SafetyError("SSH 配置中的 cssh 标记损坏")
            inside = True
        elif line.rstrip("\r\n") == END:
            if not inside:
                raise SafetyError("SSH 配置中的 cssh 标记损坏")
            inside = False
        elif inside:
            if line.strip() not in {"PubkeyAuthentication yes", "PasswordAuthentication no", "KbdInteractiveAuthentication no"}:
                raise SafetyError("cssh 管理块包含未知配置；请手动检查")
            hardened = hardened or line.strip() == "PasswordAuthentication no"
        else:
            retained.append(line)
    if inside:
        raise SafetyError("SSH 配置中的 cssh 标记未闭合")
    directives = [BEGIN, "PubkeyAuthentication yes"]
    if disable_password or hardened:
        directives += ["PasswordAuthentication no", "KbdInteractiveAuthentication no"]
    directives += [END]
    # First global values beat subsequent Includes; existing Match blocks survive.
    return ("\n".join(directives) + "\n" + "".join(retained)).encode("utf-8")


@contextlib.contextmanager
def exclusive_lock(config, uid):
    path = config.parent / ".cssh.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_mode & 0o077:
            raise SafetyError(f"不安全的锁文件: {path}")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SafetyError("另一个 cssh 操作正在运行") from error
        yield
    finally:
        os.close(fd)


def saved_file(path, data, prefix, mode=0o600):
    fd, name = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    saved = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        saved.unlink(missing_ok=True)
        raise
    return saved


def atomic_write(path, data, mode=0o600):
    staged = saved_file(path, data, ".cssh-stage-", mode)
    try:
        os.replace(staged, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        staged.unlink(missing_ok=True)


class SystemRunner:
    def __init__(self):
        self.sshd = shutil.which("sshd")
        if not self.sshd:
            raise SafetyError("未找到 sshd")
        self.reload_command = None

    def validate(self, config):
        run_command([self.sshd, "-t", "-f", str(config)])

    def effective(self, config, connection=None):
        command = [self.sshd, "-T", "-f", str(config)]
        if connection:
            command += ["-C", connection]
        return dict(line.split(None, 1) for line in run_command(command).splitlines() if " " in line)

    def prepare_reload(self):
        for service in ("ssh", "sshd"):
            if shutil.which("systemctl"):
                try:
                    result = subprocess.run(["systemctl", "is-active", "--quiet", service + ".service"], capture_output=True, timeout=15)
                except (OSError, subprocess.TimeoutExpired):
                    continue
                if result.returncode == 0:
                    self.reload_command = ["systemctl", "reload", service + ".service"]
                    return
            if shutil.which("service"):
                try:
                    result = subprocess.run(["service", service, "status"], capture_output=True, timeout=15)
                except (OSError, subprocess.TimeoutExpired):
                    continue
                if result.returncode == 0:
                    self.reload_command = ["service", service, "reload"]
                    return
        raise SafetyError("未找到运行中的 SSH 服务；不会修改配置")

    def reload(self):
        run_command(self.reload_command)


def verify_policy(runner, config, account, disable_password, connection):
    policies = [runner.effective(config), runner.effective(config, connection)]
    key_path = account.home / ".ssh" / "authorized_keys"
    for policy in policies:
        if policy.get("pubkeyauthentication") != "yes":
            raise SafetyError("当前 SSH 策略未启用公钥认证")
        if policy.get("permitrootlogin") not in {"yes", "prohibit-password", "without-password"}:
            raise SafetyError("当前策略不允许 root 普通公钥登录")
        paths = policy.get("authorizedkeysfile", "").split()
        expanded = [p.replace("%h", str(account.home)).replace("%u", account.name).replace("%U", str(account.uid)) for p in paths]
        if not any((Path(p) if p.startswith("/") else account.home / p) == key_path for p in expanded):
            raise SafetyError("sshd 未使用本脚本管理的 authorized_keys 文件")
        if disable_password:
            if policy.get("passwordauthentication") != "no" or policy.get("kbdinteractiveauthentication") != "no":
                raise SafetyError("密码或键盘交互认证仍然启用")
            if policy.get("authenticationmethods") not in {"any", "publickey"}:
                raise SafetyError("AuthenticationMethods 要求其他认证步骤；拒绝关闭密码认证")


def connection_context(account):
    source, local, port = "127.0.0.1", "127.0.0.1", "22"
    if os.environ.get("SSH_CONNECTION"):
        fields = os.environ["SSH_CONNECTION"].split()
        if len(fields) != 4:
            raise SafetyError("SSH_CONNECTION 格式无效")
        source, _, local, port = fields
        ipaddress.ip_address(source)
        ipaddress.ip_address(local)
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise SafetyError("SSH_CONNECTION 端口无效")
    return f"user={account.name},host={source},addr={source},laddr={local},lport={port}"


def apply_changes(account, config, keys, mode, disable_password, confirmations, runner):
    destructive = mode == "replace" or disable_password
    fingerprints = {key.fingerprint for key in keys}
    if destructive and not confirmations:
        raise SafetyError("请先追加并测试新钥匙登录，再用 --confirm-fingerprint 确认已测试的公钥")
    if not set(confirmations).issubset(fingerprints):
        raise SafetyError("确认的指纹不属于本次提供的公钥")
    checked_path(account.home, account.uid, directory=True)
    checked_path(config.parent, account.uid, directory=True)
    checked_parents(account.home, account.uid)
    checked_parents(config, account.uid)
    with exclusive_lock(config, account.uid):
        return _apply_locked(account, config, keys, mode, disable_password, runner)


def _apply_locked(account, config, keys, mode, disable_password, runner):
    ssh_dir = account.home / ".ssh"
    key_file = ssh_dir / "authorized_keys"
    directory_info = checked_path(ssh_dir, account.uid, directory=True) if os.path.lexists(ssh_dir) else None
    key_info = checked_path(key_file, account.uid) if os.path.lexists(key_file) else None
    config_info = checked_path(config, account.uid)
    original_keys = read_checked(key_file, account.uid) if key_info else b""
    original_config = read_checked(config, account.uid)
    conditional = inspect_config(config, account.uid)
    if disable_password and conditional:
        raise SafetyError("配置或 Include 中存在 Match；拒绝全局关闭密码，请先手动审查条件策略")
    candidate_keys = build_authorized_keys(original_keys, keys, mode)
    candidate_config = build_config(original_config, disable_password)
    context = connection_context(account)
    staged = saved_file(config, candidate_config, ".cssh-check-")
    try:
        runner.validate(staged)
        verify_policy(runner, staged, account, disable_password, context)
        runner.prepare_reload()
    finally:
        staged.unlink(missing_ok=True)

    if not directory_info:
        ssh_dir.mkdir(mode=0o700)
    backups = []
    try:
        if key_info:
            backups.append(saved_file(key_file, original_keys, "authorized_keys.bak."))
        backups.append(saved_file(config, original_config, "sshd_config.bak."))
    except BaseException:
        if not directory_info and not backups:
            ssh_dir.rmdir()
        raise

    def interrupt(signum, frame):
        raise InterruptedError(f"收到信号 {signum}")

    previous = {s: signal.signal(s, interrupt) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        ssh_dir.chmod(0o700)
        atomic_write(key_file, candidate_keys)
        atomic_write(config, candidate_config, stat.S_IMODE(config_info.st_mode))
        runner.validate(config)
        verify_policy(runner, config, account, disable_password, context)
        runner.reload()
    except BaseException as error:
        recovery_errors = []
        for path, contents, info in ((config, original_config, config_info), (key_file, original_keys, key_info)):
            try:
                if info:
                    atomic_write(path, contents, stat.S_IMODE(info.st_mode))
                else:
                    path.unlink(missing_ok=True)
            except BaseException as recovery_error:
                recovery_errors.append(str(recovery_error))
        try:
            if directory_info:
                ssh_dir.chmod(stat.S_IMODE(directory_info.st_mode))
            else:
                ssh_dir.rmdir()
        except OSError as recovery_error:
            recovery_errors.append(str(recovery_error))
        try:
            runner.reload()
        except BaseException as recovery_error:
            recovery_errors.append(str(recovery_error))
        detail = "；".join(recovery_errors) or "原公钥和 SSH 配置已恢复，并已重载"
        raise SafetyError(f"修改失败: {error}\n回滚结果: {detail}\n备份: {', '.join(map(str, backups))}") from error
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return backups


def main(argv=None):
    parser = argparse.ArgumentParser(description="安全配置当前 root 账号的 SSH 公钥登录（默认保留密码登录）")
    parser.add_argument("mode", nargs="?", choices=("append", "replace"), default="append")
    parser.add_argument("--key-file", type=Path, required=True, help="包含一个或多个普通公钥的文件")
    parser.add_argument("--disable-password", action="store_true", help="关闭密码和键盘交互登录")
    parser.add_argument("--confirm-fingerprint", action="append", default=[], help="确认已在新 SSH 会话测试过的 SHA256 公钥指纹")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or os.getuid() != 0:
            raise SafetyError("必须以 root 运行；未修改任何文件")
        entry = pwd.getpwuid(0)
        account = Account(entry.pw_name, 0, Path(entry.pw_dir))
        keys = load_public_keys(args.key_file)
        backups = apply_changes(account, CONFIG, keys, args.mode, args.disable_password, args.confirm_fingerprint, SystemRunner())
        print(f"完成: {args.mode}；公钥: {', '.join(key.fingerprint for key in keys)}")
        print("备份: " + ", ".join(map(str, backups)))
        print("请保持当前连接，并在新窗口测试公钥登录。")
        return 0
    except (SafetyError, OSError, ValueError) as error:
        print(f"失败: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
