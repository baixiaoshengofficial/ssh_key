import contextlib
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import cssh


class ConfigRunner(cssh.SystemRunner):
    """Use the real OpenSSH parser; never operate on a system service."""
    def __init__(self):
        super().__init__()
        self.reloads = 0
        self.fail_reload = 0
        self.fail_live_validation = False
        self.unavailable = False

    def prepare_reload(self):
        if self.unavailable:
            raise cssh.SafetyError("test service unavailable")

    def reload(self):
        self.reloads += 1
        if self.reloads <= self.fail_reload:
            raise cssh.SafetyError("test reload failure")

    def validate(self, config):
        super().validate(config)
        if self.fail_live_validation and config.name == "sshd_config":
            raise cssh.SafetyError("test live validation failure")


@unittest.skipUnless(shutil.which("ssh-keygen") and shutil.which("sshd"), "OpenSSH tools required")
class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(prefix="cssh-test-keys-")
        cls.material = Path(cls.shared.name)
        for name in ("host", "old", "new"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.material / name)], check=True)
        cls.keys = cssh.load_public_keys(cls.material / "new.pub")
        cls.old_line = (cls.material / "old.pub").read_text().strip()

    @classmethod
    def tearDownClass(cls):
        cls.shared.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cssh-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.sshdir = self.home / ".ssh"
        self.sshdir.mkdir(mode=0o700)
        self.keyfile = self.sshdir / "authorized_keys"
        self.keyfile.write_text(self.old_line + "\n")
        self.keyfile.chmod(0o600)
        self.config = self.root / "sshd_config"
        self.account = cssh.Account(pwd.getpwuid(os.getuid()).pw_name, os.getuid(), self.home)
        self.config.write_text(
            f"HostKey {self.material / 'host'}\n"
            f"PidFile {self.root / 'sshd.pid'}\n"
            f"AuthorizedKeysFile {self.keyfile}\n"
            "PermitRootLogin yes\nUsePAM no\n"
            "PubkeyAuthentication no\nPasswordAuthentication yes\n"
            "KbdInteractiveAuthentication yes\n"
        )
        self.runner = ConfigRunner()
        self.env = mock.patch.dict(os.environ, {"SSH_CONNECTION": "127.0.0.1 30000 127.0.0.1 22"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def apply(self, mode="append", disable=False, confirmations=None):
        return cssh.apply_changes(self.account, self.config, self.keys, mode, disable,
                                  confirmations or [], self.runner)

    def assert_unchanged(self, before):
        self.assertEqual((self.keyfile.read_bytes(), self.config.read_bytes()), before)
        self.assertEqual(self.runner.reloads, 0)

    def test_append_preserves_old_keys_and_password_authentication(self):
        old = self.keyfile.read_bytes()
        backups = self.apply()
        self.assertTrue(self.keyfile.read_bytes().startswith(old))
        self.assertIn(self.keys[0].line, self.keyfile.read_text())
        policy = self.runner.effective(self.config)
        self.assertEqual(policy["passwordauthentication"], "yes")
        self.assertEqual(policy["kbdinteractiveauthentication"], "yes")
        self.assertEqual(self.runner.reloads, 1)
        self.assertEqual(backups[0].read_bytes(), old)
        for path in [self.keyfile, *backups]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_append_is_idempotent_and_backups_are_unique(self):
        first = self.apply()
        state = self.keyfile.read_bytes(), self.config.read_bytes()
        second = self.apply()
        self.assertEqual((self.keyfile.read_bytes(), self.config.read_bytes()), state)
        self.assertFalse(set(first) & set(second))

    def test_restricted_key_with_quotes_in_comment_is_not_unrestricted(self):
        restricted = 'from="127.0.0.1",command="printf hello world",restrict ' + self.keys[0].line + " unmatched ' quote\n"
        self.keyfile.write_text(restricted)
        self.apply()
        self.assertEqual(self.keyfile.read_text(), restricted)

    def test_preserves_unknown_fido_certificate_and_malformed_records(self):
        records = "sk-ssh-ed25519@openssh.com AAAAtest owner\nssh-ed25519-cert-v01@openssh.com AAAAtest owner\nunknown future record\n"
        self.keyfile.write_text(records)
        self.apply()
        self.assertTrue(self.keyfile.read_text().startswith(records))

    def test_no_newline_does_not_concatenate_keys(self):
        self.keyfile.write_text(self.old_line)
        self.apply()
        self.assertEqual(len(self.keyfile.read_text().splitlines()), 2)

    def test_replaces_other_keys_but_preserves_selected_restrictions(self):
        restricted = 'from="127.0.0.1",no-port-forwarding ' + self.keys[0].line
        self.keyfile.write_text(self.old_line + "\n" + restricted + "\n# retained comment\n")
        self.apply("replace", confirmations=[self.keys[0].fingerprint])
        lines = self.keyfile.read_text().splitlines()
        self.assertTrue(lines[0].startswith("# "))
        self.assertEqual(lines[1], restricted)
        self.assertEqual(lines[2], "# retained comment")

    def test_destructive_operations_require_matching_confirmation(self):
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        for mode, disable, confirm in [("replace", False, []), ("append", True, []), ("replace", True, ["SHA256:wrong"])]:
            with self.subTest(mode=mode, disable=disable, confirm=confirm):
                with self.assertRaises(cssh.SafetyError):
                    self.apply(mode, disable, confirm)
                self.assert_unchanged(before)

    def test_include_does_not_override_password_hardening(self):
        included = self.root / "cloud.conf"
        included.write_text("PasswordAuthentication yes\nKbdInteractiveAuthentication yes\n")
        self.config.write_text(f'Include "{included}"\n' + self.config.read_text())
        self.apply(disable=True, confirmations=[self.keys[0].fingerprint])
        policy = self.runner.effective(self.config)
        self.assertEqual(policy["passwordauthentication"], "no")
        self.assertEqual(policy["kbdinteractiveauthentication"], "no")
        self.assertTrue(self.config.read_text().startswith(cssh.BEGIN))

    def test_append_does_not_undo_previous_password_hardening(self):
        self.apply(disable=True, confirmations=[self.keys[0].fingerprint])
        self.apply()
        self.assertEqual(self.runner.effective(self.config)["passwordauthentication"], "no")

    def test_match_is_preserved_for_append(self):
        block = "Match User nobody\n    PasswordAuthentication yes\n"
        self.config.write_text(self.config.read_text() + block)
        self.apply()
        self.assertTrue(self.config.read_text().endswith(block))

    def test_match_blocks_hardening_in_main_nested_and_equals_include(self):
        original = self.config.read_text()
        for location in ("main", "nested", "equals"):
            with self.subTest(location=location):
                if location == "main":
                    self.config.write_text(original + "Match User nobody\nPasswordAuthentication yes\n")
                else:
                    nested = self.root / "nested.conf"
                    nested.write_text("mAtCh User nobody\nPasswordAuthentication yes\n")
                    included = self.root / "include.conf"
                    included.write_text(f'Include "{nested}"\n')
                    directive = f"Include={included}" if location == "equals" else f"Include {included}"
                    self.config.write_text(original + directive + "\n")
                before = self.keyfile.read_bytes(), self.config.read_bytes()
                with self.assertRaisesRegex(cssh.SafetyError, "Match"):
                    self.apply(disable=True, confirmations=[self.keys[0].fingerprint])
                self.assert_unchanged(before)

    def test_match_can_block_selected_root_public_key_policy(self):
        self.config.write_text(self.config.read_text() + f"Match User {self.account.name}\nPubkeyAuthentication no\n")
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        with self.assertRaisesRegex(cssh.SafetyError, "公钥认证"):
            self.apply()
        self.assert_unchanged(before)

    def test_hash_in_include_filename_does_not_hide_match(self):
        included = self.root / "config#conditional"
        included.write_text("Match User nobody\nPasswordAuthentication yes\n")
        self.config.write_text(self.config.read_text() + f"Include {included}\n")
        # Prove the server accepts this filename, then require our scanner to see it.
        self.runner.validate(self.config)
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        with self.assertRaisesRegex(cssh.SafetyError, "Match"):
            self.apply(disable=True, confirmations=[self.keys[0].fingerprint])
        self.assert_unchanged(before)

    def test_quoted_directives_cannot_hide_conditional_policy(self):
        included = self.root / "quoted.conf"
        included.write_text('"Match" User nobody\nPasswordAuthentication yes\n')
        self.config.write_text(self.config.read_text() + f'"Include"="{included}"\n')
        self.runner.validate(self.config)
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        with self.assertRaisesRegex(cssh.SafetyError, "Match"):
            self.apply(disable=True, confirmations=[self.keys[0].fingerprint])
        self.assert_unchanged(before)

    def test_include_whitespace_comment_and_glob(self):
        directory = self.root / "include space"
        directory.mkdir()
        included = directory / "01.conf"
        included.write_text("PasswordAuthentication yes\n")
        self.config.write_text(f'Include "{directory}/*.conf" # trailing comment\n' + self.config.read_text())
        self.apply(disable=True, confirmations=[self.keys[0].fingerprint])
        self.assertEqual(self.runner.effective(self.config)["passwordauthentication"], "no")

    def test_ambiguous_include_globs_fail_closed(self):
        original = self.config.read_text()
        for pattern in (r"/etc/ssh/file\*.conf", "/etc/ssh/[[:alpha:]].conf", "~/config"):
            self.config.write_text(original + f"Include {pattern}\n")
            before = self.keyfile.read_bytes(), self.config.read_bytes()
            with self.assertRaises(cssh.SafetyError):
                self.apply()
            self.assert_unchanged(before)

    def test_relative_include_and_cycles(self):
        included = self.root / "relative.conf"
        included.write_text("Match User nobody\nPasswordAuthentication yes\n")
        self.config.write_text(self.config.read_text() + "Include relative.conf\n")
        with mock.patch.object(cssh, "CONFIG", self.config):
            self.assertTrue(cssh.inspect_config(self.config, self.account.uid))
        included.write_text(f"Include {self.config}\n")
        with mock.patch.object(cssh, "CONFIG", self.config):
            with self.assertRaisesRegex(cssh.SafetyError, "循环"):
                cssh.inspect_config(self.config, self.account.uid)

    def test_mfa_cannot_be_disabled(self):
        self.config.write_text(self.config.read_text() + "AuthenticationMethods publickey,password\n")
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        with self.assertRaises(cssh.SafetyError):
            self.apply(disable=True, confirmations=[self.keys[0].fingerprint])
        self.assert_unchanged(before)

    def test_wrong_authorized_keys_path_is_rejected(self):
        self.config.write_text(self.config.read_text().replace(str(self.keyfile), str(self.root / "other")))
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        with self.assertRaisesRegex(cssh.SafetyError, "authorized_keys"):
            self.apply()
        self.assert_unchanged(before)

    def test_invalid_candidate_leaves_keys_and_config_unchanged(self):
        self.config.write_text(self.config.read_text() + "UnsupportedTestDirective yes\n")
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        with self.assertRaises(cssh.SafetyError):
            self.apply()
        self.assert_unchanged(before)
        self.assertFalse(list(self.root.glob(".cssh-check-*")))

    def test_service_unavailable_leaves_files_unchanged(self):
        self.runner.unavailable = True
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        with self.assertRaises(cssh.SafetyError):
            self.apply()
        self.assert_unchanged(before)

    def test_reload_failure_restores_both_files_and_directory_mode(self):
        self.sshdir.chmod(0o750)
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        self.runner.fail_reload = 1
        with self.assertRaisesRegex(cssh.SafetyError, "已恢复"):
            self.apply()
        self.assertEqual((self.keyfile.read_bytes(), self.config.read_bytes()), before)
        self.assertEqual(self.runner.reloads, 2)
        self.assertEqual(stat.S_IMODE(self.sshdir.stat().st_mode), 0o750)

    def test_live_validation_failure_rolls_back(self):
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        self.runner.fail_live_validation = True
        with self.assertRaises(cssh.SafetyError):
            self.apply()
        self.assertEqual((self.keyfile.read_bytes(), self.config.read_bytes()), before)

    def test_partial_write_failure_restores_keys_and_config(self):
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        write = cssh.atomic_write
        failed = False
        def fail_once(path, data, mode=0o600):
            nonlocal failed
            if path == self.config and not failed:
                failed = True
                raise OSError("test config write failure")
            return write(path, data, mode)
        with mock.patch.object(cssh, "atomic_write", fail_once):
            with self.assertRaisesRegex(cssh.SafetyError, "已恢复"):
                self.apply()
        self.assertEqual((self.keyfile.read_bytes(), self.config.read_bytes()), before)

    def test_backup_failure_happens_before_live_file_changes(self):
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        save = cssh.saved_file
        def fail_backup(path, data, prefix, mode=0o600):
            if prefix.startswith("sshd_config.bak."):
                raise OSError("test backup failure")
            return save(path, data, prefix, mode)
        with mock.patch.object(cssh, "saved_file", fail_backup):
            with self.assertRaises(OSError):
                self.apply()
        self.assert_unchanged(before)

    def test_rollback_reload_failure_is_reported(self):
        self.runner.fail_reload = 2
        with self.assertRaisesRegex(cssh.SafetyError, "回滚结果: test reload failure"):
            self.apply()

    def test_failed_fresh_install_removes_new_keyfile(self):
        self.keyfile.unlink()
        self.sshdir.rmdir()
        self.runner.fail_reload = 1
        original = self.config.read_bytes()
        with self.assertRaises(cssh.SafetyError):
            self.apply()
        self.assertFalse(self.sshdir.exists())
        self.assertEqual(self.config.read_bytes(), original)

    def test_signal_triggers_rollback(self):
        before = self.keyfile.read_bytes(), self.config.read_bytes()
        real_reload = self.runner.reload
        def interrupted_reload():
            if self.runner.reloads == 0:
                self.runner.reloads += 1
                os.kill(os.getpid(), signal.SIGTERM)
            real_reload()
        with mock.patch.object(self.runner, "reload", interrupted_reload):
            with self.assertRaises(cssh.SafetyError):
                self.apply()
        self.assertEqual((self.keyfile.read_bytes(), self.config.read_bytes()), before)

    def test_symlink_target_paths_are_rejected(self):
        victim = self.root / "victim"
        victim.write_text("do not overwrite\n")
        for target in (self.keyfile, self.config):
            with self.subTest(target=target):
                contents = target.read_bytes()
                target.unlink()
                target.symlink_to(victim)
                with self.assertRaises(cssh.SafetyError):
                    self.apply()
                self.assertEqual(victim.read_text(), "do not overwrite\n")
                target.unlink()
                target.write_bytes(contents)
                target.chmod(0o600)

    def test_symlink_ssh_directory_is_rejected(self):
        self.keyfile.unlink()
        self.sshdir.rmdir()
        other = self.root / "other-dir"
        other.mkdir()
        self.sshdir.symlink_to(other)
        with self.assertRaises(cssh.SafetyError):
            self.apply()
        self.assertFalse(list(other.iterdir()))

    def test_hardlink_keys_are_rejected(self):
        os.link(self.keyfile, self.root / "hardlinked")
        with self.assertRaises(cssh.SafetyError):
            self.apply()

    def test_other_user_writable_home_is_rejected(self):
        self.home.chmod(0o777)
        with self.assertRaises(cssh.SafetyError):
            self.apply()

    def test_symlink_lock_is_not_followed(self):
        victim = self.root / "victim"
        victim.write_text("unchanged")
        (self.root / ".cssh.lock").symlink_to(victim)
        with self.assertRaises(OSError):
            self.apply()
        self.assertEqual(victim.read_text(), "unchanged")

    def test_concurrent_operation_is_rejected(self):
        with cssh.exclusive_lock(self.config, self.account.uid):
            with self.assertRaisesRegex(cssh.SafetyError, "正在运行"):
                self.apply()

    def test_empty_private_and_corrupt_key_inputs_are_rejected(self):
        for data in ("", "# comments only\n", (self.material / "new").read_text(), "ssh-ed25519 AAAAnotvalid broken\n"):
            with self.subTest(data=data[:20]):
                path = self.root / "input"
                path.write_text(data)
                with self.assertRaises(cssh.SafetyError):
                    cssh.load_public_keys(path)

    def test_key_type_must_match_encoded_blob(self):
        path = self.root / "input"
        path.write_text(self.keys[0].line.replace("ssh-ed25519", "ssh-rsa", 1))
        with self.assertRaises(cssh.SafetyError):
            cssh.load_public_keys(path)

    def test_duplicate_input_comments_do_not_duplicate_keys(self):
        path = self.root / "input"
        path.write_text(self.keys[0].line + "\n" + self.keys[0].line + " other comment\n")
        self.assertEqual(len(cssh.load_public_keys(path)), 1)

    def test_home_environment_does_not_select_root_target(self):
        with mock.patch.dict(os.environ, {"HOME": str(self.root)}), mock.patch.object(os, "getuid", return_value=0), mock.patch.object(os, "geteuid", return_value=0), mock.patch.object(cssh, "apply_changes", return_value=[]) as apply:
            with contextlib.redirect_stdout(__import__("io").StringIO()):
                result = cssh.main(["--key-file", str(self.material / "new.pub")])
            self.assertEqual(result, 0)
            self.assertEqual(apply.call_args.args[0].home, Path(pwd.getpwuid(0).pw_dir))

    def test_nonroot_rejected_before_key_loading(self):
        with mock.patch.object(os, "geteuid", return_value=1000), mock.patch.object(cssh, "load_public_keys") as load:
            with contextlib.redirect_stderr(__import__("io").StringIO()):
                self.assertEqual(cssh.main(["--key-file", str(self.root / "missing")]), 1)
            load.assert_not_called()

    @unittest.skipUnless(os.getuid() == 0, "isolated SSH login test requires root")
    def test_real_ssh_login_append_replace_and_hardening(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.config.write_text(self.config.read_text().replace("UsePAM no", "UsePAM yes").replace("PubkeyAuthentication no", "PubkeyAuthentication yes") +
                               f"ListenAddress 127.0.0.1\nPort {port}\nStrictModes no\nLogLevel ERROR\n")
        # StrictModes is disabled only for this fixture's temporary home.
        known = self.root / "known_hosts"
        known.write_text(f"[127.0.0.1]:{port} " + (self.material / "host.pub").read_text())
        log = open(self.root / "daemon.log", "w+")
        daemon = subprocess.Popen([self.runner.sshd, "-D", "-e", "-f", str(self.config)], stdout=log, stderr=log)
        self.addCleanup(log.close)
        def stop():
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=5)
        self.addCleanup(stop)
        for _ in range(100):
            if daemon.poll() is not None:
                log.seek(0)
                self.fail("test sshd failed: " + log.read())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            self.fail("test sshd did not start")

        def login(name):
            return subprocess.run(["ssh", "-F", "/dev/null", "-p", str(port), "-i", str(self.material / name),
                                   "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
                                   "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
                                   "-o", "ConnectTimeout=3", "root@127.0.0.1", "printf CSSH_LOGIN_OK"],
                                  capture_output=True, text=True, timeout=10)
        result = login("old")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.endswith("CSSH_LOGIN_OK"))
        self.assertNotEqual(login("new").returncode, 0)
        def reload_fixture():
            daemon.send_signal(signal.SIGHUP)
            time.sleep(0.1)
        with mock.patch.object(self.runner, "reload", reload_fixture):
            self.apply()
            for name in ("old", "new"):
                result = login(name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.endswith("CSSH_LOGIN_OK"))
            restricted = 'command="printf CSSH_RESTRICTED",restrict ' + self.keys[0].line
            self.keyfile.write_text(self.old_line + "\n" + restricted + "\n")
            self.apply()
            result = login("new")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.endswith("CSSH_RESTRICTED"))
            self.apply("replace", True, [self.keys[0].fingerprint])
            result = login("new")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.endswith("CSSH_RESTRICTED"))
            self.assertNotEqual(login("old").returncode, 0)
            self.assertEqual(self.runner.effective(self.config)["passwordauthentication"], "no")


if __name__ == "__main__":
    unittest.main()
