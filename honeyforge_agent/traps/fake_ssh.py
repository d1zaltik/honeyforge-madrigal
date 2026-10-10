import socket
import threading
import uuid
import datetime
import hashlib
import paramiko
from typing import Dict, Any, Callable, List
from honeyforge_agent.traps.base import BaseTrapService

class HoneySSHInterface(paramiko.ServerInterface):
    def __init__(self, auth_callback, decoy_creds):
        self.auth_callback = auth_callback
        self.decoy_creds = decoy_creds or [{"user": "root", "pass": "admin123"}, {"user": "admin", "pass": "password"}]
        self.event = threading.Event()
        self.authenticated_user = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        # Notify callback of auth attempt
        is_success = False
        for c in self.decoy_creds:
            if c.get("user") == username and c.get("pass") == password:
                is_success = True
                break
        # Allow root or admin or generic if password is standard for testing
        if username in ["root", "admin", "deploy"] and password in ["admin123", "password", "toor", "123456", "admin"]:
            is_success = True

        self.auth_callback(username, password, is_success)
        if is_success:
            self.authenticated_user = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

class FakeSSHTrap(BaseTrapService):
    """
    FR-A1, FR-A2 (Must): Medium-interaction SSH Honeypot.
    Authentic SSH protocol handshake (Paramiko), credential harverster,
    interactive virtual shell and post-exploitation artifact capture.
    """
    def __init__(
        self,
        port: int,
        event_callback: Callable[[Dict[str, Any]], None],
        session_callback: Callable[[Dict[str, Any]], None],
        trap_id: str,
        decoy_creds: List[Dict[str, str]] = None
    ):
        super().__init__("FakeSSH", port, event_callback)
        self.session_callback = session_callback
        self.trap_id = trap_id
        self.decoy_creds = decoy_creds
        self.server_socket = None
        self.host_key = paramiko.RSAKey.generate(2048)
        self._thread = None

    def _handle_client(self, client_sock, client_addr):
        client_ip = client_addr[0]
        client_port = client_addr[1]
        session_id = f"ssh-{uuid.uuid4().hex[:8]}"
        session_start = datetime.datetime.utcnow()
        command_history = []
        captured_artifacts = []

        def auth_listener(user, pwd, success):
            event = {
                "event_id": str(uuid.uuid4()),
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source_ip": client_ip,
                "source_port": client_port,
                "protocol": "SSH",
                "destination_port": self.port,
                "event_type": "auth_attempt",
                "severity": "medium" if not success else "high",
                "credentials": {"username": user, "password": pwd},
                "session_id": session_id,
                "payload_raw": f"Login attempt: user={user} pass={pwd} result={'SUCCESS' if success else 'FAILURE'}",
                "is_ioc": True
            }
            self.event_callback(event)

        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            # MASK-6: Authentic realistic banner
            transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            transport.add_server_key(self.host_key)
            server = HoneySSHInterface(auth_listener, self.decoy_creds)

            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel is None:
                return

            server.event.wait(10)
            if not server.event.is_set():
                return

            # Welcome banner for interactive fake shell
            channel.send(
                b"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n"
                b" * Documentation:  https://help.ubuntu.com\r\n"
                b" * Management:     https://landscape.canonical.com\r\n"
                b"Last login: Mon Oct 10 18:32:10 2026 from 10.0.1.1\r\n"
            )

            prompt = b"root@prod-srv-01:~# "
            channel.send(prompt)

            cmd_buffer = ""
            while True:
                data = channel.recv(1024)
                if not data:
                    break
                
                text = data.decode(errors="ignore")
                should_exit = False
                for char in text:
                    if char in ["\r", "\n"]:
                        channel.send(b"\r\n")
                        raw_cmd = cmd_buffer.strip()
                        cmd_buffer = ""
                        
                        if not raw_cmd:
                            channel.send(prompt)
                            continue
                            
                        if raw_cmd in ["exit", "quit", "logout"]:
                            channel.send(b"logout\r\nConnection to prod-srv-01 closed.\r\n")
                            should_exit = True
                            break

                        # Execute virtual command and capture output
                        output, is_download, art_hash = self._emulate_command(raw_cmd, client_ip, session_id)
                        command_history.append({
                            "timestamp": datetime.datetime.utcnow().isoformat(),
                            "cmd": raw_cmd,
                            "output": output
                        })
                        
                        if is_download:
                            captured_artifacts.append({
                                "sha256": art_hash,
                                "filename": raw_cmd.split()[-1].split("/")[-1],
                                "cmd": raw_cmd
                            })

                        # Send emulated command output
                        if output:
                            channel.send(output.replace("\n", "\r\n").encode())
                        channel.send(prompt)
                    elif char in ["\x03", "\x04"]:  # Ctrl+C or Ctrl+D
                        channel.send(b"\r\n")
                        should_exit = True
                        break
                    elif char == "\x7f" or char == "\x08":  # Backspace
                        if cmd_buffer:
                            cmd_buffer = cmd_buffer[:-1]
                            channel.send(b"\b \b")
                    else:
                        cmd_buffer += char
                        channel.send(char.encode())
                        
                if should_exit:
                    break
        except Exception:
            pass
        finally:
            if command_history:
                # Emit full session log
                sess_log = {
                    "session_id": session_id,
                    "trap_id": self.trap_id,
                    "source_ip": client_ip,
                    "protocol": "SSH",
                    "total_commands": len(command_history),
                    "commands_history": command_history,
                    "captured_artifacts": captured_artifacts,
                    "ended": True
                }
                self.session_callback(sess_log)
            try:
                if transport:
                    transport.close()
                client_sock.close()
            except Exception:
                pass

    def _emulate_command(self, cmd: str, client_ip: str, session_id: str) -> (str, bool, str):
        cmd_lower = cmd.lower()
        parts = cmd.split()
        root_cmd = parts[0].lower() if parts else ""
        
        # Log command event
        ev = {
            "event_id": str(uuid.uuid4()),
            "trap_id": self.trap_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_ip": client_ip,
            "source_port": 0,
            "protocol": "SSH",
            "destination_port": self.port,
            "event_type": "shell_command",
            "severity": "medium",
            "command_text": cmd,
            "session_id": session_id,
            "is_ioc": True
        }
        self.event_callback(ev)

        # 1. Malware / Artifact download emulation
        if root_cmd in ["wget", "curl"]:
            target_url = parts[-1] if len(parts) > 1 else "http://example.com/payload"
            mock_payload = f"#!/bin/bash\n# Miner binary payload from {target_url}\n"
            sha256 = hashlib.sha256(mock_payload.encode()).hexdigest()
            
            # Emit file_download event with artifact SHA-256
            dl_ev = {
                "event_id": str(uuid.uuid4()),
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source_ip": client_ip,
                "source_port": 0,
                "protocol": "SSH",
                "destination_port": self.port,
                "event_type": "file_download",
                "severity": "critical",
                "command_text": cmd,
                "artifact_hash": sha256,
                "session_id": session_id,
                "payload_raw": f"Downloaded: {target_url} (SHA256: {sha256})",
                "is_ioc": True
            }
            self.event_callback(dl_ev)
            
            out = f"--2026-10-10 19:40:12--  {target_url}\nResolving host... 198.51.100.4\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1048576 (1.0M)\nSaving to: 'payload.sh'\n\npayload.sh           100%[===================>]   1.00M  4.20MB/s    in 0.2s\n\n2026-10-10 19:40:13 (4.20 MB/s) - 'payload.sh' saved [1048576/1048576]\n"
            return out, True, sha256

        # 2. Honeytoken file access detection
        if ".aws" in cmd or "credentials" in cmd:
            ht_ev = {
                "event_id": str(uuid.uuid4()),
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source_ip": client_ip,
                "source_port": 0,
                "protocol": "SSH",
                "destination_port": self.port,
                "event_type": "honeytoken_triggered",
                "severity": "critical",
                "command_text": cmd,
                "payload_raw": "Attacker accessed Canary Honeytoken: /root/.aws/credentials",
                "session_id": session_id,
                "is_ioc": True
            }
            self.event_callback(ht_ev)
            return "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", False, ""

        # 3. Virtual Command Emulation
        if root_cmd == "whoami":
            return "root\n", False, ""
        elif root_cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)\n", False, ""
        elif root_cmd == "uname":
            return "Linux prod-srv-01 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 10 14:22:11 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux\n", False, ""
        elif root_cmd == "pwd":
            return "/root\n", False, ""
        elif root_cmd in ["ls", "dir"]:
            return "backup.tar.gz  docker-compose.yml  payload.sh  scripts\n", False, ""
        elif root_cmd == "cat" and "/etc/passwd" in cmd:
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nsystemd-resolve:x:102:103:systemd-resolve,,,:/run/systemd/resolve:/usr/sbin/nologin\ndeploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash\n", False, ""
        elif root_cmd == "cat" and "/etc/shadow" in cmd:
            return "root:$6$vQ9j...$fakeHashForReconnaissance:19700:0:99999:7:::\ndeploy:$6$z81p...$hash:19700:0:99999:7:::\n", False, ""
        elif root_cmd == "ps":
            return "PID TTY          TIME CMD\n    1 ?        00:00:02 systemd\n  412 ?        00:00:01 systemd-journald\n  620 ?        00:00:00 systemd-resolved\n 1204 ?        00:00:00 sshd\n 1850 pts/0    00:00:00 bash\n 1910 pts/0    00:00:00 ps\n", False, ""
        elif root_cmd in ["w", "who"]:
            return " 19:42:01 up 2 days,  4:12,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    " + client_ip + "   19:40    0.00s  0.02s  0.00s -bash\n", False, ""
        elif root_cmd == "sudo":
            return "root\n", False, ""
        else:
            return f"bash: {root_cmd}: command not found\n", False, ""

    def _listen_loop(self):
        while self.is_running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception:
                break

    async def start(self):
        self.is_running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", self.port))
        self.server_socket.listen(20)
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    async def stop(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
