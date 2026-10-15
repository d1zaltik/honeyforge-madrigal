import asyncio
import time
import uuid
import datetime
import random
import re
from typing import Dict, Any, Callable, List, Optional
from honeyforge_agent.traps.base import BaseTrapService
from honeyforge_agent.config import DEFAULT_DECOY_CREDENTIALS

DEFAULT_BANNERS = {
    2121: "220 ProFTPD 1.3.7a Server (Ubuntu) [172.28.0.10]\r\n",
    2323: "Ubuntu 22.04.4 LTS\r\n\r\nlogin: "
}

SERVICE_NAMES = {
    21: "FTP",
    2121: "FTP",
    12121: "FTP",
    23: "Telnet",
    2323: "Telnet",
    12323: "Telnet",
    6379: "Redis",
    16379: "Redis"
}

def _parse_redis_resp(data: bytes) -> List[str]:
    """Parses Redis commands from either plain inline or RESP multi-bulk format"""
    if not data:
        return []
    
    # Check if RESP multi-bulk (starts with *)
    if data.startswith(b"*"):
        try:
            lines = data.split(b"\r\n")
            if not lines:
                return []
            count_str = lines[0][1:].decode(errors="ignore")
            num_args = int(count_str)
            args = []
            idx = 1
            while idx < len(lines) and len(args) < num_args:
                if lines[idx].startswith(b"$"):
                    idx += 1
                    if idx < len(lines):
                        args.append(lines[idx].decode(errors="ignore"))
                idx += 1
            if args:
                return args
        except Exception:
            pass

    # Fallback to plain inline command
    line = data.decode(errors="ignore").strip()
    return line.split()

class LowInteractionMultiPortTrap(BaseTrapService):
    """
    FR-A1, MASK-6: Multi-port perimeter honeypot with authentic protocol fidelity.
    - ProFTPD 1.3.7a FTP daemon with RFC commands, exact errors, and 421 timeout
    - Telnet getty daemon with authentic IAC negotiation, multi-attempt login, and delays
    - Redis 7.0 daemon with dual RESP parser, dynamic persona-aligned INFO, exact unknown command errors,
      and critical exploit detection for CONFIG SET, SLAVEOF/REPLICAOF, and MODULE LOAD.
    """
    def __init__(
        self,
        ports: list,
        banners: dict,
        event_callback: Callable[[Dict[str, Any]], None],
        trap_id: str,
        persona: Dict[str, Any] = None,
        boot_time: float = None
    ):
        super().__init__("LowInteractionPerimeter", 0, event_callback)
        self.ports = ports
        self.banners = banners or {}
        self.trap_id = trap_id
        self.persona = persona or {
            "hostname": f"edge-gw-{trap_id[-4:]}",
            "ip": "172.28.0.10",
            "os": "Ubuntu 22.04.4 LTS",
            "kernel": "5.15.0-105-generic"
        }
        self.boot_time = boot_time or (time.time() - float(self.persona.get("uptime_base", 86400)))
        self.servers = []

    def update_config(self, persona: dict = None, banners: dict = None):
        """Dynamic runtime update without restarting process (FR-A3)"""
        if persona is not None:
            self.persona.update(persona)
        if banners is not None:
            self.banners.update(banners)

    # -------------------------------------------------------------------------
    # FTP HANDLER (ProFTPD 1.3.7a)
    # -------------------------------------------------------------------------
    async def _handle_ftp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: str, client_port: int, port: int):
        capture_time = time.time()
        host_ip = self.persona.get("ip", "172.28.0.10")
        
        # Authentic ProFTPD 1.3.7a banner
        raw_banner = self.banners.get(port) or self.banners.get(str(port))
        if not raw_banner:
            raw_banner = f"220 ProFTPD 1.3.7a Server (Ubuntu) [{host_ip}]\r\n"
        if isinstance(raw_banner, str):
            raw_banner = raw_banner.encode()
        if not raw_banner.endswith(b"\r\n"):
            raw_banner += b"\r\n"

        writer.write(raw_banner)
        await writer.drain()

        ftp_user = ""
        ftp_pass = ""
        captured_data = []

        pasv_server = None
        data_conn_future = None
        pasv_port = None

        async def close_pasv_server():
            nonlocal pasv_server, data_conn_future, pasv_port
            if pasv_server:
                try:
                    pasv_server.close()
                    await pasv_server.wait_closed()
                except Exception:
                    pass
                pasv_server = None
            data_conn_future = None
            pasv_port = None

        try:
            for _ in range(16):  # Command exchange loop
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                except asyncio.TimeoutError:
                    # Item: 421 on inactivity timeout
                    writer.write(b"421 Timeout (300 seconds): closing control connection.\r\n")
                    await writer.drain()
                    break

                if not line:
                    break

                cmd_line = line.decode(errors="ignore").strip()
                if not cmd_line:
                    continue

                captured_data.append(cmd_line)
                parts = cmd_line.split(maxsplit=1)
                verb = parts[0].upper() if parts else ""
                arg = parts[1] if len(parts) > 1 else ""

                if verb == "USER":
                    ftp_user = arg
                    writer.write(f"331 Password required for {ftp_user}\r\n".encode())
                    await writer.drain()

                elif verb == "PASS":
                    ftp_pass = arg
                    # Jitter delay on failed authentication
                    await asyncio.sleep(random.uniform(0.45, 0.85))
                    writer.write(b"530 Login incorrect.\r\n")
                    await writer.drain()

                elif verb == "SYST":
                    writer.write(b"215 UNIX Type: L8\r\n")
                    await writer.drain()

                elif verb == "FEAT":
                    feat_resp = (
                        "211-Features:\r\n"
                        " MDTM\r\n"
                        " MFMT\r\n"
                        " TVFS\r\n"
                        " UTF8\r\n"
                        " MFF modify;UNIX.group;UNIX.mode;\r\n"
                        " MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.mode*;UNIX.owner*;\r\n"
                        " REST STREAM\r\n"
                        " SIZE\r\n"
                        " EPSV\r\n"
                        " PASV\r\n"
                        "211 End\r\n"
                    )
                    writer.write(feat_resp.encode())
                    await writer.drain()

                elif verb in ["PWD", "XPWD"]:
                    writer.write(b'257 "/" is current directory.\r\n')
                    await writer.drain()

                elif verb == "TYPE":
                    t_mode = arg.upper() if arg else "A"
                    if "I" in t_mode:
                        writer.write(b"200 Type set to I\r\n")
                    else:
                        writer.write(b"200 Type set to A\r\n")
                    await writer.drain()

                elif verb in ["PASV", "EPSV"]:
                    await close_pasv_server()
                    loop = asyncio.get_event_loop()
                    data_conn_future = loop.create_future()

                    def _on_data_client(dr, dw):
                        if data_conn_future and not data_conn_future.done():
                            data_conn_future.set_result((dr, dw))
                        else:
                            dw.close()

                    # Try binding on candidate ports in range 50000..50050
                    candidate_ports = list(range(50000, 50051))
                    random.shuffle(candidate_ports)
                    for cp in candidate_ports:
                        try:
                            pasv_server = await asyncio.start_server(_on_data_client, "0.0.0.0", cp)
                            pasv_port = cp
                            break
                        except OSError:
                            continue

                    if not pasv_server:
                        writer.write(b"425 Can't open data connection.\r\n")
                        await writer.drain()
                        continue

                    if verb == "PASV":
                        sock = writer.get_extra_info("sockname")
                        adv_ip = sock[0] if (sock and sock[0] != "0.0.0.0") else host_ip
                        ip_parts = adv_ip.replace(".", ",")
                        p1 = pasv_port // 256
                        p2 = pasv_port % 256
                        writer.write(f"227 Entering Passive Mode ({ip_parts},{p1},{p2}).\r\n".encode())
                        await writer.drain()
                    else:  # EPSV
                        writer.write(f"229 Entering Extended Passive Mode (|||{pasv_port}|).\r\n".encode())
                        await writer.drain()

                elif verb in ["LIST", "NLST"]:
                    if not pasv_server or not data_conn_future:
                        writer.write(b"425 Use PORT or PASV first.\r\n")
                        await writer.drain()
                    else:
                        writer.write(b"150 Opening ASCII mode data connection for file list\r\n")
                        await writer.drain()
                        try:
                            d_reader, d_writer = await asyncio.wait_for(asyncio.shield(data_conn_future), timeout=6.0)
                            if verb == "LIST":
                                listing = (
                                    "drwxr-xr-x   2 root     root         4096 Apr 15 10:20 .\r\n"
                                    "drwxr-xr-x   2 root     root         4096 Apr 15 10:20 ..\r\n"
                                    "-rw-r--r--   1 root     root          158 Apr 15 10:20 welcome.msg\r\n"
                                    "-rw-r--r--   1 root     root          118 Apr 15 10:22 notice.txt\r\n"
                                )
                                d_writer.write(listing.encode("utf-8"))
                            else:
                                d_writer.write(b"welcome.msg\r\nnotice.txt\r\n")
                            await d_writer.drain()
                            d_writer.close()
                            await d_writer.wait_closed()
                            writer.write(b"226 Transfer complete.\r\n")
                            await writer.drain()
                        except Exception:
                            writer.write(b"425 Can't open data connection.\r\n")
                            await writer.drain()
                        finally:
                            await close_pasv_server()

                elif verb == "RETR":
                    target_file = arg.strip().lstrip("/")
                    if not pasv_server or not data_conn_future:
                        writer.write(b"425 Use PORT or PASV first.\r\n")
                        await writer.drain()
                    elif target_file == "welcome.msg":
                        body = (
                            b"Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n"
                            b"Authorized corporate server. All activity is monitored and reported.\r\n"
                        )
                        writer.write(f"150 Opening BINARY mode data connection for welcome.msg ({len(body)} bytes)\r\n".encode())
                        await writer.drain()
                        try:
                            d_reader, d_writer = await asyncio.wait_for(asyncio.shield(data_conn_future), timeout=6.0)
                            d_writer.write(body)
                            await d_writer.drain()
                            d_writer.close()
                            await d_writer.wait_closed()
                            writer.write(b"226 Transfer complete.\r\n")
                            await writer.drain()
                        except Exception:
                            writer.write(b"425 Can't open data connection.\r\n")
                            await writer.drain()
                        finally:
                            await close_pasv_server()
                    elif target_file == "notice.txt":
                        body = (
                            b"System maintenance scheduled for every Sunday 02:00 UTC.\r\n"
                            b"For IT support contact admin@corp.internal\r\n"
                        )
                        writer.write(f"150 Opening BINARY mode data connection for notice.txt ({len(body)} bytes)\r\n".encode())
                        await writer.drain()
                        try:
                            d_reader, d_writer = await asyncio.wait_for(asyncio.shield(data_conn_future), timeout=6.0)
                            d_writer.write(body)
                            await d_writer.drain()
                            d_writer.close()
                            await d_writer.wait_closed()
                            writer.write(b"226 Transfer complete.\r\n")
                            await writer.drain()
                        except Exception:
                            writer.write(b"425 Can't open data connection.\r\n")
                            await writer.drain()
                        finally:
                            await close_pasv_server()
                    else:
                        writer.write(f"550 {arg}: No such file or directory\r\n".encode())
                        await writer.drain()

                elif verb == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break

                else:
                    # Item: Authentic ProFTPD error format: "500 {verb} not understood"
                    writer.write(f"500 {verb} not understood\r\n".encode())
                    await writer.drain()

        except Exception:
            pass
        finally:
            await close_pasv_server()

        # Emit attack event
        payload_summary = " | ".join(captured_data) if captured_data else "SYN Handshake"
        event = {
            "event_id": str(uuid.uuid4()),
            "event_uid": f"ftp-{client_ip}-{client_port}-{capture_time}-{uuid.uuid4().hex[:6]}",
            "trap_id": self.trap_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "captured_at": capture_time,
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "FTP",
            "destination_port": port,
            "event_type": "auth_attempt" if ftp_user else "port_scan",
            "severity": "medium" if ftp_user else "low",
            "credentials": {"username": ftp_user, "password": ftp_pass} if ftp_user else None,
            "payload_raw": payload_summary[:200],
            "is_ioc": bool(ftp_user)
        }
        self.event_callback(event)

    # -------------------------------------------------------------------------
    # TELNET HANDLER (Ubuntu getty)
    # -------------------------------------------------------------------------
    async def _handle_telnet(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: str, client_port: int, port: int):
        capture_time = time.time()
        hostname = self.persona.get("hostname", f"edge-gw-{self.trap_id[-4:]}")

        # Telnet IAC handshake (WILL ECHO, WILL SGA, DO LINEMODE)
        iac_handshake = b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x22\r\n"
        writer.write(iac_handshake)

        # Authentic Ubuntu 22.04 LTS getty banner
        banner = f"Ubuntu 22.04.4 LTS\r\n\r\n{hostname} login: "
        writer.write(banner.encode())
        await writer.drain()

        telnet_user = ""
        telnet_pass = ""
        captured_attempts = []

        try:
            # Item: up to 3 attempts with authentic delay and Login incorrect
            for attempt_idx in range(3):
                # Read username
                user_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not user_line:
                    break

                # Filter out IAC control bytes
                raw_user = user_line.replace(b"\xff", b"").decode(errors="ignore").strip()
                if not raw_user:
                    continue

                telnet_user = raw_user
                writer.write(b"Password: ")
                await writer.drain()

                # Read password
                pass_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not pass_line:
                    break

                telnet_pass = pass_line.replace(b"\xff", b"").decode(errors="ignore").strip()
                captured_attempts.append(f"{telnet_user}:{telnet_pass}")

                # Realistic authentication delay (0.5s - 1.2s)
                await asyncio.sleep(random.uniform(0.5, 1.2))

                is_decoy = False
                decoy_users = {c.get("user") for c in DEFAULT_DECOY_CREDENTIALS} | {"operator", "ubuntu"}
                decoy_passes = {c.get("pass") for c in DEFAULT_DECOY_CREDENTIALS} | {"operator123"}
                if telnet_user in decoy_users and telnet_pass in decoy_passes:
                    is_decoy = True

                # Lure policy: admit on attempt 2 or 3
                if is_decoy and attempt_idx >= 1:
                    kernel = self.persona.get('kernel', '5.15.0-105-generic')
                    now_str = datetime.datetime.now().strftime('%a %b %d %H:%M:%S')
                    welcome = (
                        f"\r\nWelcome to Ubuntu 22.04.4 LTS (GNU/Linux {kernel} x86_64)\r\n\r\n"
                        f"Last login: {now_str} from {client_ip}\r\n"
                        f"{telnet_user}@{hostname}:~# "
                    )
                    writer.write(welcome.encode())
                    await writer.drain()

                    while True:
                        cmd_line = await asyncio.wait_for(reader.readline(), timeout=60.0)
                        if not cmd_line:
                            break
                        cmd_str = cmd_line.replace(b"\xff", b"").decode(errors="ignore").strip()
                        if cmd_str in ["exit", "logout"]:
                            writer.write(b"logout\r\n")
                            await writer.drain()
                            break
                        elif cmd_str == "id":
                            writer.write(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
                        elif cmd_str == "uname -a":
                            writer.write(f"Linux {hostname} {kernel} #105-Ubuntu SMP x86_64 GNU/Linux\r\n".encode())
                        elif cmd_str == "whoami":
                            writer.write(f"{telnet_user}\r\n".encode())
                        elif cmd_str:
                            writer.write(f"bash: {cmd_str.split()[0]}: command not found\r\n".encode())
                        writer.write(f"{telnet_user}@{hostname}:~# ".encode())
                        await writer.drain()
                    break

                if attempt_idx < 2:
                    # Retry prompt
                    writer.write(f"\r\nLogin incorrect\r\n\r\n{hostname} login: ".encode())
                    await writer.drain()
                else:
                    # 3rd failed attempt: disconnect
                    writer.write(b"\r\nLogin incorrect\r\n")
                    await writer.drain()
                    break

        except (asyncio.TimeoutError, Exception):
            pass

        event = {
            "event_id": str(uuid.uuid4()),
            "event_uid": f"telnet-{client_ip}-{client_port}-{capture_time}-{uuid.uuid4().hex[:6]}",
            "trap_id": self.trap_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "captured_at": capture_time,
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "Telnet",
            "destination_port": port,
            "event_type": "auth_attempt" if telnet_user else "port_scan",
            "severity": "medium" if telnet_user else "low",
            "credentials": {"username": telnet_user, "password": telnet_pass} if telnet_user else None,
            "payload_raw": f"Telnet attempts: {', '.join(captured_attempts) if captured_attempts else 'None'}",
            "is_ioc": bool(telnet_user)
        }
        self.event_callback(event)

    # -------------------------------------------------------------------------
    # REDIS HANDLER (Redis 7.0 RESP)
    # -------------------------------------------------------------------------
    async def _handle_redis(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: str, client_port: int, port: int):
        capture_time = time.time()
        captured_cmds = []
        highest_severity = "low"
        exploit_detected = False
        exploit_reason = ""

        try:
            for _ in range(15):  # Command loop
                data = await asyncio.wait_for(reader.read(1024), timeout=15.0)
                if not data:
                    break

                cmd_parts = _parse_redis_resp(data)
                if not cmd_parts:
                    continue

                root_cmd = cmd_parts[0].upper()
                args = cmd_parts[1:]
                cmd_line_repr = " ".join(cmd_parts)
                captured_cmds.append(cmd_line_repr)

                # 1. PING
                if root_cmd == "PING":
                    if args:
                        writer.write(f"+{args[0]}\r\n".encode())
                    else:
                        writer.write(b"+PONG\r\n")
                    await writer.drain()

                # 2. INFO (Dynamic, aligned with persona)
                elif root_cmd == "INFO":
                    up_s = int(time.time() - self.boot_time)
                    up_d = up_s // 86400
                    kernel = self.persona.get("kernel", "5.15.0-105-generic")
                    used_mem = 1048576 + int((time.time() % 3600) * 128)
                    used_mem_h = f"{used_mem / 1048576:.2f}M"

                    info_payload = (
                        "# Server\r\n"
                        "redis_version:7.0.15\r\n"
                        "redis_git_sha1:00000000\r\n"
                        "redis_git_dirty:0\r\n"
                        "redis_build_id:3847291a\r\n"
                        "redis_mode:standalone\r\n"
                        f"os:Linux {kernel} x86_64\r\n"
                        "arch_bits:64\r\n"
                        "multiplexing_api:epoll\r\n"
                        "tcp_port:6379\r\n"
                        f"uptime_in_seconds:{up_s}\r\n"
                        f"uptime_in_days:{up_d}\r\n"
                        "# Clients\r\n"
                        "connected_clients:1\r\n"
                        "blocked_clients:0\r\n"
                        "# Memory\r\n"
                        f"used_memory:{used_mem}\r\n"
                        f"used_memory_human:{used_mem_h}\r\n"
                        "used_memory_rss:4194304\r\n"
                        "used_memory_rss_human:4.00M\r\n"
                        "mem_allocator:jemalloc-5.3.0\r\n"
                        "# Persistence\r\n"
                        "loading:0\r\n"
                        "rdb_changes_since_last_save:0\r\n"
                        "rdb_bgsave_in_progress:0\r\n"
                        "aof_enabled:0\r\n"
                        "# Replication\r\n"
                        "role:master\r\n"
                        "connected_slaves:0\r\n"
                        "# Keyspace\r\n"
                        "db0:keys=3,expires=0,avg_ttl=0\r\n"
                    )
                    writer.write(f"${len(info_payload)}\r\n{info_payload}\r\n".encode())
                    await writer.drain()

                # 3. CONFIG (Detect Exploits: CONFIG SET dir / dbfilename)
                elif root_cmd == "CONFIG":
                    sub = args[0].upper() if args else ""
                    if sub == "GET":
                        param = args[1].lower() if len(args) > 1 else "*"
                        if param in ["dir", "*"]:
                            writer.write(b"*2\r\n$3\r\ndir\r\n$12\r\n/var/lib/redis\r\n")
                        elif param in ["dbfilename", "*"]:
                            writer.write(b"*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n")
                        elif param in ["requirepass", "*"]:
                            writer.write(b"*2\r\n$11\r\nrequirepass\r\n$0\r\n\r\n")
                        else:
                            writer.write(b"*0\r\n")
                        await writer.drain()

                    elif sub == "SET":
                        # Item: CONFIG SET exploit detection
                        exploit_detected = True
                        highest_severity = "critical"
                        exploit_reason = f"Redis RCE exploit attempt via CONFIG SET: {cmd_line_repr}"
                        writer.write(b"+OK\r\n")
                        await writer.drain()
                    else:
                        writer.write(b"+OK\r\n")
                        await writer.drain()

                # 4. SLAVEOF / REPLICAOF (Rogue Server RCE exploit)
                elif root_cmd in ["SLAVEOF", "REPLICAOF"]:
                    exploit_detected = True
                    highest_severity = "critical"
                    exploit_reason = f"Redis Rogue Server RCE exploit attempt: {cmd_line_repr}"
                    writer.write(b"+OK\r\n")
                    await writer.drain()

                # 5. MODULE LOAD (Module Load RCE exploit)
                elif root_cmd == "MODULE":
                    sub = args[0].upper() if args else ""
                    if sub == "LOAD":
                        exploit_detected = True
                        highest_severity = "critical"
                        exploit_reason = f"Redis Module Load RCE exploit attempt: {cmd_line_repr}"
                        writer.write(b"-ERR Error loading module\r\n")
                        await writer.drain()
                    else:
                        writer.write(b"*0\r\n")
                        await writer.drain()

                # 6. CLIENT LIST
                elif root_cmd == "CLIENT":
                    sub = args[0].upper() if args else ""
                    if sub == "LIST":
                        client_str = f"id=3 addr={client_ip}:{client_port} laddr={self.persona.get('ip','172.28.0.10')}:6379 fd=7 name= age=1 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=26 qbuf-free=40928 argv-mem=10 multi-mem=0 rbs=1024 rbp=0 obl=0 oll=0 omem=0 tot-mem=61466 events=r cmd=client user=default redir=-1 resp=2\r\n"
                        writer.write(f"${len(client_str)}\r\n{client_str}\r\n".encode())
                        await writer.drain()
                    else:
                        writer.write(b"+OK\r\n")
                        await writer.drain()

                # 7. KEYS & GET / SET
                elif root_cmd == "KEYS":
                    # Decoy keys
                    keys = [b"session:auth", b"cache:user", b"token:canary"]
                    out = [f"*{len(keys)}\r\n".encode()]
                    for k in keys:
                        out.append(f"${len(k)}\r\n".encode() + k + b"\r\n")
                    writer.write(b"".join(out))
                    await writer.drain()

                elif root_cmd == "GET":
                    target_k = args[0] if args else ""
                    if target_k == "token:canary":
                        val = b"CANARY_TOKEN_REDIS_SECRET_2026"
                        writer.write(f"${len(val)}\r\n".encode() + val + b"\r\n")
                    else:
                        writer.write(b"$-1\r\n")
                    await writer.drain()

                elif root_cmd == "SET":
                    writer.write(b"+OK\r\n")
                    await writer.drain()

                elif root_cmd == "DBSIZE":
                    writer.write(b":3\r\n")
                    await writer.drain()

                elif root_cmd == "SELECT":
                    writer.write(b"+OK\r\n")
                    await writer.drain()

                elif root_cmd in ["FLUSHALL", "FLUSHDB"]:
                    writer.write(b"+OK\r\n")
                    await writer.drain()

                elif root_cmd == "AUTH":
                    writer.write(b"-ERR Client sent AUTH, but no password is set\r\n")
                    await writer.drain()

                elif root_cmd in ["COMMAND", "DOCS"]:
                    writer.write(b"*0\r\n")
                    await writer.drain()

                else:
                    # Item: Exact Redis 7 error format:
                    # -ERR unknown command 'x', with args beginning with: 'arg1' 'arg2'
                    args_sample = " ".join(f"'{a}'" for a in args[:3])
                    err_msg = f"-ERR unknown command '{cmd_parts[0]}', with args beginning with: {args_sample}\r\n"
                    writer.write(err_msg.encode())
                    await writer.drain()

        except Exception:
            pass

        # Classify and emit attack event
        payload_repr = " | ".join(captured_cmds) if captured_cmds else "SYN/ACK Handshake"
        if exploit_detected:
            event_type = "exploit_attempt"
            severity = "critical"
            payload_repr = f"[EXPLOIT] {exploit_reason} | History: {payload_repr}"
        elif captured_cmds:
            event_type = "banner_probe"
            severity = "medium"
        else:
            event_type = "port_scan"
            severity = "low"

        event = {
            "event_id": str(uuid.uuid4()),
            "event_uid": f"redis-{client_ip}-{client_port}-{capture_time}-{uuid.uuid4().hex[:6]}",
            "trap_id": self.trap_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "captured_at": capture_time,
            "source_ip": client_ip,
            "source_port": client_port,
            "protocol": "Redis",
            "destination_port": port,
            "event_type": event_type,
            "severity": severity,
            "payload_raw": payload_repr[:300],
            "is_ioc": bool(captured_cmds) or exploit_detected
        }
        self.event_callback(event)

    # -------------------------------------------------------------------------
    # CONNECTION ROUTER
    # -------------------------------------------------------------------------
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
        peer = writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "0.0.0.0"
        client_port = peer[1] if peer else 0

        try:
            if port in [6379, 16379] or str(port).endswith("6379"):
                await self._handle_redis(reader, writer, client_ip, client_port, port)
            elif port in [21, 2121, 12121] or str(port).endswith("2121") or str(port).endswith("21"):
                await self._handle_ftp(reader, writer, client_ip, client_port, port)
            elif port in [23, 2323, 12323] or str(port).endswith("2323") or str(port).endswith("23"):
                await self._handle_telnet(reader, writer, client_ip, client_port, port)
            else:
                banner = self.banners.get(port, b"220 Service Ready\r\n")
                if isinstance(banner, str):
                    banner = banner.encode()
                writer.write(banner)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=3.0)
                ev = {
                    "event_id": str(uuid.uuid4()),
                    "event_uid": f"tcp-{client_ip}-{client_port}-{time.time()}-{uuid.uuid4().hex[:6]}",
                    "trap_id": self.trap_id,
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "captured_at": time.time(),
                    "source_ip": client_ip,
                    "source_port": client_port,
                    "protocol": f"TCP-{port}",
                    "destination_port": port,
                    "event_type": "port_scan",
                    "severity": "low",
                    "payload_raw": data.decode(errors="ignore")[:100] if data else "SYN",
                    "is_ioc": False
                }
                self.event_callback(ev)
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.is_running = True
        for port in self.ports:
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port: self._handle_connection(r, w, p),
                    "0.0.0.0",
                    port
                )
                self.servers.append(server)
            except Exception:
                pass

    async def stop(self):
        self.is_running = False
        for s in self.servers:
            s.close()
            await s.wait_closed()
        self.servers.clear()
