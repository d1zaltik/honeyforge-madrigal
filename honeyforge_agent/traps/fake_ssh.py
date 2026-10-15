import socket
import os
import sys
import threading
import time
import uuid
import datetime
import hashlib
import random
import re
import json
import gzip
import paramiko
from typing import Dict, Any, Callable, List, Tuple, Optional
from honeyforge_agent.traps.base import BaseTrapService
from honeyforge_agent.honeytokens import generate_synthetic_aws_key, generate_fake_aws_key
from honeyforge_agent.config import DEFAULT_DECOY_CREDENTIALS

def _format_mode(mode: int, is_dir: bool) -> str:
    lead = "d" if is_dir else "-"
    flags = [
        ("r", mode & 0o400), ("w", mode & 0o200), ("x", mode & 0o100),
        ("r", mode & 0o040), ("w", mode & 0o020), ("x", mode & 0o010),
        ("r", mode & 0o004), ("w", mode & 0o002), ("x", mode & 0o001),
    ]
    return lead + "".join(f if cond else "-" for f, cond in flags)

def _format_gnu_date(timestamp: float) -> str:
    now = time.time()
    dt = datetime.datetime.fromtimestamp(timestamp)
    # If mtime is within the last 6 months, GNU ls prints: Mmm dd HH:MM, else: Mmm dd  YYYY
    if abs(now - timestamp) < 15552000:
        return dt.strftime("%b %e %H:%M")
    return dt.strftime("%b %e  %Y")

class FSEntry:
    def __init__(
        self,
        name: str,
        is_dir: bool = False,
        content: str = "",
        mode: int = None,
        owner: str = "root",
        group: str = "root",
        mtime: float = None,
        size: int = None
    ):
        self.name = name
        self.is_dir = is_dir
        self.content = content
        if mode is None:
            self.mode = 0o755 if is_dir else 0o644
        else:
            self.mode = mode
        self.owner = owner
        self.group = group
        self.mtime = mtime if mtime is not None else (time.time() - random.randint(3600, 86400 * 14))
        if size is not None:
            self.size = size
        else:
            self.size = 4096 if is_dir else len(content.encode("utf-8"))

def _generate_auth_log_history(hostname: str, boot_time: float, primary_user: str) -> str:
    lines = []
    start_ts = boot_time - (14 * 86400)
    curr_ts = start_ts
    step_secs = 3600
    while curr_ts < boot_time:
        dt = datetime.datetime.fromtimestamp(curr_ts)
        t_str = dt.strftime("%b %d %H:%M:%S")
        hour = dt.hour
        pid = 1000 + (int(curr_ts) % 4000)
        lines.append(f"{t_str} {hostname} CRON[{pid}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        lines.append(f"{t_str} {hostname} CRON[{pid}]: pam_unix(cron:session): session closed for user root")
        if hour == 4:
            lines.append(f"{t_str} {hostname} systemd-logind[412]: Daily maintenance run completed")
        elif hour in [9, 14] and dt.weekday() < 5:
            spid = 2000 + (int(curr_ts) % 3000)
            port = 32000 + (int(curr_ts) % 20000)
            lines.append(f"{t_str} {hostname} sshd[{spid}]: Accepted publickey for {primary_user} from 10.0.4.15 port {port} ssh2: RSA SHA256:7f9a12c8b0e3f4d5")
            lines.append(f"{t_str} {hostname} sshd[{spid}]: pam_unix(sshd:session): session opened for user {primary_user}(uid=1000) by (uid=0)")
            lines.append(f"{t_str} {hostname} sudo:   {primary_user} : TTY=pts/0 ; PWD=/home/{primary_user} ; USER=root ; COMMAND=/usr/bin/apt-get check")
            lines.append(f"{t_str} {hostname} sshd[{spid}]: pam_unix(sshd:session): session closed for user {primary_user}")
        elif (int(curr_ts) % 7) == 0:
            spid = 2000 + (int(curr_ts) % 3000)
            lines.append(f"{t_str} {hostname} sshd[{spid}]: Failed password for invalid user admin from 185.220.101.5 port 49120 ssh2")
            lines.append(f"{t_str} {hostname} sshd[{spid}]: Received disconnect from 185.220.101.5 port 49120:11: Bye Bye [preauth]")
        curr_ts += step_secs * random.choice([2, 3, 4])
        
    b_dt = datetime.datetime.fromtimestamp(boot_time)
    bt_str = b_dt.strftime("%b %d %H:%M:%S")
    lines.append(f"{bt_str} {hostname} systemd[1]: Starting OpenSSH server daemon...")
    lines.append(f"{bt_str} {hostname} sshd[1204]: Server listening on 0.0.0.0 port 22.")
    lines.append(f"{bt_str} {hostname} sshd[1204]: Server listening on :: port 22.")
    lines.append(f"{bt_str} {hostname} systemd[1]: Started OpenSSH server daemon.")
    
    now_ts = time.time()
    curr_ts = boot_time + 60
    while curr_ts < now_ts:
        dt = datetime.datetime.fromtimestamp(curr_ts)
        t_str = dt.strftime("%b %d %H:%M:%S")
        pid = 1000 + (int(curr_ts) % 4000)
        lines.append(f"{t_str} {hostname} CRON[{pid}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        lines.append(f"{t_str} {hostname} CRON[{pid}]: pam_unix(cron:session): session closed for user root")
        curr_ts += 7200
    return "\n".join(lines) + "\n"

def _generate_process_list(user: str, hostname: str, persona: dict, boot_time: float, parts: list) -> str:
    is_ef = any(a in parts for a in ["-ef", "-e", "-f"])
    up_secs = int(time.time() - boot_time)
    kworker_pid = 1900 + min(9000, up_secs // 60)
    has_apache = "apache" in persona.get("services", ["ssh", "apache"]) or "http" in persona.get("services", ["ssh", "http"])
    has_redis = "redis" in persona.get("services", [])
    has_ftp = "ftp" in persona.get("services", [])
    
    procs = [
        ("root", 1, 0, "0.0", "0.1", 168340, 11244, "?", "Ss", "08:12", "0:02", "/sbin/init"),
        ("root", 2, 0, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[kthreadd]"),
        ("root", 3, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[rcu_gp]"),
        ("root", 4, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[rcu_par_gp]"),
        ("root", 5, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[slub_flushwq]"),
        ("root", 6, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[netns]"),
        ("root", 8, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[kworker/0:0H-events_highpri]"),
        ("root", 10, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[mm_percpu_wq]"),
        ("root", 11, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[rcu_tasks_kthre]"),
        ("root", 12, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[rcu_tasks_rude_]"),
        ("root", 13, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[rcu_tasks_trace]"),
        ("root", 14, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[ksoftirqd/0]"),
        ("root", 15, 2, "0.0", "0.0", 0, 0, "?", "I", "08:12", "0:00", "[rcu_sched]"),
        ("root", 16, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[migration/0]"),
        ("root", 17, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[cpuhp/0]"),
        ("root", 18, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[cpuhp/1]"),
        ("root", 19, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[migration/1]"),
        ("root", 20, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[ksoftirqd/1]"),
        ("root", 22, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[kworker/1:0H-events_highpri]"),
        ("root", 23, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[kdevtmpfs]"),
        ("root", 24, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[inet_frag_wq]"),
        ("root", 25, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[kauditd]"),
        ("root", 26, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[khungtaskd]"),
        ("root", 27, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[oom_reaper]"),
        ("root", 28, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[writeback]"),
        ("root", 29, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[kcompactd0]"),
        ("root", 30, 2, "0.0", "0.0", 0, 0, "?", "SN", "08:12", "0:00", "[ksmd]"),
        ("root", 31, 2, "0.0", "0.0", 0, 0, "?", "SN", "08:12", "0:00", "[khugepaged]"),
        ("root", 58, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[kintegrityd]"),
        ("root", 59, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[kblockd]"),
        ("root", 60, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[blkcg_punt_bio]"),
        ("root", 61, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[tpm_vtpm_proxy]"),
        ("root", 62, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[md]"),
        ("root", 63, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[edac-poller]"),
        ("root", 64, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[devfreq_wq]"),
        ("root", 65, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[watchdogd]"),
        ("root", 70, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[kswapd0]"),
        ("root", 71, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[kthrotld]"),
        ("root", 72, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[acpi_thermal_pm]"),
        ("root", 73, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[scsi_eh_0]"),
        ("root", 74, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[scsi_tmf_0]"),
        ("root", 80, 2, "0.0", "0.0", 0, 0, "?", "S", "08:12", "0:00", "[jbd2/vda1-8]"),
        ("root", 81, 2, "0.0", "0.0", 0, 0, "?", "I<", "08:12", "0:00", "[ext4-rsv-conver]"),
        ("root", 380, 1, "0.0", "0.1", 48232, 9420, "?", "S<s", "08:12", "0:01", "/lib/systemd/systemd-journald"),
        ("root", 415, 1, "0.0", "0.0", 21640, 5820, "?", "Ss", "08:12", "0:00", "/lib/systemd/systemd-udevd"),
        ("systemd+", 520, 1, "0.0", "0.0", 18450, 4910, "?", "Ss", "08:12", "0:00", "/lib/systemd/systemd-networkd"),
        ("systemd+", 580, 1, "0.0", "0.0", 24128, 6280, "?", "Ss", "08:12", "0:00", "/lib/systemd/systemd-resolved"),
        ("systemd+", 610, 1, "0.0", "0.0", 16220, 3840, "?", "Ss", "08:12", "0:00", "/lib/systemd/systemd-timesyncd"),
        ("message+", 650, 1, "0.0", "0.0", 9240, 3710, "?", "Ss", "08:12", "0:00", "/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"),
        ("root", 720, 1, "0.0", "0.0", 8420, 2940, "?", "Ss", "08:12", "0:00", "/usr/sbin/cron -f -P"),
        ("syslog", 780, 1, "0.0", "0.0", 223400, 5120, "?", "Ssl", "08:12", "0:00", "/usr/sbin/rsyslogd -n -iNONE"),
        ("root", 820, 1, "0.0", "0.0", 14850, 4320, "?", "Ss", "08:12", "0:00", "/lib/systemd/systemd-logind"),
        ("root", 890, 1, "0.0", "0.1", 15848, 7420, "?", "Ss", "08:12", "0:00", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
    ]
    if has_apache:
        procs.extend([
            ("root", 945, 1, "0.0", "0.2", 198420, 18410, "?", "Ss", "08:12", "0:00", "/usr/sbin/apache2 -k start"),
            ("www-data", 946, 945, "0.0", "0.1", 198540, 12340, "?", "S", "08:12", "0:00", "/usr/sbin/apache2 -k start"),
            ("www-data", 947, 945, "0.0", "0.1", 198540, 12340, "?", "S", "08:12", "0:00", "/usr/sbin/apache2 -k start"),
        ])
    if has_redis:
        procs.append(("redis", 950, 1, "0.1", "0.1", 65420, 10240, "?", "Ssl", "08:12", "0:02", "/usr/bin/redis-server 0.0.0.0:6379"))
    if has_ftp:
        procs.append(("proftpd", 955, 1, "0.0", "0.0", 34210, 4820, "?", "Ss", "08:12", "0:00", "proftpd: (accepting connections)"))
    procs.extend([
        ("root", kworker_pid, 2, "0.0", "0.0", 0, 0, "?", "I", "09:01", "0:00", "[kworker/u4:1-events_unbound]"),
        ("root", kworker_pid + 1, 2, "0.0", "0.0", 0, 0, "?", "I", "09:05", "0:00", "[kworker/0:1-events]"),
        ("root", kworker_pid + 2, 2, "0.0", "0.0", 0, 0, "?", "I", "09:10", "0:00", "[kworker/1:2-events]"),
        ("root", 1850, 890, "0.0", "0.1", 16820, 7940, "?", "Ss", "09:15", "0:00", f"sshd: {user}@pts/0"),
        (user, 1851, 1850, "0.0", "0.0", 14220, 5100, "pts/0", "Ss", "09:15", "0:00", "-bash"),
        (user, kworker_pid + 10, 1851, "0.0", "0.0", 12480, 3320, "pts/0", "R+", "09:16", "0:00", f"ps {' '.join(parts[1:])}"),
    ])
    if is_ef:
        lines = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
        for u, pid, ppid, cpu, mem, vsz, rss, tty, stat, start, tm, cmd in procs:
            lines.append(f"{u:<10} {pid:>6} {ppid:>7}  0 {start:>5} {tty:<10} {tm:>7} {cmd}")
        return "\n".join(lines) + "\n"
    else:
        lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for u, pid, ppid, cpu, mem, vsz, rss, tty, stat, start, tm, cmd in procs:
            lines.append(f"{u:<10} {pid:>6} {cpu:>5} {mem:>5} {vsz:>7} {rss:>5} {tty:<8} {stat:<5} {start:>5} {tm:>6} {cmd}")
        return "\n".join(lines) + "\n"

class VirtualFS:
    """
    Session-persistent structured virtual filesystem for Medium-interaction SSH trap.
    Maintains authentic POSIX metadata (mode, uid/gid, timestamps, byte size) and mutations.
    """
    def __init__(self, persona: Dict[str, Any], trap_id: str, boot_time: float):
        self.persona = persona
        self.trap_id = trap_id
        self.boot_time = boot_time
        self.entries: Dict[str, FSEntry] = {}
        self._init_tree()

    def _norm(self, path: str) -> str:
        if not path:
            return "/"
        # Collapse multiple slashes
        p = re.sub(r"/+", "/", path.strip())
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1 and p.endswith("/"):
            p = p.rstrip("/")
        return p

    def _init_tree(self):
        hostname = self.persona.get("hostname", f"srv-{self.trap_id[-4:]}")
        kernel = self.persona.get("kernel", "5.15.0-105-generic")
        users = self.persona.get("users", ["root", "deploy", "ubuntu"])
        primary_user = users[1] if len(users) > 1 else "deploy"

        # Standard directories
        base_dirs = [
            "/", "/bin", "/boot", "/dev", "/etc", "/etc/cron.d", "/etc/ssh", "/etc/pam.d",
            "/etc/systemd", "/etc/systemd/system", "/home", f"/home/{primary_user}",
            "/lib", "/lib64", "/media", "/mnt", "/opt", "/proc", "/root", "/root/.aws",
            "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/usr/bin", "/usr/sbin",
            "/usr/local", "/usr/local/bin", "/var", "/var/backups", "/var/log",
            "/var/run", "/var/tmp", "/var/www", "/var/www/html"
        ]
        for d in base_dirs:
            self.mkdir(d, parents=True)

        synthetic_aws = generate_synthetic_aws_key()

        # Seed standard authentic configuration files
        files_data = {
            "/etc/hostname": (f"{hostname}\n", 0o644, "root", "root"),
            "/etc/issue": ("Ubuntu 22.04.4 LTS \\n \\l\n\n", 0o644, "root", "root"),
            "/etc/os-release": (
                'NAME="Ubuntu"\n'
                'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
                'ID=ubuntu\n'
                'ID_LIKE=debian\n'
                'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
                'VERSION_ID="22.04"\n'
                'HOME_URL="https://www.ubuntu.com/"\n'
                'SUPPORT_URL="https://help.ubuntu.com/"\n'
                'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
                'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
                'UBUNTU_CODENAME=jammy\n',
                0o644, "root", "root"
            ),
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                "sync:x:4:65534:sync:/bin:/bin/sync\n"
                "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
                "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
                "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
                "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
                "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
                "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
                "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
                "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
                "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
                "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
                "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin\n"
                "messagebus:x:102:105::/nonexistent:/usr/sbin/nologin\n"
                "systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n"
                "pollinate:x:104:1::/var/cache/pollinate:/bin/false\n"
                "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
                "syslog:x:106:110::/home/syslog:/usr/sbin/nologin\n"
                f"{primary_user}:x:1000:1000:{primary_user},,,:/home/{primary_user}:/bin/bash\n"
                "ubuntu:x:1001:1001:Ubuntu,,,:/home/ubuntu:/bin/bash\n",
                0o644, "root", "root"
            ),
            "/etc/shadow": (
                "root:$y$j9T$w81.m7b9Wk3xL0p5A$H8x2K4v7N1z9Q5t3W6r8Y2u4P7m9S1j3L5k7N9b2V4c:19700:0:99999:7:::\n"
                "daemon:*:19680:0:99999:7:::\n"
                "bin:*:19680:0:99999:7:::\n"
                "sys:*:19680:0:99999:7:::\n"
                "sync:*:19680:0:99999:7:::\n"
                f"{primary_user}:$y$j9T$q29.v4c7Xm1zN8r2B$F5t9P2s4R8w1U3x5Z7p9A1m3C5k7E9h2G4f6H8d0J2b:19700:0:99999:7:::\n"
                "ubuntu:$y$j9T$k63.t1f5Zn9xP4s8C$D2r6N9m1V5u7X9z1B3t5E7q9G1n3I5l7K9j1M3h5O7f:19700:0:99999:7:::\n",
                0o640, "root", "shadow"
            ),
            "/etc/group": (
                "root:x:0:\n"
                "daemon:x:1:\n"
                "bin:x:2:\n"
                "sys:x:3:\n"
                "adm:x:4:syslog,ubuntu\n"
                "tty:x:5:\n"
                "disk:x:6:\n"
                "sudo:x:27:ubuntu,deploy\n"
                "audio:x:29:\n"
                "dip:x:30:\n"
                "www-data:x:33:\n"
                "backup:x:34:\n"
                "shadow:x:42:\n"
                f"{primary_user}:x:1000:\n"
                "ubuntu:x:1001:\n",
                0o644, "root", "root"
            ),
            "/etc/hosts": (
                f"127.0.0.1 localhost\n127.0.1.1 {hostname}\n\n# The following lines are desirable for IPv6 capable hosts\n::1 localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n",
                0o644, "root", "root"
            ),
            "/etc/resolv.conf": (
                "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch localdomain\n",
                0o644, "root", "root"
            ),
            "/etc/fstab": (
                "UUID=4a919240-410a-4ff1-a6ef-46be54da7454 / ext4 defaults 0 1\nUUID=4b829141-110b-4ff2-b7ef-57ce65eb8565 /boot ext4 defaults 0 2\n",
                0o644, "root", "root"
            ),
            "/etc/sudoers": (
                "Defaults\tenv_reset\nDefaults\tmail_badpass\nDefaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\nroot\tALL=(ALL:ALL) ALL\n%sudo\tALL=(ALL:ALL) ALL\n",
                0o440, "root", "root"
            ),
            "/etc/ssh/sshd_config": (
                "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding no\nPrintMotd no\nAcceptEnv LANG LC_*\nSubsystem\tsftp\t/usr/lib/openssh/sftp-server\n",
                0o644, "root", "root"
            ),
            "/var/log/auth.log": (
                _generate_auth_log_history(hostname, self.boot_time, primary_user),
                0o640, "syslog", "adm"
            ),
            "/var/log/syslog": (
                f"Oct 10 14:10:01 {hostname} systemd[1]: Starting Daily apt download activities...\n"
                f"Oct 10 14:10:04 {hostname} systemd[1]: apt-daily.service: Deactivated successfully.\n"
                f"Oct 10 14:10:04 {hostname} systemd[1]: Finished Daily apt download activities.\n",
                0o640, "syslog", "adm"
            ),
            "/var/www/html/index.nginx-debian.html": (
                "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and working.</p>\n</body>\n</html>\n",
                0o644, "www-data", "www-data"
            ),
            "/root/.bashrc": (
                "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
                "export PS1='\\[\\e]0;\\u@\\h: \\w\\a\\]${debian_chroot:+($debian_chroot)}\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\n"
                "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "alias ls='ls --color=auto'\n"
                "alias ll='ls -alF'\n",
                0o644, "root", "root"
            ),
            "/root/.profile": (
                "# ~/.profile: executed by Bourne-compatible login shells.\n"
                "if [ \"$BASH\" ]; then\n"
                "  if [ -f ~/.bashrc ]; then\n"
                "    . ~/.bashrc\n"
                "  fi\n"
                "fi\n"
                "mesg n 2> /dev/null || true\n",
                0o644, "root", "root"
            ),
            "/root/.bash_history": (
                "apt update\n"
                "apt install -y nginx curl htop\n"
                "systemctl status sshd\n"
                "cat /etc/os-release\n"
                "df -h\n",
                0o600, "root", "root"
            ),
            "/root/.aws/credentials": (
                "[default]\n"
                f"aws_access_key_id = {synthetic_aws['access_key_id']}\n"
                f"aws_secret_access_key = {synthetic_aws['secret_access_key']}\n",
                0o600, "root", "root"
            ),
            "/root/docker-compose.yml": (
                "version: '3.8'\nservices:\n  web:\n    image: nginx:alpine\n    ports:\n      - '80:80'\n    restart: always\n",
                0o644, "root", "root"
            ),
            "/root/backup.tar.gz": (
                b"\x1f\x8b\x08\x08\x35\x5b\x68\x66\x00\x03\x62\x61\x63\x6b\x75\x70\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00".decode("latin1"),
                0o644, "root", "root"
            )
        }

        for path, (content, mode, owner, group) in files_data.items():
            self.write_file(path, content, mode=mode, owner=owner, group=group)

    def exists(self, path: str) -> bool:
        return self._norm(path) in self.entries

    def is_dir(self, path: str) -> bool:
        norm = self._norm(path)
        return norm in self.entries and self.entries[norm].is_dir

    def get(self, path: str) -> Optional[FSEntry]:
        return self.entries.get(self._norm(path))

    def mkdir(self, path: str, mode: int = 0o755, owner: str = "root", group: str = "root", parents: bool = False) -> bool:
        norm = self._norm(path)
        if norm in self.entries:
            return False

        if parents and norm != "/":
            parts = norm.split("/")
            curr = ""
            for p in parts[1:-1]:
                curr += "/" + p
                if curr not in self.entries:
                    self.entries[curr] = FSEntry(name=p, is_dir=True, mode=0o755, owner=owner, group=group)

        name = norm.split("/")[-1] or "/"
        self.entries[norm] = FSEntry(name=name, is_dir=True, mode=mode, owner=owner, group=group)
        return True

    def write_file(self, path: str, content: str, mode: int = 0o644, owner: str = "root", group: str = "root", append: bool = False) -> FSEntry:
        norm = self._norm(path)
        parent_dir = norm.rsplit("/", 1)[0] or "/"
        if parent_dir not in self.entries:
            self.mkdir(parent_dir, parents=True)

        if norm in self.entries and not self.entries[norm].is_dir:
            entry = self.entries[norm]
            if append:
                entry.content += content
            else:
                entry.content = content
            entry.size = len(entry.content.encode("utf-8"))
            entry.mtime = time.time()
            return entry

        name = norm.split("/")[-1]
        entry = FSEntry(
            name=name,
            is_dir=False,
            content=content,
            mode=mode,
            owner=owner,
            group=group,
            size=len(content.encode("utf-8")),
            mtime=time.time()
        )
        self.entries[norm] = entry
        return entry

    def remove(self, path: str, recursive: bool = False) -> bool:
        norm = self._norm(path)
        if norm not in self.entries:
            return False

        if self.entries[norm].is_dir:
            if not recursive:
                # Check if empty
                prefix = norm if norm == "/" else f"{norm}/"
                has_children = any(p != norm and p.startswith(prefix) for p in self.entries)
                if has_children:
                    return False
            # Remove directory and all children
            prefix = norm if norm == "/" else f"{norm}/"
            to_del = [p for p in self.entries if p == norm or p.startswith(prefix)]
            for p in to_del:
                del self.entries[p]
            return True
        else:
            del self.entries[norm]
            return True

    def move(self, src: str, dst: str) -> bool:
        src_n = self._norm(src)
        dst_n = self._norm(dst)
        if src_n not in self.entries:
            return False

        # If destination is existing directory, move into it
        if dst_n in self.entries and self.entries[dst_n].is_dir:
            dst_n = self._norm(f"{dst_n}/{src_n.split('/')[-1]}")

        entry = self.entries.pop(src_n)
        entry.name = dst_n.split("/")[-1]
        entry.mtime = time.time()
        self.entries[dst_n] = entry
        return True

    def copy(self, src: str, dst: str) -> bool:
        src_n = self._norm(src)
        dst_n = self._norm(dst)
        if src_n not in self.entries:
            return False

        if dst_n in self.entries and self.entries[dst_n].is_dir:
            dst_n = self._norm(f"{dst_n}/{src_n.split('/')[-1]}")

        src_entry = self.entries[src_n]
        if src_entry.is_dir:
            self.mkdir(dst_n, mode=src_entry.mode, owner=src_entry.owner, group=src_entry.group)
        else:
            self.write_file(dst_n, src_entry.content, mode=src_entry.mode, owner=src_entry.owner, group=src_entry.group)
        return True

    def chmod(self, path: str, mode: int) -> bool:
        norm = self._norm(path)
        if norm in self.entries:
            self.entries[norm].mode = mode
            return True
        return False

    def list_dir(self, dir_path: str) -> List[Tuple[str, FSEntry]]:
        norm = self._norm(dir_path)
        if norm not in self.entries or not self.entries[norm].is_dir:
            return []

        prefix = norm if norm == "/" else f"{norm}/"
        results = {}
        for p, entry in self.entries.items():
            if p == norm:
                continue
            if p.startswith(prefix):
                rel = p[len(prefix):]
                parts = rel.split("/")
                child_name = parts[0]
                if child_name not in results:
                    child_path = f"{prefix}{child_name}" if norm != "/" else f"/{child_name}"
                    results[child_name] = self.entries.get(child_path, entry)
        return sorted(results.items(), key=lambda x: x[0])

    def to_legacy_dict(self) -> Dict[str, str]:
        """Provides backward compatibility for code expecting Dict[str, str]"""
        return {p: entry.content for p, entry in self.entries.items() if not entry.is_dir}

class HoneySSHInterface(paramiko.ServerInterface):
    """
    Paramiko ServerInterface with authentic OpenSSH 8.9 behavior:
    - Standard auth methods announcement: "publickey,password"
    - Strict 3-attempt limit per session before disconnect
    - Jittered delay on authentication (0.5s - 1.8s)
    - Lure Policy: Never admit on first password attempt; admit weak decoy creds on attempt 2 or 3
    - Disconnect message: "Too many authentication failures"
    """
    def __init__(
        self,
        auth_callback: Callable,
        decoy_creds: List[dict] = None,
        max_attempts: int = 3,
        trap_ref = None,
        client_ip: str = "127.0.0.1"
    ):
        self.auth_callback = auth_callback
        self.decoy_creds = decoy_creds or list(DEFAULT_DECOY_CREDENTIALS)
        self.event = threading.Event()
        self.authenticated_user = None
        self.auth_attempts = 0
        self.max_attempts = max_attempts
        self.trap_ref = trap_ref
        self.client_ip = client_ip
        self.transport = None
        self.exec_command = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode("utf-8") if isinstance(command, bytes) else str(command)
        self.event.set()
        return True

    def get_allowed_auths(self, username):
        # OpenSSH standard auth offer: publickey first, then password
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        # Scanners / authentic clients query or try keys first
        time.sleep(random.uniform(0.1, 0.3))
        fingerprint = hashlib.sha256(key.asbytes()).hexdigest()[:16]
        self.auth_callback(username, f"[publickey-{key.get_name()}:{fingerprint}]", False, "publickey_rejected")
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        self.auth_attempts += 1
        
        # MASK-6: Realistic authentication jitter delay (0.5s - 1.8s)
        time.sleep(random.uniform(0.5, 1.8))

        is_decoy = False
        for c in self.decoy_creds:
            if c.get("user") == username and c.get("pass") == password:
                is_decoy = True
                break

        if not is_decoy:
            decoy_users = {c.get("user") for c in self.decoy_creds}
            decoy_passes = {c.get("pass") for c in self.decoy_creds} | {"toor", "123456", "admin"}
            if username in decoy_users and password in decoy_passes:
                is_decoy = True

        # Check if client IP previously attempted auth recently on this trap
        prior_attempt = False
        if self.trap_ref and hasattr(self.trap_ref, "_recent_auth_ips"):
            ip_key = f"{self.client_ip}:{username}"
            now = time.time()
            last_attempt = self.trap_ref._recent_auth_ips.get(ip_key, 0)
            if 0 < (now - last_attempt) <= 45.0:
                prior_attempt = True
            else:
                self.trap_ref._recent_auth_ips[ip_key] = now

        # Lure Policy (Item 3):
        # Never admit on first password attempt (permission denied).
        # Admit valid decoy credentials on attempt 2 or 3 (or on immediate retry connection).
        can_admit = is_decoy and (self.auth_attempts >= 2 or prior_attempt)

        if can_admit:
            self.authenticated_user = username
            self.auth_callback(username, password, True, "decoy_accepted")
            if self.trap_ref and hasattr(self.trap_ref, "_recent_auth_ips"):
                self.trap_ref._recent_auth_ips.pop(ip_key, None)
            return paramiko.AUTH_SUCCESSFUL

        # Failed attempt
        reason = "lure_first_attempt_rejection" if is_decoy else "invalid_password"
        self.auth_callback(username, password, False, reason)

        if self.auth_attempts >= self.max_attempts:
            # Item 2: Max 3 attempts, then disconnect with "Too many authentication failures"
            def _delayed_disconnect():
                time.sleep(0.08)
                try:
                    if self.transport:
                        m = paramiko.Message()
                        m.add_byte(paramiko.common.cMSG_DISCONNECT)
                        m.add_int(paramiko.common.DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE)
                        m.add_string("Too many authentication failures")
                        m.add_string("en")
                        self.transport._send_message(m)
                        self.transport.close()
                except Exception:
                    pass
            threading.Thread(target=_delayed_disconnect, daemon=True).start()

        return paramiko.AUTH_FAILED

class FakeSSHTrap(BaseTrapService):
    """
    FR-A1, FR-A2, MASK-6: High-fidelity Medium-interaction SSH Honeypot.
    - Indistinguishable from authentic Ubuntu 22.04 LTS OpenSSH 8.9 server
    - Persistent Host Keys (RSA, ECDSA, Ed25519)
    - Dynamic persona integration (unique hostname, MAC, kernel, dynamic uptime)
    - Persistent boot timestamp (btime) preserved across container restarts
    - Hardened protocol suite: OpenSSH 8.9 modern ciphers/kex/macs
    - Strict lure policy (attempt 1 rejection, admission on attempt 2/3)
    - Interactive shell: exit codes ($?), Ctrl-C, Ctrl-D, Tab completion, history
    - Complete GNU coreutils command set with authentic error strings
    - Network simulation (wget, curl, ping, nc) with artifact capture and zero egress
    - Realistic execution jitter (15-75ms regular, 350-850ms heavy)
    - Concurrency limiter and resilient exception guarding
    """
    def __init__(
        self,
        port: int,
        event_callback: Callable[[Dict[str, Any]], None],
        session_callback: Callable[[Dict[str, Any]], None],
        trap_id: str,
        decoy_creds: List[Dict[str, str]] = None,
        persona: Dict[str, Any] = None,
        max_concurrent_sessions: int = 15
    ):
        super().__init__("SSHService", port, event_callback)
        self.session_callback = session_callback
        self.trap_id = trap_id
        self.decoy_creds = decoy_creds if decoy_creds is not None else list(DEFAULT_DECOY_CREDENTIALS)
        self.persona = persona or self._generate_default_persona(trap_id)
        self.semaphore = threading.Semaphore(max_concurrent_sessions)
        self._recent_auth_ips: Dict[str, float] = {}

        # Setup persistent cache and boot timestamp
        self.cache_dir = os.environ.get("PERSISTENT_DATA_DIR", ".cache")
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except Exception:
            self.cache_dir = "/var/tmp/.cache"
            try:
                os.makedirs(self.cache_dir, exist_ok=True)
            except Exception:
                self.cache_dir = "/tmp/.sysmon_cache"
                os.makedirs(self.cache_dir, exist_ok=True)
        self.boot_time = self._init_boot_time()

        # Load or create persistent host keys (RSA, ECDSA, Ed25519)
        keys_dir = os.environ.get("SSH_KEYS_DIR", "/etc/ssh")
        try:
            os.makedirs(keys_dir, exist_ok=True)
            test_f = os.path.join(keys_dir, ".test_write")
            with open(test_f, "w") as f:
                f.write("1")
            os.remove(test_f)
        except Exception:
            keys_dir = os.path.join(self.cache_dir, "keys")
            os.makedirs(keys_dir, exist_ok=True)
        self.host_keys = self._load_or_create_host_keys(keys_dir)
        self.host_key = self.host_keys[0] # primary RSA for backward compat

        self.server_socket = None
        self._thread = None

    def _generate_default_persona(self, trap_id: str) -> Dict[str, Any]:
        """Generates deterministic unique persona based on trap_id hash"""
        h = hashlib.sha256(trap_id.encode()).hexdigest()
        host_num = (int(h[:4], 16) % 30) + 1
        prefixes = ["srv-app", "corp-web", "int-syslog", "dc-node", "prod-srv", "mon-edge"]
        prefix = prefixes[int(h[4:6], 16) % len(prefixes)]
        hostname = f"{prefix}-{host_num:02d}"

        mac = f"02:42:{h[6:8]}:{h[8:10]}:{h[10:12]}:{h[12:14]}"
        kernel = "5.15.0-105-generic"
        uptime_base = 172800 + (int(h[16:20], 16) % 600000)

        return {
            "hostname": hostname,
            "mac": mac,
            "kernel": kernel,
            "os": "Ubuntu 22.04.4 LTS",
            "uptime_base": uptime_base,
            "users": ["root", "deploy", "ubuntu"]
        }

    def _init_boot_time(self) -> float:
        """Item 1: Persistent boot time across container restarts"""
        btime_file = os.path.join(self.cache_dir, f"btime_{self.trap_id}.json")
        try:
            if os.path.isfile(btime_file):
                with open(btime_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    bt = float(data.get("boot_time", 0))
                    if bt > 0 and bt < time.time():
                        return bt
        except Exception:
            pass

        base_uptime = float(self.persona.get("uptime_base", 172800))
        boot_time = time.time() - base_uptime
        try:
            with open(btime_file, "w", encoding="utf-8") as f:
                json.dump({"boot_time": boot_time}, f)
        except Exception:
            pass
        return boot_time

    def _load_or_create_host_keys(self, keys_dir: str) -> List[paramiko.PKey]:
        """Item 2: Persistent RSA, ECDSA, and Ed25519 host keys with 0600 private / 0644 .pub permissions"""
        os.makedirs(keys_dir, exist_ok=True)
        rsa_path = os.path.join(keys_dir, "ssh_host_rsa_key")
        ecdsa_path = os.path.join(keys_dir, "ssh_host_ecdsa_key")
        ed25519_path = os.path.join(keys_dir, "ssh_host_ed25519_key")
        hostname = self.persona.get("hostname", "ubuntu-node")

        keys = []

        # 1. RSA Key
        try:
            if os.path.isfile(rsa_path):
                rsa_key = paramiko.RSAKey.from_private_key_file(rsa_path)
            else:
                raise ValueError("Generate new")
        except Exception:
            rsa_key = paramiko.RSAKey.generate(2048)
            try:
                rsa_key.write_private_key_file(rsa_path)
            except Exception:
                pass
        keys.append(rsa_key)
        try:
            os.chmod(rsa_path, 0o600)
            rsa_pub_path = f"{rsa_path}.pub"
            with open(rsa_pub_path, "w", encoding="utf-8") as f:
                f.write(f"{rsa_key.get_name()} {rsa_key.get_base64()} root@{hostname}\n")
            os.chmod(rsa_pub_path, 0o644)
        except Exception:
            pass

        # 2. ECDSA Key
        try:
            if os.path.isfile(ecdsa_path):
                ecdsa_key = paramiko.ECDSAKey.from_private_key_file(ecdsa_path)
            else:
                raise ValueError("Generate new")
        except Exception:
            ecdsa_key = paramiko.ECDSAKey.generate()
            try:
                ecdsa_key.write_private_key_file(ecdsa_path)
            except Exception:
                pass
        keys.append(ecdsa_key)
        try:
            os.chmod(ecdsa_path, 0o600)
            ecdsa_pub_path = f"{ecdsa_path}.pub"
            with open(ecdsa_pub_path, "w", encoding="utf-8") as f:
                f.write(f"{ecdsa_key.get_name()} {ecdsa_key.get_base64()} root@{hostname}\n")
            os.chmod(ecdsa_pub_path, 0o644)
        except Exception:
            pass

        # 3. Ed25519 Key
        try:
            if os.path.isfile(ed25519_path):
                ed25519_key = paramiko.Ed25519Key.from_private_key_file(ed25519_path)
            else:
                raise ValueError("Generate new")
        except Exception:
            try:
                from cryptography.hazmat.primitives.asymmetric import ed25519
                from cryptography.hazmat.primitives import serialization
                ed_priv = ed25519.Ed25519PrivateKey.generate()
                pem = ed_priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.OpenSSH,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open(ed25519_path, "wb") as f:
                    f.write(pem)
                ed25519_key = paramiko.Ed25519Key.from_private_key_file(ed25519_path)
            except Exception:
                import io
                ed25519_key = paramiko.Ed25519Key.from_private_key(io.StringIO(pem.decode("utf-8")))
        keys.append(ed25519_key)
        try:
            os.chmod(ed25519_path, 0o600)
            ed25519_pub_path = f"{ed25519_path}.pub"
            with open(ed25519_pub_path, "w", encoding="utf-8") as f:
                f.write(f"{ed25519_key.get_name()} {ed25519_key.get_base64()} root@{hostname}\n")
            os.chmod(ed25519_pub_path, 0o644)
        except Exception:
            pass

        return keys

    def update_config(self, decoy_creds: List[dict] = None, persona: dict = None):
        """Dynamic runtime update without restarting process (FR-A3)"""
        if decoy_creds is not None:
            self.decoy_creds = decoy_creds
        if persona is not None:
            self.persona.update(persona)

    def _create_initial_fs(self) -> Dict[str, str]:
        """Legacy helper returning Dict[str, str] for backward compatibility"""
        vfs = VirtualFS(self.persona, self.trap_id, self.boot_time)
        return vfs.to_legacy_dict()

    def _configure_security_options(self, transport: paramiko.Transport):
        """Item 2: Configure OpenSSH 8.9 modern cipher suite on Transport"""
        sec = transport.get_security_options()
        sec.ciphers = (
            "aes128-ctr", "aes192-ctr", "aes256-ctr",
            "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"
        )
        sec.kex = (
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group14-sha256"
        )
        sec.digests = (
            "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256", "hmac-sha2-512"
        )
        sec.key_types = (
            "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
            "rsa-sha2-512", "rsa-sha2-256"
        )

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]):
        if not self.semaphore.acquire(blocking=False):
            # Item 8: Concurrency limit exceeded
            try:
                client_sock.close()
            except Exception:
                pass
            return

        client_ip, client_port = client_addr
        session_id = f"ssh-{uuid.uuid4().hex[:8]}"
        command_history = []
        captured_artifacts = []
        vfs = VirtualFS(self.persona, self.trap_id, self.boot_time)
        current_dir = "/root"
        last_exit_code = 0

        def auth_listener(user, pwd, success, reason=""):
            event = {
                "event_id": str(uuid.uuid4()),
                "event_uid": f"auth-{client_ip}-{user}-{time.time()}-{uuid.uuid4().hex[:6]}",
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "captured_at": time.time(),
                "source_ip": client_ip,
                "source_port": client_port,
                "protocol": "SSH",
                "destination_port": self.port,
                "event_type": "auth_attempt",
                "severity": "medium" if not success else "high",
                "credentials": {"username": user, "password": pwd},
                "session_id": session_id,
                "payload_raw": f"SSH Login attempt: user={user} pass={pwd} result={'SUCCESS' if success else 'FAILURE'} reason={reason}",
                "is_ioc": True
            }
            self.event_callback(event)

        transport = None
        try:
            # LoginGraceTime 120s (Item 2)
            client_sock.settimeout(120.0)

            transport = paramiko.Transport(client_sock)
            # Realistic OpenSSH 8.9p1 banner (Ubuntu 22.04.4 LTS)
            ssh_banner = (
                self.persona.get("ssh_banner")
                or (self.persona.get("banners") or {}).get("22")
                or (self.persona.get("banners") or {}).get(22)
                or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
            )
            if not ssh_banner.startswith("SSH-2.0-"):
                ssh_banner = f"SSH-2.0-{ssh_banner}"
            transport.local_version = ssh_banner
            self._configure_security_options(transport)

            # Add all host keys (RSA, ECDSA, Ed25519)
            for k in self.host_keys:
                transport.add_server_key(k)

            server = HoneySSHInterface(
                auth_callback=auth_listener,
                decoy_creds=self.decoy_creds,
                max_attempts=3,
                trap_ref=self,
                client_ip=client_ip
            )
            server.transport = transport

            transport.start_server(server=server)

            while transport.is_active():
                channel = transport.accept(120)
                if channel is None:
                    break

                server.event.wait(15)
                if not server.event.is_set():
                    break

                # Client authenticated, set session idle timeout (300s)
                channel.settimeout(300.0)

                hostname = self.persona.get("hostname", f"srv-{self.trap_id[-4:]}")
                user = server.authenticated_user or "root"
                home_dir = "/root" if user == "root" else f"/home/{user}"
                if not current_dir:
                    current_dir = home_dir

                # Handle non-interactive command execution (e.g. paramiko exec_command)
                if getattr(server, "exec_command", None):
                    raw_cmd = server.exec_command.strip()
                    server.exec_command = None
                    server.event.clear()
                    output, is_download, art_hash, new_dir, retcode = self._execute_command_vfs(
                        raw_cmd, client_ip, session_id, user, current_dir, vfs, last_exit_code, command_history
                    )
                    current_dir = new_dir
                    last_exit_code = retcode
                    if output:
                        if retcode == 0:
                            channel.send(output.encode("utf-8"))
                        else:
                            channel.send_stderr(output.encode("utf-8"))
                    channel.send_exit_status(retcode)
                    channel.close()
                    continue

                # Record session login into virtual /var/log/auth.log
                auth_log_entry = f"{datetime.datetime.utcnow().strftime('%b %d %H:%M:%S')} {hostname} sshd[{random.randint(1900, 3200)}]: Accepted password for {user} from {client_ip} port {client_port} ssh2\n"
                vfs.write_file("/var/log/auth.log", auth_log_entry, append=True)

                self._run_interactive_shell(
                    channel, user, hostname, home_dir, current_dir, vfs,
                    client_ip, client_port, session_id, last_exit_code, command_history, captured_artifacts
                )
                channel.close()
                break

        except Exception:
            pass
        finally:
            self.semaphore.release()
            if command_history:
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

    def _run_interactive_shell(
        self, channel, user, hostname, home_dir, current_dir, vfs,
        client_ip, client_port, session_id, last_exit_code, command_history, captured_artifacts
    ):
        kernel = self.persona.get("kernel", "5.15.0-105-generic")
        now_dt = datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
        banner = (
            f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux {kernel} x86_64)\r\n\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/pro\r\n\r\n"
            f"System information as of {now_dt}\r\n\r\n"
            "  System load:  0.08               Processes:             118\r\n"
            "  Usage of /:   24.1% of 48.29GB   Users logged in:       1\r\n"
            f"  Memory usage: 22%                IPv4 address for eth0: {self.persona.get('ip', '172.28.0.20')}\r\n"
            "  Swap usage:   0%\r\n\r\n"
            f"Last login: {now_dt} from {client_ip}\r\n"
        )
        channel.send(banner.encode())

        def get_prompt_path(cd: str) -> str:
            if cd == home_dir:
                return "~"
            if cd.startswith(home_dir + "/"):
                return "~" + cd[len(home_dir):]
            return cd

        def get_prompt(cd: str) -> str:
            p_path = get_prompt_path(cd)
            return f"{user}@{hostname}:{p_path}# " if user == "root" else f"{user}@{hostname}:{p_path}$ "

        prompt_str = get_prompt(current_dir)
        channel.send(prompt_str.encode())

        cmd_buffer = ""
        while True:
            try:
                data = channel.recv(1024)
            except socket.timeout:
                channel.send(b"\r\nTimed out waiting for input: auto-logout\r\n")
                break
            except Exception:
                break

            if not data:
                break

            if len(cmd_buffer) > 4096:
                cmd_buffer = cmd_buffer[:4096]

            text = data.decode(errors="ignore")
            should_exit = False

            for char in text:
                if char in ["\r", "\n"]:
                    channel.send(b"\r\n")
                    raw_cmd = cmd_buffer.strip()
                    cmd_buffer = ""

                    if not raw_cmd:
                        channel.send(prompt_str.encode())
                        continue

                    if raw_cmd in ["exit", "logout"]:
                        channel.send(f"logout\r\nConnection to {hostname} closed.\r\n".encode())
                        should_exit = True
                        break

                    output, is_download, art_hash, new_dir, retcode = self._execute_command_vfs(
                        raw_cmd, client_ip, session_id, user, current_dir, vfs, last_exit_code, command_history
                    )
                    current_dir = new_dir
                    last_exit_code = retcode
                    prompt_str = get_prompt(current_dir)

                    command_history.append({
                        "timestamp": datetime.datetime.utcnow().isoformat(),
                        "cmd": raw_cmd[:1024],
                        "output": output[:2048],
                        "exit_code": retcode
                    })

                    if is_download:
                        filename = raw_cmd.split()[-1].split("/")[-1] or "payload.sh"
                        captured_artifacts.append({
                            "sha256": art_hash,
                            "filename": filename,
                            "cmd": raw_cmd
                        })

                    if output:
                        channel.send(output.replace("\n", "\r\n").encode())
                    channel.send(prompt_str.encode())

                elif char == "\x03":
                    channel.send(b"^C\r\n")
                    cmd_buffer = ""
                    last_exit_code = 130
                    prompt_str = get_prompt(current_dir)
                    channel.send(prompt_str.encode())

                elif char == "\x04":
                    if not cmd_buffer:
                        channel.send(f"logout\r\nConnection to {hostname} closed.\r\n".encode())
                        should_exit = True
                        break

                elif char == "\t":
                    tokens = cmd_buffer.split()
                    prefix = tokens[-1] if (tokens and not cmd_buffer.endswith(" ")) else ""
                    if "/" in prefix:
                        search_dir = prefix.rsplit("/", 1)[0]
                        if not search_dir.startswith("/"):
                            search_dir = f"{current_dir.rstrip('/')}/{search_dir}"
                        match_prefix = prefix.rsplit("/", 1)[1]
                    else:
                        search_dir = current_dir
                        match_prefix = prefix

                    candidates = []
                    for name, entry in vfs.list_dir(search_dir):
                        if name.startswith(match_prefix):
                            candidates.append(name + ("/" if entry.is_dir else ""))

                    if len(candidates) == 1:
                        match = candidates[0]
                        remainder = match[len(match_prefix):]
                        if not match.endswith("/"):
                            remainder += " "
                        cmd_buffer += remainder
                        channel.send(remainder.encode())

                elif char in ["\x7f", "\x08"]:
                    if cmd_buffer:
                        cmd_buffer = cmd_buffer[:-1]
                        channel.send(b"\b \b")

                else:
                    if len(cmd_buffer) < 4096:
                        cmd_buffer += char
                        channel.send(char.encode())

            if should_exit:
                break

    def _execute_command_vfs(
        self,
        cmd: str,
        client_ip: str,
        session_id: str,
        user: str,
        current_dir: str,
        vfs: VirtualFS,
        last_exit_code: int,
        session_history: List[dict]
    ) -> Tuple[str, bool, str, str, int]:
        # Item 7: Realistic command timing jitter
        parts = cmd.split()
        root_cmd = parts[0] if parts else ""

        # Heavy command delay (350-850ms) vs normal command jitter (15-75ms)
        if root_cmd in ["find", "du", "apt", "apt-get", "pip", "grep", "top"]:
            time.sleep(random.uniform(0.35, 0.85))
        else:
            time.sleep(random.uniform(0.015, 0.075))

        out, is_dl, sha, new_dir = self._emulate_command_core(
            cmd, client_ip, session_id, user, current_dir, vfs, last_exit_code, session_history
        )
        # Determine exit code based on output error markers
        code = 0
        if "command not found" in out:
            code = 127
        elif "No such file or directory" in out or "cannot access" in out or "Not a directory" in out or "Is a directory" in out:
            code = 1
        elif "Permission denied" in out:
            code = 1
        elif "no crontab for" in out:
            code = 1
        elif "Connection refused" in out:
            code = 7 if "curl:" in out else 4
        elif "Could not resolve host" in out or "unable to resolve" in out:
            code = 6 if "curl:" in out else 4
        elif "Connection timed out" in out or "failed: Connection timed out" in out:
            code = 28 if "curl:" in out else 4
        return out, is_dl, sha, new_dir, code

    def _emulate_command(
        self,
        cmd: str,
        client_ip: str,
        session_id: str,
        user: str,
        current_dir: str,
        fs: Any
    ) -> Tuple[str, bool, str, str]:
        """Backward-compatible method signature used by existing unit tests & selfchecks"""
        if isinstance(fs, VirtualFS):
            vfs = fs
        else:
            vfs = VirtualFS(self.persona, self.trap_id, self.boot_time)
            if isinstance(fs, dict):
                for k, v in fs.items():
                    if isinstance(v, str):
                        vfs.write_file(k, v)

        out, is_dl, sha, new_dir = self._emulate_command_core(
            cmd, client_ip, session_id, user, current_dir, vfs, 0, []
        )
        if isinstance(fs, dict):
            # Sync back modifications into dictionary for legacy tests
            fs.update(vfs.to_legacy_dict())
        return out, is_dl, sha, new_dir

    def _emulate_command_core(
        self,
        cmd: str,
        client_ip: str,
        session_id: str,
        user: str,
        current_dir: str,
        vfs: VirtualFS,
        last_exit_code: int,
        session_history: List[dict]
    ) -> Tuple[str, bool, str, str]:
        parts = cmd.split()
        root_cmd = parts[0] if parts else ""
        new_dir = current_dir
        hostname = self.persona.get("hostname", f"srv-{self.trap_id[-4:]}")

        # Record shell_command event
        ev = {
            "event_id": str(uuid.uuid4()),
            "event_uid": f"cmd-{session_id}-{time.time()}-{uuid.uuid4().hex[:6]}",
            "trap_id": self.trap_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "captured_at": time.time(),
            "source_ip": client_ip,
            "source_port": 0,
            "protocol": "SSH",
            "destination_port": self.port,
            "event_type": "shell_command",
            "severity": "medium",
            "command_text": cmd[:1024],
            "session_id": session_id,
            "is_ioc": True
        }
        self.event_callback(ev)

        # Item 5: Canary lure / Honeytoken access detection
        if any(kw in cmd for kw in [".aws", "credentials", "id_rsa", "production_dump.sql", "/etc/shadow"]):
            ht_ev = {
                "event_id": str(uuid.uuid4()),
                "event_uid": f"ht-{session_id}-{time.time()}-{uuid.uuid4().hex[:6]}",
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "captured_at": time.time(),
                "source_ip": client_ip,
                "source_port": 0,
                "protocol": "SSH",
                "destination_port": self.port,
                "event_type": "honeytoken_triggered",
                "severity": "critical",
                "command_text": cmd[:1024],
                "payload_raw": f"Attacker accessed Honeytoken file: {cmd}",
                "session_id": session_id,
                "is_ioc": True
            }
            self.event_callback(ht_ev)

        # Chained command execution support (&& and ;)
        if "&&" in cmd:
            subcmds = [c.strip() for c in cmd.split("&&") if c.strip()]
            combined_out = []
            final_is_dl = False
            final_sha = ""
            for subcmd in subcmds:
                sub_out, sub_dl, sub_sha, new_dir = self._emulate_command_core(
                    subcmd, client_ip, session_id, user, new_dir, vfs, last_exit_code, session_history
                )
                combined_out.append(sub_out)
                if sub_dl:
                    final_is_dl = True
                    final_sha = sub_sha
                if "command not found" in sub_out or "No such file or directory" in sub_out:
                    break
            return "".join(combined_out), final_is_dl, final_sha, new_dir

        if ";" in cmd and not cmd.startswith("awk"):
            subcmds = [c.strip() for c in cmd.split(";") if c.strip()]
            combined_out = []
            final_is_dl = False
            final_sha = ""
            for subcmd in subcmds:
                sub_out, sub_dl, sub_sha, new_dir = self._emulate_command_core(
                    subcmd, client_ip, session_id, user, new_dir, vfs, last_exit_code, session_history
                )
                combined_out.append(sub_out)
                if sub_dl:
                    final_is_dl = True
                    final_sha = sub_sha
            return "".join(combined_out), final_is_dl, final_sha, new_dir

        # ---------------------------------------------------------------------
        # Item 6: Simulated Network Utilities (Zero Egress)
        # ---------------------------------------------------------------------
        if root_cmd in ["wget", "curl"]:
            is_wget = (root_cmd == "wget")
            is_curl = (root_cmd == "curl")

            quiet = False
            output_to_stdout = False
            output_filename = None
            target_url = None

            i = 1
            while i < len(parts):
                arg = parts[i]
                if arg in ["-q", "--quiet"]:
                    quiet = True
                elif arg == "-qO-":
                    quiet = True
                    output_to_stdout = True
                elif arg.startswith("-qO") and len(arg) > 3:
                    quiet = True
                    output_filename = arg[3:]
                    if output_filename == "-":
                        output_to_stdout = True
                elif arg in ["-s", "--silent", "-sS", "-sSL", "-fsSL", "-SsL", "-sL"]:
                    quiet = True
                elif arg in ["-O", "-o", "--output"]:
                    if i + 1 < len(parts):
                        output_filename = parts[i + 1]
                        i += 1
                        if output_filename == "-":
                            output_to_stdout = True
                    elif arg == "-O" and is_curl:
                        pass
                elif arg == "-O-":
                    output_to_stdout = True
                elif arg.startswith("-o") and len(arg) > 2:
                    output_filename = arg[2:]
                elif arg.startswith("-O") and len(arg) > 2:
                    output_filename = arg[2:]
                    if output_filename == "-":
                        output_to_stdout = True
                elif not arg.startswith("-"):
                    target_url = arg
                i += 1

            if not target_url:
                target_url = "http://example.com/payload.sh"

            derived_name = target_url.split("/")[-1].split("?")[0]
            if not derived_name:
                derived_name = "index.html"

            if output_filename and output_filename != "-":
                filename = output_filename
            else:
                filename = derived_name

            # Failure / connection simulation:
            if "127.0.0.1" in target_url or "localhost" in target_url:
                p_match = re.search(r":(\d+)", target_url)
                port_num = p_match.group(1) if p_match else "80"
                if port_num not in ["22", "80", "8088", "443"]:
                    if is_wget:
                        return f"Connecting to 127.0.0.1:{port_num}... failed: Connection refused.\n", False, "", new_dir
                    else:
                        return f"curl: (7) Failed to connect to 127.0.0.1 port {port_num} after 0 ms: Connection refused\n", False, "", new_dir

            if any(w in target_url.lower() for w in ["timeout", "unreachable-host"]):
                time.sleep(2.0)
                now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                if is_wget:
                    return f"--{now_str}--  {target_url}\nConnecting to {target_url}... failed: Connection timed out.\nGiving up.\n", False, "", new_dir
                else:
                    return f"curl: (28) Failed to connect to host: Connection timed out\n", False, "", new_dir

            if any(w in target_url.lower() for w in ["nonexistent", "nxdomain", "invalid-host"]):
                time.sleep(2.0)
                now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                if is_wget:
                    return f"--{now_str}--  {target_url}\nResolving {target_url}... failed: Name or service not known.\nwget: unable to resolve host address ‘{target_url}’\n", False, "", new_dir
                else:
                    return f"curl: (6) Could not resolve host: {target_url}\n", False, "", new_dir

            # Realistic content by file type without simulation markers
            if filename.endswith((".sh", ".bash")):
                payload_bytes = b"#!/bin/bash\n# System maintenance routine\nset -e\nSTATUS=0\nif [ -d \"/var/log\" ]; then\n    STATUS=1\nfi\nexit 0\n"
                mime_type = "text/x-shellscript"
            elif filename.endswith((".tar.gz", ".tgz", ".gz")):
                payload_bytes = gzip.compress(b"system-archive-backup-payload-stream-v1\n")
                mime_type = "application/x-gzip"
            elif filename.endswith((".elf", ".bin", ".so")):
                payload_bytes = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00\x70\x10@\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00"
                mime_type = "application/x-executable"
            else:
                payload_bytes = b"<!DOCTYPE html>\n<html><head><title>Index</title></head><body>OK</body></html>\n"
                mime_type = "text/html"

            payload_len = len(payload_bytes)
            sha256 = hashlib.sha256(payload_bytes).hexdigest()

            if not output_to_stdout or (output_filename and output_filename != "-"):
                target_path = f"{current_dir}/{filename}" if not filename.startswith("/") else filename
                vfs.write_file(target_path, payload_bytes.decode("latin1"), mode=0o755)

            dl_ev = {
                "event_id": str(uuid.uuid4()),
                "event_uid": f"dl-{session_id}-{sha256[:8]}-{uuid.uuid4().hex[:6]}",
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "captured_at": time.time(),
                "source_ip": client_ip,
                "source_port": 0,
                "protocol": "SSH",
                "destination_port": self.port,
                "event_type": "file_download",
                "severity": "critical",
                "command_text": cmd[:1024],
                "artifact_hash": sha256,
                "session_id": session_id,
                "payload_raw": f"Downloaded artifact: {target_url} (SHA256: {sha256})",
                "is_ioc": True
            }
            self.event_callback(dl_ev)

            now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            if quiet:
                if output_to_stdout:
                    return payload_bytes.decode("latin1"), True, sha256, new_dir
                return "", True, sha256, new_dir

            if is_wget:
                if output_to_stdout:
                    return payload_bytes.decode("latin1"), True, sha256, new_dir
                out = (
                    f"--{now_str}--  {target_url}\n"
                    "Resolving example.com (example.com)... 93.184.216.34\n"
                    "Connecting to example.com (example.com)|93.184.216.34|:80... connected.\n"
                    "HTTP request sent, awaiting response... 200 OK\n"
                    f"Length: {payload_len} [{mime_type}]\n"
                    f"Saving to: '{filename}'\n\n"
                    f"{filename:<20} 100%[===================>]     {payload_len}  --.-KB/s    in 0.001s\n\n"
                    f"{now_str} (4.20 MB/s) - '{filename}' saved [{payload_len}/{payload_len}]\n"
                )
                return out, True, sha256, new_dir
            elif is_curl:
                if output_to_stdout and not output_filename:
                    return payload_bytes.decode("latin1"), True, sha256, new_dir
                progress = (
                    f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                    f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                    f"100  {payload_len:>4}  100  {payload_len:>4}    0     0   {max(100, payload_len*10):>5}      0 --:--:-- --:--:-- --:--:-- {max(120, payload_len*12):>5}\n"
                )
                return progress, True, sha256, new_dir

        elif root_cmd == "ping":
            target = parts[1] if len(parts) > 1 and not parts[1].startswith("-") else "8.8.8.8"
            out = (
                f"PING {target} ({target}) 56(84) bytes of data.\n"
                f"64 bytes from {target}: icmp_seq=1 ttl=118 time=12.4 ms\n"
                f"64 bytes from {target}: icmp_seq=2 ttl=118 time=11.9 ms\n"
                f"64 bytes from {target}: icmp_seq=3 ttl=118 time=12.1 ms\n"
                f"64 bytes from {target}: icmp_seq=4 ttl=118 time=12.0 ms\n\n"
                f"--- {target} ping statistics ---\n"
                "4 packets transmitted, 4 received, 0% packet loss, time 3004ms\n"
                "rtt min/avg/max/mdev = 11.902/12.100/12.412/0.187 ms\n"
            )
            return out, False, "", new_dir

        elif root_cmd == "nc":
            if "-z" in parts or "-v" in parts:
                dest = parts[-2] if len(parts) > 2 else "127.0.0.1"
                p_num = parts[-1] if len(parts) > 1 else "22"
                if p_num in ["22", "80"]:
                    return f"Connection to {dest} {p_num} port [tcp/*] succeeded!\n", False, "", new_dir
                return f"nc: connect to {dest} port {p_num} (tcp) failed: Connection refused\n", False, "", new_dir
            return "", False, "", new_dir

        elif root_cmd == "ssh":
            dest = parts[-1] if len(parts) > 1 else "10.0.1.1"
            return f"ssh: connect to host {dest} port 22: Connection refused\n", False, "", new_dir

        # ---------------------------------------------------------------------
        # Item 4: Coreutils & Bash Handlers with Authentic GNU Layout & Errors
        # ---------------------------------------------------------------------
        if root_cmd == "whoami":
            return f"{user}\n", False, "", new_dir

        elif root_cmd == "id":
            if user == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n", False, "", new_dir
            return f"uid=1000({user}) gid=1000({user}) groups=1000({user}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)\n", False, "", new_dir

        elif root_cmd == "pwd":
            return f"{current_dir}\n", False, "", new_dir

        elif root_cmd == "uname":
            hostname = self.persona.get("hostname", f"srv-{self.trap_id[-4:]}")
            kernel = self.persona.get("kernel", "5.15.0-105-generic")
            if "-a" in parts:
                return f"Linux {hostname} {kernel} #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n", False, "", new_dir
            elif "-r" in parts:
                return f"{kernel}\n", False, "", new_dir
            elif "-m" in parts:
                return "x86_64\n", False, "", new_dir
            elif "-s" in parts:
                return "Linux\n", False, "", new_dir
            elif "-n" in parts:
                return f"{hostname}\n", False, "", new_dir
            return "Linux\n", False, "", new_dir

        elif root_cmd == "hostname":
            hostname = self.persona.get("hostname", f"srv-{self.trap_id[-4:]}")
            if "-f" in parts:
                return f"{hostname}.local\n", False, "", new_dir
            elif "-I" in parts or "-i" in parts:
                return f"{self.persona.get('ip', '172.28.0.20')}\n", False, "", new_dir
            return f"{hostname}\n", False, "", new_dir

        elif root_cmd == "uptime":
            # Item 1: Dynamic real-time uptime progression
            up_secs = int(time.time() - self.boot_time)
            days = up_secs // 86400
            hours = (up_secs % 86400) // 3600
            mins = (up_secs % 3600) // 60
            now_t = datetime.datetime.now().strftime("%H:%M:%S")
            if days > 0:
                return f" {now_t} up {days} days, {hours}:{mins:02d},  1 user,  load average: 0.08, 0.03, 0.01\n", False, "", new_dir
            return f" {now_t} up  {hours}:{mins:02d},  1 user,  load average: 0.08, 0.03, 0.01\n", False, "", new_dir

        elif root_cmd in ["w", "who"]:
            up_secs = int(time.time() - self.boot_time)
            days = up_secs // 86400
            hours = (up_secs % 86400) // 3600
            mins = (up_secs % 3600) // 60
            now_t = datetime.datetime.now().strftime("%H:%M:%S")
            login_t = (datetime.datetime.now() - datetime.timedelta(minutes=2)).strftime("%H:%M")
            if root_cmd == "who":
                return f"{user:<8} pts/0        {datetime.datetime.now().strftime('%Y-%m-%d')} {login_t} ({client_ip})\n", False, "", new_dir
            return (
                f" {now_t} up {days} days, {hours}:{mins:02d},  1 user,  load average: 0.08, 0.03, 0.01\n"
                "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{user:<8} pts/0    {client_ip:<16} {login_t}    0.00s  0.02s  0.00s -bash\n"
            ), False, "", new_dir

        elif root_cmd == "last":
            kernel = self.persona.get("kernel", "5.15.0-105-generic")
            boot_dt = datetime.datetime.fromtimestamp(self.boot_time).strftime("%a %b %d %H:%M")
            now_dt = datetime.datetime.now().strftime("%a %b %d %H:%M")
            return (
                f"{user:<8} pts/0        {client_ip:<16} {now_dt}   still logged in\n"
                f"reboot   system boot  {kernel:<16} {boot_dt}   still running\n\n"
                f"wtmp begins {boot_dt}\n"
            ), False, "", new_dir

        elif root_cmd == "date":
            return f"{datetime.datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')}\n", False, "", new_dir

        elif root_cmd == "cd":
            home_dir = "/root" if user == "root" else f"/home/{user}"
            target = parts[1] if len(parts) > 1 else home_dir
            if target == "~":
                target = home_dir
            elif target.startswith("~/"):
                target = f"{home_dir}/{target[2:]}"
            elif target == "..":
                if current_dir != "/":
                    target = "/".join(current_dir.rstrip("/").split("/")[:-1]) or "/"
                else:
                    target = "/"
            elif not target.startswith("/"):
                target = f"{current_dir.rstrip('/')}/{target}"

            target = vfs._norm(target)
            if not vfs.exists(target):
                return f"bash: cd: {parts[1] if len(parts) > 1 else target}: No such file or directory\n", False, "", new_dir
            if not vfs.is_dir(target):
                return f"bash: cd: {parts[1] if len(parts) > 1 else target}: Not a directory\n", False, "", new_dir
            new_dir = target
            return "", False, "", new_dir

        elif root_cmd in ["ls", "dir"]:
            # Parse arguments
            show_all = any(a in parts for a in ["-a", "-la", "-al", "-laF", "-all"])
            long_format = any(a in parts for a in ["-l", "-la", "-al", "-lh", "-lF"])
            sort_mtime = "-t" in parts

            target_path = current_dir
            for p in parts[1:]:
                if not p.startswith("-"):
                    target_path = p if p.startswith("/") else f"{current_dir.rstrip('/')}/{p}"
                    break

            target_path = vfs._norm(target_path)
            if not vfs.exists(target_path):
                raw_arg = [p for p in parts[1:] if not p.startswith("-")][0]
                return f"ls: cannot access '{raw_arg}': No such file or directory\n", False, "", new_dir

            target_entry = vfs.get(target_path)
            if not target_entry.is_dir:
                # Listing a single file
                if long_format:
                    m_str = _format_mode(target_entry.mode, False)
                    d_str = _format_gnu_date(target_entry.mtime)
                    return f"{m_str} 1 {target_entry.owner} {target_entry.group} {target_entry.size:>6} {d_str} {target_entry.name}\n", False, "", new_dir
                return f"{target_entry.name}\n", False, "", new_dir

            entries = vfs.list_dir(target_path)
            if not show_all:
                entries = [(name, e) for name, e in entries if not name.startswith(".")]

            if sort_mtime:
                entries.sort(key=lambda x: x[1].mtime, reverse=True)

            if long_format:
                lines = [f"total {len(entries) * 4}"]
                if show_all:
                    dot_d = _format_gnu_date(target_entry.mtime)
                    lines.append(f"drwxr-xr-x 4 {target_entry.owner} {target_entry.group} 4096 {dot_d} .")
                    lines.append(f"drwxr-xr-x 8 root root 4096 {dot_d} ..")
                for name, e in entries:
                    m_str = _format_mode(e.mode, e.is_dir)
                    d_str = _format_gnu_date(e.mtime)
                    nlink = 2 if e.is_dir else 1
                    lines.append(f"{m_str} {nlink} {e.owner} {e.group} {e.size:>6} {d_str} {name}")
                return "\n".join(lines) + "\n", False, "", new_dir
            else:
                names = [name for name, _ in entries]
                if not names:
                    return "", False, "", new_dir
                return "  ".join(names) + "\n", False, "", new_dir

        elif root_cmd == "cat":
            if len(parts) < 2:
                return "", False, "", new_dir
            target = parts[1]
            home_dir = "/root" if user == "root" else f"/home/{user}"
            if target == "~":
                target = home_dir
            elif target.startswith("~/"):
                target = f"{home_dir}/{target[2:]}"
            elif not target.startswith("/"):
                target = f"{current_dir.rstrip('/')}/{target}"
            target = vfs._norm(target)

            if target.startswith("/proc/"):
                # Handle dynamic virtual proc files
                if target == "/proc/version":
                    kernel = self.persona.get('kernel', '5.15.0-105-generic')
                    return f"Linux version {kernel} (buildd@lcy02-amd64-077) (gcc version 11.4.0) #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024\n", False, "", new_dir
                elif target == "/proc/uptime":
                    up_s = time.time() - self.boot_time
                    return f"{up_s:.2f} {up_s * 0.95:.2f}\n", False, "", new_dir
                elif target == "/proc/stat":
                    return f"cpu  1420 0 850 182040 120 0 15 0 0 0\nbtime {int(self.boot_time)}\nprocesses 2410\n", False, "", new_dir
                elif target == "/proc/loadavg":
                    return "0.08 0.03 0.01 1/118 2450\n", False, "", new_dir

            if not vfs.exists(target):
                return f"cat: {parts[1]}: No such file or directory\n", False, "", new_dir
            if vfs.is_dir(target):
                return f"cat: {parts[1]}: Is a directory\n", False, "", new_dir
            return vfs.get(target).content, False, "", new_dir

        elif root_cmd == "touch":
            if len(parts) < 2:
                return "touch: missing file operand\n", False, "", new_dir
            for p in parts[1:]:
                if p.startswith("-"):
                    continue
                target = p if p.startswith("/") else f"{current_dir.rstrip('/')}/{p}"
                vfs.write_file(target, "", mode=0o644, owner=user, group=user)
            return "", False, "", new_dir

        elif root_cmd == "mkdir":
            if len(parts) < 2:
                return "mkdir: missing operand\n", False, "", new_dir
            parents = "-p" in parts
            for p in parts[1:]:
                if p.startswith("-"):
                    continue
                target = p if p.startswith("/") else f"{current_dir.rstrip('/')}/{p}"
                target = vfs._norm(target)
                if vfs.exists(target) and not parents:
                    return f"mkdir: cannot create directory '{p}': File exists\n", False, "", new_dir
                vfs.mkdir(target, parents=parents, owner=user, group=user)
            return "", False, "", new_dir

        elif root_cmd == "rm":
            if len(parts) < 2:
                return "rm: missing operand\n", False, "", new_dir
            recursive = any(a in parts for a in ["-r", "-R", "-rf", "-fr"])
            target = parts[-1]
            target_path = target if target.startswith("/") else f"{current_dir.rstrip('/')}/{target}"
            target_path = vfs._norm(target_path)
            if not vfs.exists(target_path):
                return f"rm: cannot remove '{target}': No such file or directory\n", False, "", new_dir
            if vfs.is_dir(target_path) and not recursive:
                return f"rm: cannot remove '{target}': Is a directory\n", False, "", new_dir
            vfs.remove(target_path, recursive=recursive)
            return "", False, "", new_dir

        elif root_cmd in ["mv", "cp"]:
            if len(parts) < 3:
                return f"{root_cmd}: missing file operand\n", False, "", new_dir
            src = parts[1] if not parts[1].startswith("/") else parts[1]
            dst = parts[2] if not parts[2].startswith("/") else parts[2]
            src_p = src if src.startswith("/") else f"{current_dir.rstrip('/')}/{src}"
            dst_p = dst if dst.startswith("/") else f"{current_dir.rstrip('/')}/{dst}"
            if not vfs.exists(src_p):
                return f"{root_cmd}: cannot stat '{src}': No such file or directory\n", False, "", new_dir
            if root_cmd == "mv":
                vfs.move(src_p, dst_p)
            else:
                vfs.copy(src_p, dst_p)
            return "", False, "", new_dir

        elif root_cmd == "chmod":
            if len(parts) < 3:
                return "chmod: missing operand\n", False, "", new_dir
            mode_arg = parts[1]
            target = parts[2]
            target_p = target if target.startswith("/") else f"{current_dir.rstrip('/')}/{target}"
            if not vfs.exists(target_p):
                return f"chmod: cannot access '{target}': No such file or directory\n", False, "", new_dir
            try:
                new_mode = int(mode_arg, 8)
                vfs.chmod(target_p, new_mode)
            except Exception:
                pass
            return "", False, "", new_dir

        elif root_cmd == "echo":
            # Support $? variable inspection
            if "$?" in cmd:
                return f"{last_exit_code}\n", False, "", new_dir
            # Redirection support: echo "foo" > file or >> file
            if ">" in parts or ">>" in parts:
                is_append = ">>" in parts
                sep = ">>" if is_append else ">"
                idx = parts.index(sep)
                content = " ".join(parts[1:idx]).strip("\"'")
                target_name = parts[idx + 1] if idx + 1 < len(parts) else "output.txt"
                target_p = target_name if target_name.startswith("/") else f"{current_dir.rstrip('/')}/{target_name}"
                vfs.write_file(target_p, content + "\n", append=is_append, owner=user, group=user)
                return "", False, "", new_dir
            echo_text = " ".join(parts[1:]).strip("\"'")
            return f"{echo_text}\n", False, "", new_dir

        elif root_cmd == "history":
            lines = []
            # Preload realistic initial history
            initial_history = [
                "apt update",
                "apt install -y nginx curl htop",
                "systemctl status sshd",
                "cat /etc/os-release"
            ]
            idx = 1
            for h in initial_history:
                lines.append(f" {idx:>4}  {h}")
                idx += 1
            for rec in session_history:
                lines.append(f" {idx:>4}  {rec.get('cmd', '')}")
                idx += 1
            return "\n".join(lines) + "\n", False, "", new_dir

        elif root_cmd == "ps":
            if any(a in parts for a in ["aux", "-aux", "-ef", "ax", "-ax", "-e", "-f"]):
                return _generate_process_list(user, hostname, self.persona, self.boot_time, parts), False, "", new_dir
            return (
                "  PID TTY          TIME CMD\n"
                " 1851 pts/0    00:00:00 bash\n"
                " 1860 pts/0    00:00:00 ps\n"
            ), False, "", new_dir

        elif root_cmd in ["df", "df -h"]:
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/root        48G   12G   36G  25% /\n"
                "tmpfs           3.9G     0  3.9G   0% /dev/shm\n"
                "tmpfs           1.6G  1.1M  1.6G   1% /run\n"
                "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
            ), False, "", new_dir

        elif root_cmd in ["free", "free -m", "free -h"]:
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:            7951        1752        4710          18        1488        5980\n"
                "Swap:              0           0           0\n"
            ), False, "", new_dir

        elif root_cmd in ["netstat", "ss"]:
            return (
                "State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess\n"
                "LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:((\"sshd\",pid=1204,fd=3))\n"
                "LISTEN 0      128          0.0.0.0:80         0.0.0.0:*    users:((\"nginx\",pid=945,fd=4))\n"
                f"ESTAB  0      0           {self.persona.get('ip', '172.28.0.20')}:22        {client_ip}:52144 users:((\"sshd\",pid=1850,fd=4))\n"
            ), False, "", new_dir

        elif root_cmd == "ip":
            mac = self.persona.get("mac", "02:42:0a:c8:00:2c")
            ip = self.persona.get("ip", "172.28.0.20")
            if "route" in parts:
                return f"default via 172.28.0.1 dev eth0 proto dhcp src {ip} metric 100\n172.28.0.0/16 dev eth0 proto kernel scope link src {ip} metric 100\n", False, "", new_dir
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "       valid_lft forever preferred_lft forever\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n"
                f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff\n"
                f"    inet {ip}/16 brd 172.28.255.255 scope global dynamic eth0\n"
                "       valid_lft 85400sec preferred_lft 85400sec\n"
            ), False, "", new_dir

        elif root_cmd == "ifconfig":
            mac = self.persona.get("mac", "02:42:0a:c8:00:2c")
            ip = self.persona.get("ip", "172.28.0.20")
            return (
                f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                f"        inet {ip}  netmask 255.255.0.0  broadcast 172.28.255.255\n"
                f"        ether {mac}  txqueuelen 1000  (Ethernet)\n"
                "        RX packets 14210  bytes 1251920 (1.2 MB)\n"
                "        TX packets 8540  bytes 941020 (941.0 KB)\n\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                "        inet 127.0.0.1  netmask 255.0.0.0\n"
                "        loop  txqueuelen 1000  (Local Loopback)\n"
            ), False, "", new_dir

        elif root_cmd == "env":
            home_dir = "/root" if user == "root" else f"/home/{user}"
            return (
                f"SHELL=/bin/bash\n"
                f"PWD={current_dir}\n"
                f"LOGNAME={user}\n"
                f"USER={user}\n"
                f"HOME={home_dir}\n"
                "LANG=C.UTF-8\n"
                "TERM=xterm-256color\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            ), False, "", new_dir

        elif root_cmd == "lscpu":
            return (
                "Architecture:            x86_64\n"
                "  CPU op-mode(s):        32-bit, 64-bit\n"
                "  Address sizes:         46 bits physical, 48 bits virtual\n"
                "  Byte Order:            Little Endian\n"
                "CPU(s):                  2\n"
                "  On-line CPU(s) list:   0,1\n"
                "Vendor ID:               GenuineIntel\n"
                "  Model name:            Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
                "    CPU family:          6\n"
                "    Model:               85\n"
                "    Thread(s) per core:  1\n"
                "    Core(s) per socket:  2\n"
            ), False, "", new_dir

        elif root_cmd == "crontab":
            if "-l" in parts:
                return f"no crontab for {user}\n", False, "", new_dir
            return "", False, "", new_dir

        elif root_cmd == "sudo":
            h_name = self.persona.get('hostname', f'srv-{self.trap_id[-4:]}')
            if "-l" in parts:
                return (
                    f"Matching Defaults entries for {user} on {h_name}:\n"
                    "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n"
                    f"User {user} may run the following commands on {h_name}:\n"
                    "    (ALL : ALL) ALL\n"
                ), False, "", new_dir
            if len(parts) > 1:
                return self._emulate_command_core(" ".join(parts[1:]), client_ip, session_id, "root", current_dir, vfs, last_exit_code, session_history)
            return "root\n", False, "", new_dir

        elif root_cmd == "which":
            if len(parts) < 2:
                return "", False, "", new_dir
            target_binary = parts[1]
            standard_bins = ["bash", "sh", "ls", "cat", "cd", "cp", "mv", "rm", "mkdir", "touch", "chmod", "echo", "id", "whoami", "uname", "hostname", "uptime", "ps", "top", "free", "df", "grep", "find", "wget", "curl", "ssh", "ping", "nc", "sudo", "apt", "systemctl"]
            if target_binary in standard_bins:
                return f"/usr/bin/{target_binary}\n", False, "", new_dir
            return "", False, "", new_dir

        elif root_cmd == "find":
            search_path = parts[1] if len(parts) > 1 and not parts[1].startswith("-") else current_dir
            norm_search = vfs._norm(search_path if search_path.startswith("/") else f"{current_dir.rstrip('/')}/{search_path}")
            name_filter = None
            if "-name" in parts:
                idx = parts.index("-name")
                if idx + 1 < len(parts):
                    name_filter = parts[idx + 1].strip("\"'")

            matched = []
            prefix = norm_search if norm_search == "/" else f"{norm_search}/"
            for p in sorted(vfs.entries.keys()):
                if p == norm_search or p.startswith(prefix):
                    if name_filter:
                        fname = p.split("/")[-1]
                        if name_filter.replace("*", "") in fname:
                            matched.append(p)
                    else:
                        matched.append(p)
            return "\n".join(matched[:100]) + ("\n" if matched else ""), False, "", new_dir

        elif root_cmd == "grep":
            if len(parts) < 3:
                return "", False, "", new_dir
            pattern = parts[1].strip("\"'")
            fpath = parts[2]
            norm_f = vfs._norm(fpath if fpath.startswith("/") else f"{current_dir.rstrip('/')}/{fpath}")
            if not vfs.exists(norm_f):
                return f"grep: {fpath}: No such file or directory\n", False, "", new_dir
            entry = vfs.get(norm_f)
            matches = [line for line in entry.content.splitlines() if pattern in line]
            return ("\n".join(matches) + "\n") if matches else "", False, "", new_dir

        elif root_cmd in ["head", "tail"]:
            if len(parts) < 2:
                return "", False, "", new_dir
            fpath = parts[-1]
            norm_f = vfs._norm(fpath if fpath.startswith("/") else f"{current_dir.rstrip('/')}/{fpath}")
            if not vfs.exists(norm_f):
                return f"{root_cmd}: cannot open '{fpath}' for reading: No such file or directory\n", False, "", new_dir
            lines = vfs.get(norm_f).content.splitlines()
            res = lines[:10] if root_cmd == "head" else lines[-10:]
            return "\n".join(res) + "\n", False, "", new_dir

        elif root_cmd == "wc":
            if len(parts) < 2:
                return "", False, "", new_dir
            fpath = parts[-1]
            norm_f = vfs._norm(fpath if fpath.startswith("/") else f"{current_dir.rstrip('/')}/{fpath}")
            if not vfs.exists(norm_f):
                return f"wc: {fpath}: No such file or directory\n", False, "", new_dir
            c = vfs.get(norm_f).content
            lines_c = len(c.splitlines())
            words_c = len(c.split())
            bytes_c = len(c.encode("utf-8"))
            return f" {lines_c:>4}  {words_c:>4} {bytes_c:>5} {fpath}\n", False, "", new_dir

        elif root_cmd in ["apt", "apt-get"]:
            return (
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                "All packages are up to date.\n"
            ), False, "", new_dir

        elif root_cmd == "pip":
            return "Requirement already satisfied: pip in /usr/lib/python3/dist-packages\n", False, "", new_dir

        elif root_cmd == "top":
            up_secs = int(time.time() - self.boot_time)
            days = up_secs // 86400
            hours = (up_secs % 86400) // 3600
            mins = (up_secs % 3600) // 60
            now_t = datetime.datetime.now().strftime("%H:%M:%S")
            return (
                f"top - {now_t} up {days} days, {hours}:{mins:02d},  1 user,  load average: 0.08, 0.03, 0.01\n"
                "Tasks: 118 total,   1 running, 117 sleeping,   0 stopped,   0 zombie\n"
                "%Cpu(s):  1.2 us,  0.8 sy,  0.0 ni, 97.8 id,  0.1 wa,  0.0 hi,  0.1 si,  0.0 st\n"
                "MiB Mem :   7951.2 total,   4710.1 free,   1752.4 used,   1488.7 buff/cache\n"
                "MiB Swap:      0.0 total,      0.0 free,      0.0 used.   5980.2 avail Mem\n\n"
                "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
                "      1 root      20   0  168420  12480   8420 S   0.0   0.2   0:02.14 systemd\n"
                f"   1850 {user:<8}  20   0   14210   4820   3410 S   0.0   0.1   0:00.04 bash\n"
            ), False, "", new_dir

        else:
            return f"bash: {root_cmd}: command not found\n", False, "", new_dir

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
        self.server_socket.listen(25)
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    async def stop(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
