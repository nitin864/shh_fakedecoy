"""
SSH Honeypot – Enhanced
Features added:
  • GeoIP lookup (ip-api.com, no key required)
  • Per-session command transcript saved to sessions/
  • Tarpit mode: slow down blocked IPs instead of hard-rejecting
  • More realistic shell (ifconfig, netstat, df, free, crontab, sudo, su, find, grep, unzip, tar, vim/nano)
  • Decoy /proc files and a fake crontab
  • SFTP stub (logs upload/download attempts)
  • JSON structured log alongside plain-text log
  • Graceful shutdown on SIGINT / SIGTERM
  • CLI argument parsing (argparse) – no hard-coded creds
  • Auto-rotate IP block list (blocks expire after BLOCK_TTL seconds)
"""

import argparse
import datetime
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import urllib.request
from collections import defaultdict
from logging.handlers import RotatingFileHandler
from pathlib import Path

import paramiko

# ──────────────────────────── constants ────────────────────────────

SSH_BANNER        = "SSH-2.0-OpenSSH_8.9p1 RedHat-1.el9"
MAX_FAILED        = 5
RECV_TIMEOUT      = 120
BLOCK_TTL         = 3600          # seconds before a block expires
TARPIT_DELAY      = 5             # seconds to sleep before closing a blocked IP
SESSIONS_DIR      = Path("sessions")
LOG_FORMAT        = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# ──────────────────────────── logging ──────────────────────────────

def _make_logger(name, filename, max_bytes=2_000_000, backup_count=10):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    h = RotatingFileHandler(filename, maxBytes=max_bytes, backupCount=backup_count)
    h.setFormatter(LOG_FORMAT)
    logger.addHandler(h)
    return logger

funnel_logger = _make_logger("FunnelLogger", "audits.log")
creds_logger  = _make_logger("CredsLogger",  "cm_audits.log")

JSON_LOG = Path("events.json")          # newline-delimited JSON

def jlog(event: dict):
    """Append a structured JSON event."""
    event.setdefault("ts", datetime.datetime.utcnow().isoformat())
    with JSON_LOG.open("a") as f:
        f.write(json.dumps(event) + "\n")

# ──────────────────────────── host key ─────────────────────────────

KEY_FILE = "server.key"
if not Path(KEY_FILE).exists():
    print("[*] Generating RSA host key …")
    paramiko.RSAKey.generate(2048).write_private_key_file(KEY_FILE)

host_key = paramiko.RSAKey(filename=KEY_FILE)

# ──────────────────────────── state ────────────────────────────────

failed_attempts: defaultdict[str, int] = defaultdict(int)
blocked_at:      dict[str, float]      = {}   # ip -> epoch time of block
lock = threading.Lock()
_shutdown = threading.Event()

SESSIONS_DIR.mkdir(exist_ok=True)

# ──────────────────────────── GeoIP ────────────────────────────────

_geo_cache: dict[str, dict] = {}
_geo_lock  = threading.Lock()

def geoip(ip: str) -> dict:
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp", timeout=3) as r:
            data = json.loads(r.read())
    except Exception:
        data = {}
    with _geo_lock:
        _geo_cache[ip] = data
    return data

# ──────────────────────────── fake filesystem ──────────────────────

FAKE_FS = {
    "/":                    ["bin", "dev", "etc", "home", "lib", "proc", "root", "tmp", "usr", "var"],
    "/usr":                 ["local", "bin", "lib", "share"],
    "/usr/local":           ["bin", "etc", "lib", "share"],
    "/home":                ["admin"],
    "/home/admin":          [".bashrc", ".bash_history", ".ssh", "notes.txt", "backup.tar.gz"],
    "/home/admin/.ssh":     ["authorized_keys", "known_hosts"],
    "/root":                [".secrets", ".bash_history", "backup.sh"],
    "/etc":                 ["cron.d", "crontab", "hosts", "hostname", "issue", "motd",
                             "os-release", "passwd", "resolv.conf", "shadow", "ssh"],
    "/etc/ssh":             ["sshd_config", "ssh_host_rsa_key"],
    "/etc/cron.d":          ["backup", "cleanup"],
    "/var":                 ["log", "www", "spool", "tmp"],
    "/var/log":             ["auth.log", "syslog", "nginx"],
    "/tmp":                 [],
    "/proc":                ["cpuinfo", "meminfo", "version", "net"],
    "/proc/net":            ["tcp", "if_inet6"],
}

FAKE_FILES = {
    "/etc/passwd":
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",

    "/etc/hostname":  "corp-virtulbox3\n",
    "/etc/hosts":     "127.0.0.1   localhost\n127.0.1.1   corp-virtulbox3\n",
    "/etc/shadow":    "Permission denied\n",
    "/etc/issue":     "Ubuntu 20.04.6 LTS \\n \\l\n",
    "/etc/motd":      "Welcome to corp-virtulbox3. Unauthorized access is prohibited.\n",
    "/etc/os-release":
        'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nID_LIKE=debian\n'
        'PRETTY_NAME="Ubuntu 20.04.6 LTS"\nVERSION_ID="20.04"\n',
    "/etc/resolv.conf": "nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
    "/etc/ssh/sshd_config":
        "Port 22\nPermitRootLogin no\nPasswordAuthentication yes\nX11Forwarding no\n",

    "/etc/crontab":
        "# /etc/crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        "0 */6 * * * root /root/backup.sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",

    "/root/.secrets":              "Permission denied\n",
    "/home/admin/notes.txt":       "TODO: rotate credentials before Q3 audit\ndb_pass=Ch@ng3M3!\n",
    "/home/admin/backup.tar.gz":   "<binary data>\n",
    "/home/admin/.bashrc":
        "# .bashrc\nexport PATH=$PATH:/usr/local/bin\nalias ll='ls -la'\n",
    "/home/admin/.bash_history":
        "ls\npwd\ncat /etc/passwd\nsudo su\nwhoami\ncat /home/admin/notes.txt\n",
    "/home/admin/.ssh/authorized_keys": "",
    "/home/admin/.ssh/known_hosts":     "",

    "/proc/cpuinfo":
        "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\ncpu MHz\t\t: 2400.000\n"
        "cache size\t: 30720 KB\nbogomips\t: 4800.00\n",
    "/proc/meminfo":
        "MemTotal:        2048000 kB\nMemFree:          512000 kB\nMemAvailable:     900000 kB\n"
        "Buffers:          64000 kB\nCached:           300000 kB\nSwapTotal:       1048576 kB\nSwapFree:        1048576 kB\n",
    "/proc/version":
        "Linux version 5.4.0-42-generic (buildd@lgw01-amd64-038) "
        "(gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) "
        "#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020\n",

    "/var/log/auth.log":
        "Apr 14 09:10:03 corp-virtulbox3 sshd[1234]: Accepted password for admin from 10.0.0.5 port 52341 ssh2\n"
        "Apr 14 09:10:03 corp-virtulbox3 sshd[1234]: pam_unix(sshd:session): session opened for user admin\n",
    "/var/log/syslog":
        "Apr 14 09:00:01 corp-virtulbox3 cron[987]: (root) CMD (/root/backup.sh)\n"
        "Apr 14 09:10:03 corp-virtulbox3 sshd[1234]: Server listening on 0.0.0.0 port 22.\n",
}

# ──────────────────────────── fake crontab ─────────────────────────

FAKE_CRONTAB = (
    "# user crontab\n"
    "30 3 * * * /home/admin/cleanup.sh\n"
    "0 */12 * * * /home/admin/sync_db.py\n"
)

# ──────────────────────────── session transcript ───────────────────

class SessionTranscript:
    def __init__(self, client_ip: str):
        ts  = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        safe_ip = client_ip.replace(":", "_")
        self.path = SESSIONS_DIR / f"{safe_ip}_{ts}.txt"
        self._f   = self.path.open("w", buffering=1)
        self._f.write(f"# Session: {client_ip}  started={ts}\n")

    def write(self, line: str):
        self._f.write(line + "\n")

    def close(self):
        self._f.close()

# ──────────────────────────── SFTP server stub ─────────────────────

class SFTPStub(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        self._ip = getattr(server, "client_ip", "?")
        super().__init__(server, *args, **kwargs)

    def _log(self, action, path):
        funnel_logger.info(f"{self._ip} | sftp_{action} | {path}")
        jlog({"event": f"sftp_{action}", "ip": self._ip, "path": path})

    def open(self, path, flags, attr):
        self._log("open", path)
        return paramiko.SFTP_OP_UNSUPPORTED

    def stat(self, path):
        self._log("stat", path)
        return paramiko.SFTP_NO_SUCH_FILE

    def lstat(self, path):
        return self.stat(path)

    def list_folder(self, path):
        self._log("list_folder", path)
        entries = FAKE_FS.get(path, [])
        return [paramiko.SFTPAttributes() for _ in entries]

    def remove(self, path):
        self._log("remove", path)
        return paramiko.SFTP_OP_UNSUPPORTED

    def rename(self, oldpath, newpath):
        self._log("rename", f"{oldpath} -> {newpath}")
        return paramiko.SFTP_OP_UNSUPPORTED

    def mkdir(self, path, attr):
        self._log("mkdir", path)
        return paramiko.SFTP_OP_UNSUPPORTED

    def rmdir(self, path):
        self._log("rmdir", path)
        return paramiko.SFTP_OP_UNSUPPORTED

# ──────────────────────────── emulated shell ───────────────────────

def emulated_shell(channel, client_ip: str, transcript: SessionTranscript):
    cwd      = "/home/admin"
    hostname = "corp-virtulbox3"
    user     = "admin"
    env      = {
        "HOME": "/home/admin", "USER": "admin", "SHELL": "/bin/bash",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM": "xterm-256color", "LANG": "en_US.UTF-8",
    }

    def prompt():
        return f"{user}@{hostname}:{cwd}$ ".encode()

    def send(text: str | bytes):
        if isinstance(text, str):
            text = text.encode()
        channel.send(text)

    def resolve(path: str) -> str:
        if path.startswith("/"):
            return os.path.normpath(path)
        return os.path.normpath(f"{cwd}/{path}")

    channel.settimeout(RECV_TIMEOUT)
    send(b"\r\n")
    send(prompt())
    command = b""

    while True:
        try:
            char = channel.recv(1)
        except socket.timeout:
            send(b"\r\nSession timed out.\r\n")
            channel.close()
            break

        if not char:
            channel.close()
            break

        # backspace
        if char == b"\x7f":
            if command:
                command = command[:-1]
                send(b"\b \b")
            continue

        # Ctrl-C
        if char == b"\x03":
            send(b"^C\r\n")
            send(prompt())
            command = b""
            continue

        # Ctrl-D (EOF)
        if char == b"\x04":
            send(b"logout\r\n")
            channel.close()
            break

        send(char)
        command += char

        if char != b"\r":
            continue

        # ── process command ─────────────────────────────────────────
        cmd_str = command.strip().decode(errors="ignore")
        # handle chained commands (;  &&  ||) naively – just run each
        sub_cmds = [c.strip() for c in cmd_str.replace("&&", ";").replace("||", ";").split(";")]

        send(b"\n")
        transcript.write(f"$ {cmd_str}")
        funnel_logger.info(f"{client_ip} | cmd | {cmd_str}")
        jlog({"event": "cmd", "ip": client_ip, "cmd": cmd_str})

        for sub in sub_cmds:
            if not sub:
                continue
            parts = sub.split()
            verb  = parts[0]

            # ── detect credential patterns anywhere in command ──────
            low = sub.lower()
            if any(k in low for k in ("password", "passwd", "secret", "token", "apikey", "api_key")):
                creds_logger.info(f"{client_ip} | sensitive_cmd | {sub}")
                jlog({"event": "sensitive_cmd", "ip": client_ip, "cmd": sub})

            # ── download attempts ───────────────────────────────────
            if verb in ("wget", "curl"):
                url = parts[1] if len(parts) > 1 else ""
                funnel_logger.info(f"{client_ip} | download_attempt | {url}")
                jlog({"event": "download_attempt", "ip": client_ip, "url": url})
                if verb == "wget":
                    send(f"--{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n"
                         "Resolving host... connected.\r\n"
                         "HTTP request sent, awaiting response... 200 OK\r\n"
                         "Length: 4096 (4.0K) [application/octet-stream]\r\nSaved: 'file'\r\n")
                else:
                    send(b"  % Total    % Received  Xferd  Average Speed\r\n"
                         b"100  4096  100  4096    0     0   8192      0 --:--:-- --:--:-- --:--:--  8192\r\n")
                continue

            # ── builtins ────────────────────────────────────────────

            if verb in ("exit", "logout"):
                send(b"logout\r\n")
                channel.close()
                return

            elif verb == "pwd":
                send(f"{cwd}\r\n")

            elif verb == "cd":
                dest = parts[1] if len(parts) > 1 else "/home/admin"
                if dest == "-":
                    pass   # no OLDPWD tracking
                elif dest == "..":
                    cwd = "/" if cwd == "/" else os.path.dirname(cwd)
                elif dest == "~" or dest == "":
                    cwd = "/home/admin"
                else:
                    candidate = resolve(dest)
                    if candidate in FAKE_FS:
                        cwd = candidate
                    else:
                        send(f"bash: cd: {dest}: No such file or directory\r\n")

            elif verb == "ls":
                flags  = [p for p in parts[1:] if p.startswith("-")]
                args   = [p for p in parts[1:] if not p.startswith("-")]
                target = resolve(args[0]) if args else cwd
                entries = FAKE_FS.get(target)
                if entries is None:
                    send(f"ls: cannot access '{target}': No such file or directory\r\n")
                elif "-l" in " ".join(flags):
                    send(f"total {len(entries) * 4}\r\n")
                    for e in entries:
                        p = f"{target}/{e}".replace("//", "/")
                        is_dir = p in FAKE_FS
                        perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                        send(f"{perm}  1 admin admin  4096 Apr 14 09:12 {e}\r\n")
                else:
                    send("  ".join(entries) + "\r\n")

            elif verb == "cat":
                if len(parts) < 2:
                    send(b"cat: missing operand\r\n")
                else:
                    for target_arg in parts[1:]:
                        path    = resolve(target_arg)
                        content = FAKE_FILES.get(path)
                        if content is None:
                            send(f"cat: {target_arg}: No such file or directory\r\n")
                        else:
                            send(content.replace("\n", "\r\n"))

            elif verb == "echo":
                out = " ".join(parts[1:])
                # simple $VAR substitution
                for k, v in env.items():
                    out = out.replace(f"${k}", v)
                send(out + "\r\n")

            elif verb == "whoami":
                send(b"admin\r\n")

            elif verb == "id":
                send(b"uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),24(cdrom),27(sudo)\r\n")

            elif verb == "uname":
                if "-a" in parts or "--all" in parts:
                    send(b"Linux corp-virtulbox3 5.4.0-42-generic #46-Ubuntu SMP "
                         b"Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                elif "-r" in parts:
                    send(b"5.4.0-42-generic\r\n")
                else:
                    send(b"Linux\r\n")

            elif verb == "hostname":
                send(b"corp-virtulbox3\r\n")

            elif verb == "uptime":
                send(b" 14:32:01 up 42 days,  3:17,  1 user,  load average: 0.01, 0.03, 0.00\r\n")

            elif verb == "date":
                send(datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n")

            elif verb == "ps":
                send(b"  PID TTY          TIME CMD\r\n"
                     b"    1 ?        00:00:02 systemd\r\n"
                     b" 1234 pts/0    00:00:00 bash\r\n"
                     b" 1391 pts/0    00:00:00 ps\r\n")

            elif verb == "top":
                send(b"top - 14:32:01 up 42 days,  3:17,  1 user,  load average: 0.01, 0.03, 0.00\r\n"
                     b"Tasks:  87 total,   1 running,  86 sleeping,   0 stopped,   0 zombie\r\n"
                     b"%Cpu(s):  0.3 us,  0.1 sy,  0.0 ni, 99.5 id,  0.1 wa,  0.0 hi,  0.0 si\r\n"
                     b"MiB Mem:   2000.0 total,    500.1 free,    700.0 used,    800.0 buff/cache\r\n\r\n")

            elif verb in ("env", "printenv"):
                for k, v in env.items():
                    send(f"{k}={v}\r\n")

            elif verb == "export":
                if len(parts) > 1 and "=" in parts[1]:
                    k, v = parts[1].split("=", 1)
                    env[k] = v

            elif verb == "history":
                hist = [
                    "ls", "pwd", "cat /etc/passwd", "cat /home/admin/notes.txt",
                    "whoami", "id", "sudo su", "uname -a", "ps aux",
                ]
                for i, h in enumerate(hist, 1):
                    send(f"  {i:3d}  {h}\r\n")

            elif verb == "ifconfig" or (verb == "ip" and len(parts) > 1 and parts[1] in ("a", "addr", "address")):
                send(b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                     b"        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255\r\n"
                     b"        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>\r\n"
                     b"        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\r\n\r\n"
                     b"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
                     b"        inet 127.0.0.1  netmask 255.0.0.0\r\n")

            elif verb == "netstat" or (verb == "ss"):
                send(b"Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
                     b"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
                     b"tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n"
                     b"tcp        0      0 10.0.0.42:22            10.0.0.5:52341          ESTABLISHED\r\n")

            elif verb == "df":
                send(b"Filesystem      1K-blocks    Used Available Use% Mounted on\r\n"
                     b"overlay          51473908 8234512  40612936  17% /\r\n"
                     b"tmpfs               65536       0     65536   0% /dev\r\n"
                     b"/dev/xvda1       51473908 8234512  40612936  17% /etc/hosts\r\n")

            elif verb == "free":
                send(b"              total        used        free      shared  buff/cache   available\r\n"
                     b"Mem:        2048000      700000      512000       12000      836000      900000\r\n"
                     b"Swap:       1048576           0     1048576\r\n")

            elif verb == "crontab":
                if "-l" in parts:
                    send(FAKE_CRONTAB)
                else:
                    send(b"crontab: no changes made to crontab\r\n")

            elif verb in ("sudo", "su"):
                funnel_logger.info(f"{client_ip} | privilege_escalation_attempt | {sub}")
                jlog({"event": "priv_esc", "ip": client_ip, "cmd": sub})
     