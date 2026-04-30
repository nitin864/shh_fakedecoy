import logging
import socket
import threading
import datetime
import os
from logging.handlers import RotatingFileHandler
from collections import defaultdict

import paramiko

SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 RedHat-1.el9"
LOG_FORMAT = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
MAX_FAILED_ATTEMPTS = 5
RECV_TIMEOUT = 120

host_key = paramiko.RSAKey(filename='server.key')

failed_attempts = defaultdict(int)
blocked_ips = set()
lock = threading.Lock()


def _make_logger(name, filename, max_bytes=1_000_000, backup_count=10):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(filename, maxBytes=max_bytes, backupCount=backup_count)
    handler.setFormatter(LOG_FORMAT)
    logger.addHandler(handler)
    return logger


funnel_logger = _make_logger("FunnelLogger", "audits.log")
creds_logger  = _make_logger("CredsLogger",  "cm_audits.log")


FAKE_FS = {
    "/": ["bin", "etc", "home", "var", "tmp", "root", "usr"],
    "/usr": ["local", "bin", "lib"],
    "/usr/local": ["bin", "etc", "home", "var", "tmp", "root"],
    "/home": ["admin"],
    "/home/admin": [".bashrc", ".bash_history", "notes.txt"],
    "/root": [".secrets", "backup.sh"],
    "/etc": ["passwd", "hosts", "hostname", "shadow"],
}

FAKE_FILES = {
    "/etc/passwd":   "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "/etc/hostname": "corp-virtulbox3\n",
    "/etc/hosts":    "127.0.0.1   localhost\n127.0.1.1   corp-virtulbox3\n",
    "/etc/shadow":   "Permission denied\n",
    "/root/.secrets":       "Permission denied\n",
    "/home/admin/notes.txt": "TODO: rotate credentials before Q3 audit\n",
}


def emulated_shell(channel, client_ip):
    cwd = "/usr/local"
    hostname = "corp-virtulbox3"
    user = "admin"

    def prompt():
        return f"{user}@{hostname}:{cwd}$ ".encode()

    channel.settimeout(RECV_TIMEOUT)
    channel.send(b"\r\n")
    channel.send(prompt())
    command = b""

    while True:
        try:
            char = channel.recv(1)
        except socket.timeout:
            channel.send(b"\r\nSession timed out.\r\n")
            channel.close()
            break

        if not char:
            channel.close()
            break

        if char == b"\x7f":
            if command:
                command = command[:-1]
                channel.send(b"\b \b")
            continue

        if char == b"\x03":
            channel.send(b"^C\r\n")
            channel.send(prompt())
            command = b""
            continue

        channel.send(char)
        command += char

        if char == b"\r":
            cmd_str = command.strip().decode(errors="ignore")
            parts   = cmd_str.split()
            verb    = parts[0] if parts else ""

            funnel_logger.info(f"{client_ip} | cmd | {cmd_str}")
            channel.send(b"\n")

            if not cmd_str:
                channel.send(prompt())
                command = b""
                continue

            if cmd_str == "exit" or cmd_str == "logout":
                channel.send(b"logout\r\n")
                channel.close()
                break

            elif verb == "pwd":
                channel.send(f"{cwd}\r\n".encode())

            elif verb == "ls":
                target = cwd
                if len(parts) > 1:
                    arg = parts[1]
                    target = arg if arg.startswith("/") else os.path.normpath(f"{cwd}/{arg}")
                entries = FAKE_FS.get(target)
                if entries is None:
                    channel.send(f"ls: cannot access '{target}': No such file or directory\r\n".encode())
                else:
                    channel.send(("  ".join(entries) + "\r\n").encode())

            elif verb == "cd":
                dest = parts[1] if len(parts) > 1 else "/home/admin"
                if dest == "..":
                    cwd = "/" if cwd == "/" else os.path.dirname(cwd)
                elif dest.startswith("/"):
                    cwd = dest if dest in FAKE_FS else cwd
                else:
                    candidate = os.path.normpath(f"{cwd}/{dest}")
                    cwd = candidate if candidate in FAKE_FS else cwd

            elif verb == "whoami":
                channel.send(b"admin\r\n")

            elif verb == "id":
                channel.send(b"uid=1000(admin) gid=1000(admin) groups=1000(admin)\r\n")

            elif verb == "uname":
                channel.send(b"Linux corp-virtulbox3 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 GNU/Linux\r\n")

            elif verb == "hostname":
                channel.send(b"corp-virtulbox3\r\n")

            elif verb == "uptime":
                channel.send(b" 14:32:01 up 42 days,  3:17,  1 user,  load average: 0.01, 0.03, 0.00\r\n")

            elif verb == "cat":
                if len(parts) < 2:
                    channel.send(b"cat: missing operand\r\n")
                else:
                    path = parts[1] if parts[1].startswith("/") else os.path.normpath(f"{cwd}/{parts[1]}")
                    content = FAKE_FILES.get(path)
                    if content is None:
                        channel.send(f"cat: {parts[1]}: No such file or directory\r\n".encode())
                    else:
                        channel.send(content.encode())

            elif verb == "echo":
                channel.send((" ".join(parts[1:]) + "\r\n").encode())

            elif verb in ("wget", "curl"):
                url = parts[1] if len(parts) > 1 else ""
                funnel_logger.info(f"{client_ip} | download_attempt | {url}")
                channel.send(b"Connecting... connected.\r\nHTTP request sent, awaiting response... 200 OK\r\nSaved.\r\n")

            elif verb in ("python", "python3"):
                channel.send(b"Python 3.8.10 (default, Nov 14 2022, 12:59:47)\r\n[GCC 9.4.0] on linux\r\nType 'help', 'copyright', 'credits' or 'license' for more information.\r\n>>> \r\n")

            elif verb in ("rm", "rmdir", "mkdir", "touch", "chmod", "chown"):
                pass

            elif verb == "ps":
                channel.send(b"  PID TTY          TIME CMD\r\n 1234 pts/0    00:00:00 bash\r\n 1391 pts/0    00:00:00 ps\r\n")

            elif verb == "env" or verb == "printenv":
                channel.send(b"HOME=/home/admin\r\nUSER=admin\r\nSHELL=/bin/bash\r\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n")

            elif verb == "history":
                channel.send(b"    1  ls\r\n    2  pwd\r\n    3  cat /etc/passwd\r\n    4  whoami\r\n")

            elif verb == "help":
                channel.send(b"GNU bash, type 'man' for more information.\r\nBuilt-in commands: cd, echo, exit, export, history, pwd, read, set, type\r\n")

            elif "password" in cmd_str.lower() or "passwd" in cmd_str.lower():
                creds_logger.info(f"{client_ip} | password_in_cmd | {cmd_str}")
                channel.send(b"passwd: Authentication token manipulation error\r\n")

            else:
                channel.send(f"{verb}: command not found\r\n".encode())

            channel.send(prompt())
            command = b""


class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f"{self.client_ip} | auth_attempt | user={username} pass={password}")
        creds_logger.info(f"{self.client_ip} | auth_attempt | user={username} pass={password}")

        with lock:
            if self.client_ip in blocked_ips:
                funnel_logger.info(f"{self.client_ip} | blocked")
                return paramiko.AUTH_FAILED

            if username == self.input_username and password == self.input_password:
                funnel_logger.info(f"{self.client_ip} | auth_success | user={username}")
                return paramiko.AUTH_SUCCESSFUL

            failed_attempts[self.client_ip] += 1
            if failed_attempts[self.client_ip] >= MAX_FAILED_ATTEMPTS:
                blocked_ips.add(self.client_ip)
                funnel_logger.info(f"{self.client_ip} | auto_blocked | too many failed attempts")

        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        funnel_logger.info(f"exec_request | {command.decode(errors='ignore')}")
        return True


def client_handle(client, addr, username, password):
    client_ip = addr[0]
    funnel_logger.info(f"{client_ip} | connected")
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] Connection from {client_ip}")

    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)

        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            funnel_logger.info(f"{client_ip} | no_channel_opened")
            return

        server.event.wait(10)
        channel.send(b"\r\nWelcome to corp-virtulbox3\r\n")
        channel.send(b"Last login: Mon Apr 14 09:12:44 2025 from 10.0.0.5\r\n")
        emulated_shell(channel, client_ip)

    except paramiko.SSHException as e:
        funnel_logger.info(f"{client_ip} | ssh_error | {e}")
    except Exception as e:
        funnel_logger.info(f"{client_ip} | error | {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        client.close()
        funnel_logger.info(f"{client_ip} | disconnected")


def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    print(f"[*] SSH Honeypot listening on {address}:{port}")

    while True:
        try:
            client, addr = socks.accept()
            with lock:
                if addr[0] in blocked_ips:
                    funnel_logger.info(f"{addr[0]} | rejected | ip blocked")
                    client.close()
                    continue

            t = threading.Thread(
                target=client_handle,
                args=(client, addr, username, password),
                daemon=True
            )
            t.start()
        except Exception as e:
            print(f"[!] Accept error: {e}")


if __name__ == "__main__":
    honeypot("0.0.0.0", 2222, "admin", "admin123")