import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading

# constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 RedHat-1.el9"

host_key = paramiko.RSAKey(filename='server.key')

# Loggers
funnel_logger = logging.getLogger("FunnelLogger")
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger("CredsLogger")
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cm_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


# emulated shell
def emulated_shell(channel, client_ip):
    channel.send(b'corp-virtulbox3$ ')
    command = b""

    while True:
        char = channel.recv(1)

        if not char:
            channel.close()
            break

        channel.send(char)
        command += char

        if char == b'\r':
            cmd = command.strip()
            funnel_logger.info(f"{client_ip} -> {cmd.decode(errors='ignore')}")

            response = b''

            if cmd == b'exit':
                response = b'\nGoodbye!\n'
                channel.send(response)
                channel.close()
                break

            elif cmd == b'pwd':
                response = b'\n/usr/local/\r\n'

            elif cmd == b'ls':
                response = b'\nbin  etc  home  var  tmp  root\r\n'

            elif cmd == b'whoami':
                response = b'\nadmin\r\n'

            elif cmd == b'uname -a':
                response = b'\nLinux honeypot 5.4.0-42-generic x86_64 GNU/Linux\r\n'

            elif cmd == b'id':
                response = b'\nuid=1000(admin) gid=1000(admin) groups=1000(admin)\r\n'

            elif cmd == b'cat /etc/passwd':
                response = b'\nroot:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n'

            elif cmd == b'ls /root':
                response = b'\n.secrets  backup.sh\r\n'

            elif cmd == b'cat /root/.secrets':
                response = b'\nPermission denied\r\n'

            elif cmd.startswith(b'cd'):
                response = b''

            elif cmd.startswith(b'wget') or cmd.startswith(b'curl'):
                response = b'\nDownloading...\r\nSaved.\r\n'

            elif cmd.startswith(b'rm'):
                response = b''

            elif cmd.startswith(b'python'):
                response = b'\nPython 3.8.10\r\n>>> \r\n'

            elif cmd == b'help':
                response = b'\nAvailable commands: ls, pwd, whoami, uname, cat, exit\r\n'

            elif b'password' in cmd.lower():
                creds_logger.info(f"{client_ip} -> {cmd.decode(errors='ignore')}")
                response = b'\nAccess denied\r\n'

            else:
                response = b'\ncommand not found\r\n'

            channel.send(response)
            channel.send(b'corp-virtulbox3$ ')
            command = b""


# SSH Server class
class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
 
        funnel_logger.info(f"{self.client_ip} -> username: {username}  password: {password}")
        creds_logger.info(f"{self.client_ip} -> username: {username}  password: {password}")
        if username == self.input_username and password == self.input_password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True


def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        # FIX: host_key is already an RSAKey object, don't wrap it again
        transport.add_server_key(host_key)

        transport.start_server(server=server)

        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened.")
            return

        channel.send(b"Welcome to corp-virtulbox3\r\n\r\n")
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print(f"Client handle error: {error}")

    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
        client.close()


def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)

    # FIX: print AFTER listen, not inside the loop
    print(f"SSH Honeypot listening on {address}:{port}")

    while True:
        try:
            # FIX: socks.accept() not socket.accept()
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(
                target=client_handle, args=(client, addr, username, password)
            )
            ssh_honeypot_thread.start()
        except Exception as error:
            print(f"Honeypot error: {error}")


honeypot('0.0.0.0', 2222, 'username', 'password')