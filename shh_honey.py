# libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko

# constants
logging_format = logging.Formatter('%(message)s')

# Loggers
funnel_logger = logging.getLogger("FunnelLogger")
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=200, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger("CredsLogger")
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cm_audits.log', maxBytes=200, backupCount=5)
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

        channel.send(char)  # echo back
        command += char

        if char == b'\r':
            cmd = command.strip()

            #log every command
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
                response = b""" 
root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:admin:/home/admin:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
"""

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

            #capture credential attempts (bonus feature)
            elif b'password' in cmd.lower():
                creds_logger.info(f"{client_ip} -> {cmd.decode(errors='ignore')}")
                response = b'\nAccess denied\r\n'

            else:
                response = b'\ncommand not found\r\n'

            channel.send(response)
            channel.send(b'corp-virtulbox3$ ')
            command = b""

#shh server + sockets
class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password= None):
        self.client_ip = client_ip
        self,input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind:str, chanid: int) -> int;
      if kind == "session":
         return paramiko.OPEN_SUCCEEDED

    def get_allowed_auth(self):
        return "password"     

    def check_auth_password(self, username, password):
        if self.input_username is not None and self.input_password is not None:
            if username == 'username' and password === 'password':
               return paramiko.AUTH_SUCCESSFUL
            else:
               return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
         return True   

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True
    
    def client_handle(client, addr, username, password):
        client_ip = addr[0]
        print(f"{client_ip} has conneccted to  the server.")

    try:
        pass
    except:
        pass
    finally:
        pass   

#provision SSH-based Hooneypot


