import socket
import subprocess
import threading
import time

class Communicator:
    def __init__(self, my_port, peer_ip, peer_port, ssh_user=None, ssh_host=None, use_ssh=False):
        self.my_port = my_port
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.use_ssh = use_ssh
        self.ssh_user = ssh_user
        self.ssh_host = ssh_host
        self.ssh_proc = None

    def start_ssh_tunnel(self):
        if not self.use_ssh:
            return

        ssh_command = [
            "ssh",
            "-N",  # No remote command
            "-L", f"{self.peer_port}:localhost:{self.peer_port}",
            f"{self.ssh_user}@{self.ssh_host}"
        ]
        self.ssh_proc = subprocess.Popen(ssh_command)
        print(f"[COMM] SSH Tunnel started: {self.peer_port} -> {self.ssh_host}:{self.peer_port}")
        time.sleep(2)  # Give tunnel time to initialize

    def stop_ssh_tunnel(self):
        if self.ssh_proc:
            self.ssh_proc.terminate()
            print("[COMM] SSH Tunnel closed")

    def start_listener(self, on_message_callback):
        def listen():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", self.my_port))
                s.listen(1)
                print(f"[COMM] Listening on port {self.my_port}...")

                while True:
                    conn, addr = s.accept()
                    with conn:
                        data = conn.recv(1024).decode()
                        if data:
                            print(f"[COMM] Message from {addr}: {data}")
                            on_message_callback(data)
        thread = threading.Thread(target=listen, daemon=True)
        thread.start()

    def send_message(self, message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.peer_ip, self.peer_port))
                s.sendall(message.encode())
                print(f"[COMM] Sent message to {self.peer_ip}:{self.peer_port}")
        except Exception as e:
            print(f"[COMM] Could not send message: {e}")
