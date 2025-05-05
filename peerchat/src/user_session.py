import threading
import socket
from core.crypto import (
    decrypt_aes_key_with_rsa, decrypt_message_with_aes
)
from dht_node import DHTNode

class UserSession:
    def __init__(self, nickname, ip, port, key_manager, on_message_callback=None, on_peer_discovered=None):
        self.nickname = nickname
        self.ip = ip
        self.port = port
        self.key_manager = key_manager
        self.on_message_callback = on_message_callback
        self.active_peer = None

        self.private_key = self.key_manager._load_private_key()

        #Initialize DHTNode here
        self.dht = DHTNode(
            username=nickname,
            ip=ip,
            port=port,
            on_peer_discovered=on_peer_discovered
        )

        if self.nickname == "alice":
            self.dht.send_hello("bob", "192.168.1.198", 8178)
        elif self.nickname == "bob":
            self.dht.send_hello("alice", "192.168.1.160", 8257)

        self.start_tcp_server()

    def start_tcp_server(self):
        def server_thread():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.ip, self.port))
            server.listen()
            print(f"[TCP] Listening on {self.ip}:{self.port}")

            while True:
                conn, addr = server.accept()
                threading.Thread(target=self.handle_tcp_connection, args=(conn, addr), daemon=True).start()

        threading.Thread(target=server_thread, daemon=True).start()

    def handle_tcp_connection(self, conn, addr):
        try:
            data = conn.recv(4096)
            if data.startswith(b"[HANDSHAKE]"):
                message = data.decode()
                print(f"[TCP] Received: {message}")

            elif data.startswith(b"[ACCEPT]"):
                message = data.decode()
                print(f"[TCP] Received: {message}")
                if self.on_message_callback:
                    self.on_message_callback(f"[System] {message}")

            else:
                enc_key_len = int.from_bytes(data[:4], byteorder='big')
                encrypted_key = data[4:4+enc_key_len]
                encrypted_message = data[4+enc_key_len:]

                aes_key = decrypt_aes_key_with_rsa(self.private_key, encrypted_key)
                decrypted_msg = decrypt_message_with_aes(aes_key, encrypted_message)

                print(f"[TCP] Decrypted message: {decrypted_msg}")
                if self.on_message_callback:
                    self.on_message_callback(decrypted_msg)

        except Exception as e:
            print(f"[ERROR] Failed to handle TCP message: {e}")
        finally:
            conn.close()

    def send_tcp_message(self, ip, port, msg_bytes):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                s.sendall(msg_bytes)
        except Exception as e:
            print(f"[ERROR] Failed to send TCP message: {e}")

    def send_encrypted_message(self, packet, ip, port):
        self.send_tcp_message(ip, port + 1000, packet)
