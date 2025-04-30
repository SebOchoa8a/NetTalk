import os
import socket
import threading
import json

from communicator import Communicator
from core.crypto import load_private_key, decrypt_aes_key_with_rsa, decrypt_message_with_aes
from friend_request import handle_friend_request
from key_manager import KeyManager
from dht_node import DHTNode

class UserSession:
    def __init__(self, nickname, on_message_callback=None, on_friend_update=None):
        self.nickname = nickname
        self.listen_port = 6001 if nickname == "alice" else 6000  # Example: Static ports
        self.key_manager = KeyManager(nickname)
        self.private_key = load_private_key(nickname)
        self.on_message_callback = on_message_callback
        self.on_friend_update = on_friend_update

        self.comm = Communicator(self.listen_port, self._handle_message)

        #NEW: Start DHT Node
        self.dht = DHTNode(nickname, self.get_local_ip(), 8000 + (0 if nickname == "alice" else 1))

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def start(self):
        self.comm.start_listener()

    def _handle_message(self, data):
        try:
            enc_key_len = int.from_bytes(data[:4], byteorder='big')
            encrypted_key = data[4:4+enc_key_len]
            encrypted_message = data[4+enc_key_len:]

            aes_key = decrypt_aes_key_with_rsa(self.private_key, encrypted_key)
            message = decrypt_message_with_aes(aes_key, encrypted_message)

            print(f"[SESSION] Decrypted incoming message: {message}")

            # If it's a friend request format
            if message.startswith("{") and "FRIEND_REQUEST" in message:
                friend_data = json.loads(message)
                handle_friend_request(friend_data, self.key_manager, dht=self.dht)

                # refresh friends GUI
                if self.on_friend_update:
                    self.on_friend_update()

            else:
                if self.on_message_callback:
                    self.on_message_callback(message)

        except Exception as e:
            print(f"[SESSION] Failed to decrypt/process incoming message: {e}")

    def send_friend_request(self, target_ip, target_name, public_key_pem):
        """Send a friend request to another peer."""
        packet = json.dumps({
            "type": "FRIEND_REQUEST",
            "from": self.nickname,
            "pubkey": friend_pubkey,
            "dht_ip": get_local_ip(),
            "dht_port": self.dht_port  # Add this to UserSession if needed
        }).encode()

        try:
            self.comm.send_message(packet, target_ip, 6000)  # Assuming friends listen on 6000
            print(f"[SESSION] Sent friend request to {target_name} at {target_ip}")
        except Exception as e:
            print(f"[SESSION] Failed to send friend request: {e}")

    def send_raw_packet(self, data: bytes, peer_ip: str, peer_port: int):
        try:
            self.comm.send_message(data, peer_ip, peer_port)
            print(f"[SESSION] Sent packet to {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"[SESSION] Failed to send packet: {e}")
