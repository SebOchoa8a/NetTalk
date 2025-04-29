import os
import socket
import threading
import json
import random

from communicator import Communicator
from core.crypto import load_private_key, decrypt_aes_key_with_rsa, decrypt_message_with_aes
from friend_request import handle_friend_request
from key_manager import KeyManager

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

class UserSession:
    def __init__(self, nickname, on_message_callback=None):
        self.nickname = nickname
        self.listen_port = random.randint(6000, 7000)  # Random open port for this user
        self.key_manager = KeyManager(nickname)
        self.private_key = load_private_key(nickname)
        self.on_message_callback = on_message_callback 

        # Load IP and port info for this user
        registry_path = os.path.join(os.path.dirname(__file__), "peer_registery.json")
        if os.path.exists(registry_path):
            with open(registry_path, "r") as f:
                registry = json.load(f)
                user_info = registry.get(nickname, {})
                self.local_ip = get_local_ip()
                self.listen_port = user_info.get("listen_port", self.listen_port)
                print(f"[DEBUG] {nickname} will listen on {self.local_ip}:{self.listen_port}")
        else:
            self.local_ip = get_local_ip()

        self.comm = None

    def start(self):
        self._start_tcp_server()

    def _start_tcp_server(self):
        self.comm = Communicator(self.listen_port, on_receive_callback=self._handle_message)
        self.comm.start_listener()
        print(f"[SESSION] Started TCP server on {self.local_ip}:{self.listen_port}")

    def _handle_message(self, data):
        try:
            # Try to decode as JSON first (friend request)
            try:
                message_obj = json.loads(data.decode())
                if message_obj.get("type") == "FRIEND_REQUEST":
                    print(f"[SESSION] Received friend request from {message_obj.get('from')}")
                    handle_friend_request(message_obj, self.key_manager, parent_widget=None, chat_gui=None)
                    return
            except Exception:
                # Not JSON - it's probably an encrypted chat message
                pass

            # Otherwise, handle as encrypted message
            enc_key_len = int.from_bytes(data[:4], byteorder='big')
            encrypted_key = data[4:4+enc_key_len]
            encrypted_message = data[4+enc_key_len:]

            aes_key = decrypt_aes_key_with_rsa(self.private_key, encrypted_key)
            message = decrypt_message_with_aes(aes_key, encrypted_message)

            print(f"[SESSION] Decrypted incoming message: {message}")

            if self.on_message_callback:
                self.on_message_callback(message)

        except Exception as e:
            print(f"[SESSION] Failed to decrypt/process incoming message: {e}")


    def send_friend_request(self, target_ip, friend_nickname, friend_pubkey):
        known_peers = {}
        if os.path.exists(PEER_REGISTRY):
            with open(PEER_REGISTRY, "r") as f:
                known_peers = json.load(f)

        packet = json.dumps({
            "type": "FRIEND_REQUEST",
            "from": self.nickname,
            "pubkey": friend_pubkey,
            "known_peers": known_peers  # NEW
        }).encode()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_ip, 6000))
                s.sendall(packet)
            print(f"[SESSION] Sent friend request to {friend_nickname} at {target_ip}")
        except Exception as e:
            print(f"[SESSION] Failed to send friend request: {e}")


    def send_raw_packet(self, data: bytes, peer_ip: str, peer_port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, peer_port))
                s.sendall(data)
            print(f"[SESSION] Sent packet to {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"[SESSION] Failed to send packet: {e}")
