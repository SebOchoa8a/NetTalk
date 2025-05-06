import os
import json
import socket
import threading
import random

from communicator import Communicator
from core.crypto import load_private_key, decrypt_aes_key_with_rsa, decrypt_message_with_aes
from friend_request import handle_friend_request
from key_manager import KeyManager

KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "keys"))
FRIENDS_DIR = os.path.join(os.path.dirname(__file__), "friends")
FRIENDS_FILE = os.path.join(FRIENDS_DIR, "friends.json")
PEER_REGISTRY = os.path.join(os.path.dirname(__file__), "peer_registry.json")


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
    def __init__(self, nickname, on_message_callback=None, on_friend_update=None, gui_ref=None):
        self.nickname = nickname
        if nickname == "alice":
            self.listen_port = 6000
        elif nickname == "bob":
            self.listen_port = 6001
        else:
            self.listen_port = random.randint(6002, 7000)
        self.key_manager = KeyManager(nickname)
        self.private_key = load_private_key(nickname)
        self.on_message_callback = on_message_callback 
        self.on_friend_update = on_friend_update

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

    def _handle_message(self, data, addr=None):
        try:
            # First, try to decode as JSON (for friend requests)
            decoded = data.decode('utf-8')
            msg = json.loads(decoded)

            if msg.get("type") == "FRIEND_REQUEST":
                print(f"[SESSION] Received friend request from {msg['from']}")
                handle_friend_request(msg, self.key_manager, self.on_friend_update)
                return  # Successfully handled friend request!

        except (UnicodeDecodeError, json.JSONDecodeError):
            # Not JSON — may be chat or control message
            try:
                decoded = data.decode('utf-8')
                if decoded.startswith("[CHAT_REQUEST]") or decoded.startswith("[CHAT_ACCEPTED]") or decoded.startswith("[CHAT_DECLINED]"):
                    parts = decoded.split("|")
                    if len(parts) < 2:
                        return
                    from_user = parts[1]

                    if self.gui_ref:
                        if decoded.startswith("[CHAT_REQUEST]"):
                            self.gui_ref.on_friend_request(from_user)
                        elif decoded.startswith("[CHAT_ACCEPTED]"):
                            self.gui_ref.approved_peers.add(from_user)
                            self.gui_ref.chat_area.append(f"[INFO] {from_user} accepted your chat request.")
                            if self.gui_ref.active_peer == from_user:
                                self.gui_ref.enable_chat(True)
                        elif decoded.startswith("[CHAT_DECLINED]"):
                            self.gui_ref.chat_area.append(f"[INFO] {from_user} declined your chat request.")
                            self.gui_ref.pending_requests.discard(from_user)
                            self.gui_ref.enable_chat(False)
                    return
            except Exception as e:
                print(f"[SESSION] Failed to process control message: {e}")

        # Encrypted chat message fallback
        try:
            enc_key_len = int.from_bytes(data[:4], byteorder='big')
            encrypted_key = data[4:4+enc_key_len]
            encrypted_message = data[4+enc_key_len:]

            aes_key = decrypt_aes_key_with_rsa(self.private_key, encrypted_key)
            message = decrypt_message_with_aes(aes_key, encrypted_message)

            print(f"[SESSION] Decrypted incoming message: {message}")

            if self.on_message_callback:
                self.on_message_callback(message)
        except Exception as e:
            print(f"[SESSION] Failed to decrypt chat message: {e}")



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
