import os
import socket
import json

from communicator import Communicator  # Your custom TCP communication handler
from core.crypto import (
    load_private_key,
    decrypt_aes_key_with_rsa,
    decrypt_message_with_aes
)
from key_manager import KeyManager  # For managing keys and friend list
from friend_request import handle_friend_request  # Logic for updating friend list

class UserSession:
    def __init__(self, nickname, on_message_callback=None, on_friend_update=None):
        self.nickname = nickname
        self.listen_port = 6001 if nickname == "alice" else 6000
        self.key_manager = KeyManager(nickname)
        self.private_key = load_private_key(nickname)
        self.on_message_callback = on_message_callback
        self.on_friend_update = on_friend_update
        self.comm = Communicator(self.listen_port, self._handle_message)

        self.peer_cache = {}  #Cache for dynamic peer info
        print(f"[INFO] {nickname} is reachable at {self.get_local_ip()}:{self.listen_port}")

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

    def _handle_message(self, data, addr=None):
        try:
            # 🔍 Try decoding as plain JSON first (for presence / friend announcements)
            try:
                message = json.loads(data.decode())
                if isinstance(message, dict) and message.get("type") == "FRIEND_REQUEST":
                    sender = message.get("from")
                    sender_ip = message.get("ip")
                    sender_port = message.get("port")

                    if sender and sender_ip and sender_port:
                        self.peer_cache[sender] = {
                            "ip": sender_ip,
                            "port": sender_port
                        }
                        print(f"[SESSION] Cached peer info: {sender} → {sender_ip}:{sender_port}")

                    # Refresh friend list in GUI if needed
                    if self.on_friend_update:
                        self.on_friend_update()

                    return  # Done handling plaintext message
            except Exception:
                pass  # Not a plaintext message, try encrypted instead

            #Otherwise, treat it as an encrypted chat message
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


    def send_presence_announcement(self, target_ip, target_port):
        """Send this user's IP and port to a peer."""
        packet = json.dumps({
            "type": "FRIEND_REQUEST",
            "from": self.nickname,
            "ip": self.get_local_ip(),
            "port": self.listen_port
        }).encode()
        try:
            self.comm.send_message(packet, target_ip, target_port)
            print(f"[SESSION] Sent presence announcement to {target_ip}:{target_port}")
        except Exception as e:
            print(f"[SESSION] Failed to send presence: {e}")

    def get_peer_connection_info(self, peer_name):
        return self.peer_cache.get(peer_name)

    def send_raw_packet(self, data: bytes, peer_ip: str, peer_port: int):
        try:
            self.comm.send_message(data, peer_ip, peer_port)
            print(f"[SESSION] Sent packet to {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"[SESSION] Failed to send packet: {e}")
