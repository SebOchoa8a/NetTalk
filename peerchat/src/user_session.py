import os
import socket
import json

from communicator import Communicator
from core.crypto import (
    load_private_key,
    decrypt_aes_key_with_rsa,
    decrypt_message_with_aes
)
from key_manager import KeyManager


class UserSession:
    def __init__(self, nickname, on_message_callback=None, on_friend_update=None):
        self.nickname = nickname
        self.listen_port = 6001 if nickname == "alice" else 6000  # Example static ports
        self.key_manager = KeyManager(nickname)
        self.private_key = load_private_key(nickname)
        self.on_message_callback = on_message_callback
        self.on_friend_update = on_friend_update

        self.comm = Communicator(self.listen_port, self._handle_message)
        self.peer_cache = {}  # Dynamic cache: {username: {"ip": ..., "port": ..., "pubkey": ...}}

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

    def send_presence_announcement(self, target_ip, target_port):
        """Send presence info (IP and port) to another peer."""
        packet = json.dumps({
            "type": "FRIEND_REQUEST",
            "from": self.nickname,
            "ip": self.get_local_ip(),
            "port": self.listen_port
        }).encode()
        self.send_raw_packet(packet, target_ip, target_port)

    def request_public_key(self, peer_name, ip, port):
        """Ask a peer for their public key."""
        packet = json.dumps({
            "type": "KEY_REQUEST",
            "from": self.nickname
        }).encode()
        self.send_raw_packet(packet, ip, port)

    def _send_public_key(self, peer_name, ip, port):
        """Send this user's public key to another peer."""
        path = os.path.join("..", "keys", f"{self.nickname}_public.pem")
        if os.path.exists(path):
            with open(path, "r") as f:
                pubkey = f.read()
            packet = json.dumps({
                "type": "KEY_RESPONSE",
                "from": self.nickname,
                "pubkey": pubkey
            }).encode()
            self.send_raw_packet(packet, ip, port)

    def _handle_message(self, data, addr=None):
        try:
            message = data.decode()
            obj = json.loads(message)

            msg_type = obj.get("type")
            sender = obj.get("from")

            if msg_type == "FRIEND_REQUEST":
                sender_ip = obj.get("ip")
                sender_port = obj.get("port")

                if sender and sender_ip and sender_port:
                    self.peer_cache[sender] = {
                        "ip": sender_ip,
                        "port": sender_port
                    }
                    print(f"[SESSION] Cached peer {sender}: {sender_ip}:{sender_port}")

                if self.on_friend_update:
                    self.on_friend_update()

            elif msg_type == "KEY_REQUEST":
                if sender in self.peer_cache:
                    peer = self.peer_cache[sender]
                    self._send_public_key(sender, peer["ip"], peer["port"])

            elif msg_type == "KEY_RESPONSE":
                pubkey = obj.get("pubkey")
                if pubkey:
                    self.key_manager.save_friend_key(sender, pubkey)
                    print(f"[SESSION] Stored public key for {sender}")
                    if self.on_friend_update:
                        self.on_friend_update()

        except Exception:
            # If it fails JSON parse, treat as encrypted chat
            try:
                enc_key_len = int.from_bytes(data[:4], byteorder='big')
                encrypted_key = data[4:4+enc_key_len]
                encrypted_message = data[4+enc_key_len:]

                aes_key = decrypt_aes_key_with_rsa(self.private_key, encrypted_key)
                message = decrypt_message_with_aes(aes_key, encrypted_message)

                print(f"[SESSION] Decrypted chat: {message}")
                if self.on_message_callback:
                    self.on_message_callback(message)

            except Exception as e:
                print(f"[SESSION] Failed to decrypt/process incoming message: {e}")

    def get_peer_connection_info(self, peer_name):
        return self.peer_cache.get(peer_name)

    def send_raw_packet(self, data: bytes, peer_ip: str, peer_port: int):
        try:
            self.comm.send_message(data, peer_ip, peer_port)
            print(f"[SESSION] Sent packet to {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"[SESSION] Failed to send packet: {e}")
