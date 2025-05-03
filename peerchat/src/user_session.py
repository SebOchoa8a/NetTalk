import threading, time
import socket
import json
import os
from dht_node import DHTNode
from core.crypto import (
    load_private_key,
    decrypt_aes_key_with_rsa,
    decrypt_message_with_aes,
    load_public_key_from_file
)
from key_manager import KeyManager

class UserSession:
    def __init__(self, nickname, on_message_callback=None, on_peer_update=None):
        self.nickname = nickname
        self.listen_port = 8000 + (0 if nickname == "alice" else 1)
        self.key_manager = KeyManager(nickname)
        self.private_key = load_private_key(nickname)
        self.on_message_callback = on_message_callback
        self.on_peer_update = on_peer_update

        self.dht = DHTNode(nickname, self.get_local_ip(), self.listen_port, on_receive_callback=self._handle_message)

        print(f"[INFO] {nickname} is reachable at {self.get_local_ip()}:{self.listen_port}")

        # Register self in DHT
        self.dht.put(nickname, {
            "ip": self.get_local_ip(),
            "port": self.listen_port,
            "public_key_path": f"/keys/{nickname}_public.pem"
        })

        self.broadcast_presence()
        # Start periodic re-broadcast to help new peers discover each other
        def periodic_broadcast():
            while True:
                time.sleep(5)
                self.broadcast_presence()

        threading.Thread(target=periodic_broadcast, daemon=True).start()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
        
    def broadcast_presence(self):
        # Ask DHT for all known peers (this will be empty on first run)
        known_peers = self.dht.get_all_known_peers()
        print(f"[INFO] {self.nickname} sees known peers: {known_peers}")

        # Tell each known peer "Hey I'm here"
        for peer_name in known_peers:
            peer_info = self.get_peer_info(peer_name)
            if peer_info:
                print(f"[BROADCAST] Telling {peer_name} I'm here at {self.get_local_ip()}:{self.listen_port}")
                msg = {
                    "type": "HELLO",
                    "from": self.nickname,
                    "ip": self.get_local_ip(),
                    "port": self.listen_port
                }
                self.dht.send_udp(peer_info["ip"], peer_info["port"], msg)


    def _handle_message(self, data, addr):
        print(f"[RECEIVED] From {addr} → {message}")
        try:
            if data.startswith(b"{"):
                # Assume plaintext JSON message
                if data.startswith(b"{"):
                    message = json.loads(data.decode())
                    msg_type = message.get("type")
                    
                    if msg_type == "CHAT_REQUEST":
                        from_user = message.get("from")
                        if self.on_peer_update:
                            self.on_peer_update(from_user, is_request=True)
                        print(f"[SESSION] Received chat request from {from_user}")
                        return
                    elif msg_type == "PUBLIC_KEY_SHARE":
                        from_user = message.get("from")
                        public_key_pem = message.get("public_key")
                        self.key_manager.save_peer_key(from_user, public_key_pem)
                        print(f"[SESSION] Received public key from {from_user}")
                        if self.on_peer_update:
                            self.on_peer_update(from_user)
                    elif msg_type == "HELLO":
                        from_user = message.get("from")
                        ip = message.get("ip")
                        port = message.get("port")
                        self.add_peer(from_user, ip, port)
                        print(f"[DHTNode] {from_user} said hello from {ip}:{port}")

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

    def get_peer_info(self, peer_name):
        return self.dht.get(peer_name)

    def get_peer_public_key(self, peer_name):
        peer_info = self.get_peer_info(peer_name)
        if peer_info and 'public_key_path' in peer_info:
            path = peer_info['public_key_path']
            if os.path.exists(path):
                return load_public_key_from_file(path)
        return None

    def send_encrypted_message(self, packet: bytes, peer_ip: str, peer_port: int):
        try:
            self.dht.send_udp(peer_ip, peer_port, packet)
            print(f"[SESSION] Sent UDP message to {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"[SESSION] Failed to send UDP message: {e}")
