import os
import subprocess
import socket
import threading
import json
import random

from communicator import Communicator
from communicator_udp import CommunicatorUDP
from core.crypto import load_private_key
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
    def __init__(self, nickname, ssh_user=None, ssh_host=None):
        self.nickname = nickname
        self.local_ip = get_local_ip()
        self.listen_port = random.randint(6000, 7000)

        # Load peer info
        registry_path = os.path.join(os.path.dirname(__file__), "peer_registery.json")
        if os.path.exists(registry_path):
            with open(registry_path, "r") as f:
                registry = json.load(f)
                peer_info = registry.get(nickname, {})
                self.ssh_user = peer_info.get("ssh_user", nickname)
                self.ssh_host = peer_info.get("ssh_host", get_local_ip())
                self.peer_port = peer_info.get("peer_port", 6000)
                print(f"[DEBUG] Using ssh_user={self.ssh_user}, ssh_host={self.ssh_host}, peer_port={self.peer_port}")
        else:
            self.ssh_user = ssh_user or nickname
            self.ssh_host = ssh_host or get_local_ip()
            self.peer_port = 6000

        self.key_manager = KeyManager(nickname)
        self.private_key = load_private_key(nickname)
        self.mode = "udp"  # default
        self.comm = None
        self.ssh_process = None


    def start(self):
        self._determine_connection_mode()
        self.comm.start_listener(self._handle_message)

    def _handle_message(self, data: bytes):
        try:
            msg = json.loads(data.decode())
            msg_type = msg.get("type")

            if msg_type == "FRIEND_REQUEST":
                handle_friend_request(msg, self.key_manager)
            else:
                print("[SESSION] Received unknown message type.")
        except Exception as e:
            print(f"[SESSION] Failed to handle message: {e}")

    def _determine_connection_mode(self):
        # Default to local IP if nothing is passed
        if not self.ssh_host:
            self.ssh_host = get_local_ip()

        print(f"[DEBUG] Local IP: {self.local_ip}, Target SSH Host: {self.ssh_host}")

        # If the host is the same machine, skip SSH tunnel
        if self.ssh_host == self.local_ip or self.ssh_host == "127.0.0.1":
            self.mode = "udp"
            print("[SESSION] Same host detected. Using local UDP mode.")
            self.comm = CommunicatorUDP(self.listen_port, on_receive_callback=self._handle_udp)
            return

        # Otherwise, use SSH tunnel
        self.mode = "ssh"
        self._start_ssh_tunnel()
        print("[SESSION] Using SSH tunnel mode")
        self.comm = Communicator(self.listen_port, key_manager=self.key_manager)

    def _on_same_subnet(self, peer_ip):
        return peer_ip.rsplit('.', 1)[0] == self.local_ip.rsplit('.', 1)[0]

    def _start_ssh_tunnel(self):
        if not self.ssh_user or not self.ssh_host:
            print("[SESSION] SSH credentials not provided. Skipping tunnel.")
            return

        # Load peer registry to get remote port
        registry_path = os.path.join(os.path.dirname(__file__), "peer_registery.json")
        if os.path.exists(registry_path):
            with open(registry_path, "r") as f:
                registry = json.load(f)
                peer_info = registry.get(self.nickname, {})
                remote_port = peer_info.get("listen_port", 6000)
        else:
            remote_port = 6000  # fallback

        ssh_command = [
            "ssh", "-N",
            "-L", f"{self.listen_port}:{self.ssh_host}:{remote_port}",
            f"{self.ssh_user}@{self.ssh_host}"
        ]

        print(f"[SESSION] Starting SSH tunnel: {' '.join(ssh_command)}")
        self.ssh_process = subprocess.Popen(ssh_command)


    def stop(self):
        if self.ssh_process:
            self.ssh_process.terminate()
            print("[SESSION] SSH tunnel closed")

    def _handle_udp(self, data, addr):
        try:
            msg = json.loads(data.decode())
            if msg.get("type") == "FRIEND_REQUEST":
                handle_friend_request(msg, self.key_manager)
        except Exception as e:
            print(f"[UDP] Error handling message: {e}")

    def send_friend_request(self, target_ip, friend_nickname, friend_pubkey):
        packet = json.dumps({
            "type": "FRIEND_REQUEST",
            "from": self.nickname,
            "pubkey": friend_pubkey
        }).encode()

        try:
            if self.mode == "udp":
                self.comm.send_message(packet, target_ip, self.peer_port)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((target_ip, self.peer_port))
                    s.send(packet)
            print(f"[SESSION] Sent friend request to {friend_nickname}")
        except Exception as e:
            print(f"[SESSION] Failed to send request: {e}")

    def send_raw_packet(self, data: bytes, peer_ip: str, peer_port: int):
        try:
            if self.mode == "udp":
                self.comm.send_message(data, peer_ip, peer_port)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((peer_ip, peer_port))
                    s.sendall(data)
            print(f"[SESSION] Sent packet to {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"[SESSION] Failed to send packet: {e}")
