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
        self.peer_port = 6000
        self.ssh_user = ssh_user
        self.ssh_host = ssh_host
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
        if self.ssh_host and not self._on_same_subnet(self.ssh_host):
            self.mode = "ssh"
            self._start_ssh_tunnel()
            print("[SESSION] Using SSH tunnel mode")
            self.comm = Communicator(self.listen_port, key_manager=self.key_manager)
        else:
            self.mode = "udp"
            print("[SESSION] Using local UDP mode")
            self.comm = CommunicatorUDP(self.listen_port, on_receive_callback=self._handle_udp)

    def _on_same_subnet(self, peer_ip):
        return peer_ip.rsplit('.', 1)[0] == self.local_ip.rsplit('.', 1)[0]

    def _start_ssh_tunnel(self):
        if not self.ssh_user or not self.ssh_host:
            print("[SESSION] SSH credentials not provided. Skipping tunnel.")
            return
        ssh_command = [
            "ssh", "-N",
            "-L", f"{self.peer_port}:localhost:{self.peer_port}",
            f"{self.ssh_user}@{self.ssh_host}"
        ]
        print(f"[SESSION] Starting SSH tunnel: {ssh_command}")
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
