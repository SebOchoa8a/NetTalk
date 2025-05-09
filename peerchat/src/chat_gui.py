import sys
import os
import threading
import socket
import json
import requests
import asyncio

from datetime import datetime

"""Helper function to find the public ip after the user logs in."""

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text.strip()
    except Exception:
        return "127.0.0.1"

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QStackedLayout, QListWidget, QFileDialog
)
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtCore import QTimer
from PyQt5.QtCore import Qt


from key_manager import KeyManager
from user_session import UserSession
from file_transfer import start_file_listener, send_file_to_peer, PEER_RUNTIME_INFO
from core.crypto import (
    generate_rsa_keypair, load_private_key,
    generate_aes_key, encrypt_message_with_aes, decrypt_message_with_aes,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
)
from core.auth import register_user, login_user
from core.crypto import load_public_key_from_file
from dht_service import DHTService

KEY_DIR = os.path.join("..", "keys")
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

class ChatApp(QWidget):
    new_message_signal = pyqtSignal(str)
    friend_request_signal = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NeTalk (Encrypted P2P)")
        self.setFixedSize(720, 600)

        self.nickname = ""
        self.private_key = None
        self.peer_public_key = None
        self.active_peer = ""
        self.key_manager = None
        self.session = None
        self.approved_peers = set()  # Peers you've been allowed to chat with
        self.pending_requests = set()  # Peers you've sent a request to
        self.new_message_signal.connect(self.display_incoming_message)
        self.friend_request_signal.connect(self.on_friend_request)
        self.layout = QStackedLayout()
        self.init_login_ui()
        self.init_chat_ui()
        self.setStyleSheet("""
        QWidget {
            background-color: #2f3136;
            color: #ffffff;
            font-family: 'Segoe UI', sans-serif;
        }
        QTextEdit, QLineEdit {
            background-color: #40444b;
            border: 1px solid #202225;
            color: #dcddde;
        }
        QPushButton {
            background-color: #8b0000;
            color: white;
            padding: 6px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #a40000;
        }
        QListWidget {
            background-color: #2f3136;
            border: 1px solid #202225;
            color: #dcddde;
        }
        QLabel {
            color: #ffffff;
        }
        """)
        
        self.setLayout(self.layout)

    def init_login_ui(self):
        self.login_widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(50, 50, 50, 50)
        layout.setSpacing(20)

        title = QLabel("NETTALK")
        title.setStyleSheet("font-size: 36px; font-weight: bold; color: #ffffff;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        layout.addSpacing(40)

        self.nickname_input = QLineEdit()
        self.nickname_input.setPlaceholderText("Your Nickname")
        layout.addWidget(self.nickname_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.status_label = QLabel()
        self.status_label.setStyleSheet("color: #ff5555;")
        layout.addWidget(self.status_label)

        register_btn = QPushButton("Register")
        login_btn = QPushButton("Login")

        # Match button appearance
        for btn in [register_btn, login_btn]:
            btn.setStyleSheet("background-color: #8b0000; padding: 10px; font-weight: bold; border-radius: 4px;")

        layout.addWidget(register_btn)
        layout.addWidget(login_btn)

        register_btn.clicked.connect(self.register_user)
        login_btn.clicked.connect(self.login_user)

        self.login_widget.setLayout(layout)
        self.layout.addWidget(self.login_widget)

    def init_chat_ui(self):
        self.chat_widget = QWidget()
        main_layout = QVBoxLayout()  # Top-level layout

        # === Chat Body Layout: Left = Friends | Right = Chat ===
        chat_body_layout = QHBoxLayout()

        # === Left: Friends List ===
        left_side = QVBoxLayout()
        left_side.addWidget(QLabel("Online Users"))
        self.friends_list = QListWidget()
        self.friends_list.itemClicked.connect(self.select_friend)
        left_side.addWidget(self.friends_list)

        # === Right: Chat Display + Input ===
        right_side = QVBoxLayout()
        self.chat_status = QLabel("Select a user to chat with")
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        # Input Row ( + | message | Send )
        chat_input_layout = QHBoxLayout()
        file_button = QPushButton("+")
        file_button.setFixedWidth(30)
        file_button.clicked.connect(self.show_file_options)

        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("Type a message...")
        self.input_box.returnPressed.connect(self.send_message)
        self.input_box.setEnabled(False)

        self.send_button = QPushButton("Send")
        self.send_button.setFixedWidth(80)
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)

        chat_input_layout.addWidget(file_button)
        chat_input_layout.addWidget(self.input_box)
        chat_input_layout.addWidget(self.send_button)

        right_side.addWidget(self.chat_status)
        right_side.addWidget(self.chat_area)
        right_side.addLayout(chat_input_layout)

        # Combine both sides
        chat_body_layout.addLayout(left_side, 1)
        chat_body_layout.addLayout(right_side, 4)

        main_layout.addLayout(chat_body_layout)
        self.chat_widget.setLayout(main_layout)
        self.layout.addWidget(self.chat_widget)

        # Refresh peer list every 5 seconds
        self.online_timer = QTimer()
        self.online_timer.timeout.connect(self.populate_friends)
        self.online_timer.start(5000)

    def display_incoming_message(self, message):
        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_area.append(f"[{timestamp}] {message}")

    def register_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()
        success, message = register_user(name, password)
        self.status_label.setText(message)

        # Register public IP in peer_registry.json
        if success:
            try:
                self.nickname = name
                self.key_manager = KeyManager(name)

                self.session = UserSession(nickname=name, on_message_callback=lambda msg: self.new_message_signal.emit(msg))
                self.session.start()

                # Start file receiver on a separate port
                FILE_TRANSFER_BASE_PORT = 7000
                start_file_listener(port=FILE_TRANSFER_BASE_PORT)
                self.file_transfer_port = FILE_TRANSFER_BASE_PORT

                ip_public = get_public_ip()
                ip_local = get_local_ip()

                registry = {}
                if os.path.exists(PEER_REGISTRY):
                    with open(PEER_REGISTRY, "r") as f:
                        registry = json.load(f)

                registry[name] = {
                    "public_ip": ip_public,
                    "local_ip": ip_local,
                    "listen_port": self.session.listen_port
                }

                with open(PEER_REGISTRY, "w") as f:
                    json.dump(registry, f, indent=4)

                print(f"[INFO] Updated peer_registry.json with {name}'s public and local IPs.")

                self.populate_friends()
                self.layout.setCurrentWidget(self.chat_widget)
                
                # Dynamic peer-based bootstrap config
                bootstrap_nodes = []

                known_peers = [("192.168.1.198", 5678), ("192.168.1.242", 5678)]
                for ip, port in known_peers:
                    if ip != get_local_ip():
                        bootstrap_nodes.append((ip, port))

                self.dht = DHTService(username=name, ip=ip_public, port=self.session.listen_port, bootstrap_nodes=bootstrap_nodes)
                self.dht.start()

            except Exception as e:
                print(f"[ERROR] Session initialization failed: {e}")
                self.status_label.setText("Something went wrong during session start.")



    def login_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()

        if not name or not password:
            self.status_label.setText("Enter your nickname and password.")
            return

        private_path = os.path.join(KEY_DIR, f"{name}_private.pem")

        self.private_key = load_private_key(name)
        success, message = login_user(name, password)
        self.status_label.setText(message)

        if success:
            try:
                self.nickname = name
                self.key_manager = KeyManager(name)

                self.session = UserSession(
                    nickname=name,
                    on_message_callback=self.display_incoming_message,
                    on_friend_update=self.populate_friends,
                    gui_ref=self
                )
                self.session.start()

                # Start file receiver on a separate port
                FILE_TRANSFER_BASE_PORT = 7000
                start_file_listener(port=FILE_TRANSFER_BASE_PORT)
                self.file_transfer_port = FILE_TRANSFER_BASE_PORT

                ip_public = get_public_ip()
                ip_local = get_local_ip()

                registry = {}
                if os.path.exists(PEER_REGISTRY):
                    with open(PEER_REGISTRY, "r") as f:
                        registry = json.load(f)

                registry[name] = {
                    "public_ip": ip_public,
                    "local_ip": ip_local,
                    "listen_port": self.session.listen_port
                }

                with open(PEER_REGISTRY, "w") as f:
                    json.dump(registry, f, indent=4)

                print(f"[INFO] Updated peer_registry.json with {name}'s public and local IPs.")

                

                self.populate_friends()
                self.layout.setCurrentWidget(self.chat_widget)

                # Dynamic peer-based bootstrap config
                bootstrap_nodes = []

                if name.lower() == "alice":
                    bootstrap_nodes = [("192.168.1.198", 5678)]  # bob's IP
                elif name.lower() == "bob":
                    bootstrap_nodes = [("192.168.1.242", 5678)]  # alice's IP

                self.dht = DHTService(username=name, ip=ip_public, port=self.session.listen_port, bootstrap_nodes=bootstrap_nodes)

                self.dht.start()

            except Exception as e:
                print(f"[ERROR] Session initialization failed: {e}")
                self.status_label.setText("Something went wrong during session start.")

    def populate_friends(self):
        self.friends_list.clear()
        try:
            with open("peer_registry.json", "r") as f:
                registry = json.load(f)
                for username in registry:
                    if username != self.nickname:
                        self.friends_list.addItem(username)
        except Exception as e:
            print(f"[GUI] Could not populate friends from registry: {e}")

    def enable_chat(self, allowed):
        self.input_box.setEnabled(allowed)
        self.send_button.setEnabled(allowed)

    def select_friend(self, item):
        selected_user = item.text()
        self.active_peer = selected_user
        self.chat_status.setText(f"Chatting with {selected_user}")

        # Always load the public key
        public_key_path = os.path.join("keys", f"{selected_user}_public.pem")
        if not os.path.exists(public_key_path):
            self.chat_area.append(f"[ERROR] Public key for {selected_user} not found at {public_key_path}")
            self.peer_public_key = None
            return

        self.peer_public_key = load_public_key_from_file(public_key_path)

        if selected_user in self.approved_peers:
            self.enable_chat(True)
            self.chat_area.append(f"[INFO] Reconnected to {selected_user}")
            return

        if selected_user in self.pending_requests:
            self.chat_area.append(f"[INFO] Chat request already sent to {selected_user}. Waiting for response...")
            return

        # Send chat request
        peer_info = self.get_peer_info(selected_user)
        if not peer_info:
            self.chat_area.append("Peer info not found.")
            return

        peer_ip = self.get_target_ip(peer_info)
        peer_port = peer_info.get("listen_port", 6000)
        message = f"[CHAT_REQUEST]|{self.nickname}"
        self.session.comm.send_message(message.encode(), peer_ip, peer_port)

        self.chat_area.append(f"[INFO] Sent chat request to {selected_user}")
        self.pending_requests.add(selected_user)
        self.enable_chat(False)


    def send_friend_request_to_active(self):
        if not self.active_peer:
            self.chat_area.append("Select a user to send a friend request.")
            return

        if not self.session or not self.key_manager:
            self.chat_area.append("Session not started or key manager unavailable.")
            return

        peer_info = self.get_peer_info(self.active_peer)
        if not peer_info:
            self.chat_area.append(f"No peer info found for {self.active_peer}.")
            return

        peer_ip = self.get_target_ip(peer_info)
        peer_port = peer_info.get("listen_port", 6000)

        pubkey_path = os.path.join("..", "keys", f"{self.nickname}_public.pem")
        if not os.path.exists(pubkey_path):
            self.chat_area.append("Your public key was not found.")
            return

        with open(pubkey_path, "r") as f:
            public_key_pem = f.read()

        self.session.send_friend_request(peer_ip, self.active_peer, public_key_pem)
        self.chat_area.append(f"Sent friend request to {self.active_peer}")

    def get_peer_info(self, name):
        if os.path.exists(PEER_REGISTRY):
            with open(PEER_REGISTRY, "r") as f:
                return json.load(f).get(name, {})
        return {}
    
    def get_target_ip(self, peer_info):
        my_local = get_local_ip()
        target_local = peer_info.get("local_ip")
        target_public = peer_info.get("public_ip")

        if target_local and my_local.split(".")[:2] == target_local.split(".")[:2]:
            # Same network, use LAN IP
            return target_local
        else:
            # Different network, use public IP
            return target_public

    def send_message(self):
        if not self.nickname or not self.peer_public_key:
            self.chat_area.append("You must select a friend to chat with.")
            return

        msg = self.input_box.text()
        aes_key = generate_aes_key()
        full_msg = f"{self.nickname}:{msg}"
        encrypted_msg = encrypt_message_with_aes(aes_key, full_msg)
        encrypted_key = encrypt_aes_key_with_rsa(self.peer_public_key, aes_key)

        full_packet = len(encrypted_key).to_bytes(4, byteorder='big') + encrypted_key + encrypted_msg

        try:
            # Get the active friend's IP and port
            peer_info = self.get_peer_info(self.active_peer)
            if not peer_info:
                self.chat_area.append(f"No peer info found for {self.active_peer}.")
                return

            peer_ip = self.get_target_ip(peer_info)
            peer_port = peer_info.get("listen_port", 6000)

            # Send the packet over TCP
            self.session.comm.send_message(full_packet, peer_ip, peer_port)

            # Update UI
            timestamp = datetime.now().strftime("%I:%M %p")
            self.chat_area.append(f"[{timestamp}] You: {msg}")
            self.input_box.clear()
        except Exception as e:
            self.chat_area.append(f"Failed to send message: {e}")

    def show_file_options(self):
        if not self.active_peer:
            self.chat_area.append("You must select a friend to send a file.")
            return

        # Select file
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if not file_path:
            return

        # Get peer info
        peer_info = self.get_peer_info(self.active_peer)
        if not peer_info:
            self.chat_area.append("Peer info not found.")
            return

        ip = self.get_target_ip(peer_info)
        port = 7000 # File receiver on +1 port

        # Populate runtime info and send
        PEER_RUNTIME_INFO[self.active_peer] = {"ip": ip, "port": port}
        send_file_to_peer(file_path, self.active_peer)

    def on_friend_request(self, from_user):
        from PyQt5.QtWidgets import QMessageBox

        msg_box = QMessageBox()
        msg_box.setWindowTitle("Chat Request")
        msg_box.setText(f"{from_user} would like to chat with you.")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        response = msg_box.exec_()

        peer_info = self.get_peer_info(from_user)
        peer_ip = self.get_target_ip(peer_info)
        peer_port = peer_info.get("listen_port", 6000)

        if response == QMessageBox.Yes:
            self.approved_peers.add(from_user)
            self.session.comm.send_message(f"[CHAT_ACCEPTED]|{self.nickname}".encode(), peer_ip, peer_port)
            self.chat_area.append(f"[INFO] You accepted chat with {from_user}")
            if self.active_peer == from_user:
                self.enable_chat(True)
        else:
            self.session.comm.send_message(f"[CHAT_DECLINED]|{self.nickname}".encode(), peer_ip, peer_port)
            self.chat_area.append(f"[INFO] You declined chat with {from_user}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec_())