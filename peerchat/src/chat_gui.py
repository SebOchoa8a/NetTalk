import sys
import os
import threading
import socket
import json
import requests
from datetime import datetime

"""Helper function to find the public ip after the user logs in."""

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text.strip()
    except Exception:
        return "127.0.0.1"

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QStackedLayout, QListWidget
)

from key_manager import KeyManager
from user_session import UserSession
from friend_request import handle_friend_request
from core.crypto import (
    generate_rsa_keypair, load_private_key,
    generate_aes_key, encrypt_message_with_aes, decrypt_message_with_aes,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
)
from core.auth import register_user, login_user

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
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NeTalk (Encrypted P2P)")
        self.setGeometry(100, 100, 700, 500)

        self.nickname = ""
        self.private_key = None
        self.peer_public_key = None
        self.active_peer = ""
        self.key_manager = None
        self.session = None

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

        title = QLabel("Welcome to NeTalk")
        title.setStyleSheet("font-size: 20px; font-weight: bold")
        layout.addWidget(title)

        self.nickname_input = QLineEdit()
        self.nickname_input.setPlaceholderText("Your Nickname")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.status_label = QLabel()

        register_btn = QPushButton("Register")
        login_btn = QPushButton("Login")
        register_btn.clicked.connect(self.register_user)
        login_btn.clicked.connect(self.login_user)

        layout.addWidget(self.nickname_input)
        layout.addWidget(self.password_input)
        layout.addWidget(register_btn)
        layout.addWidget(login_btn)
        layout.addWidget(self.status_label)

        self.login_widget.setLayout(layout)
        self.layout.addWidget(self.login_widget)

    def init_chat_ui(self):
        self.chat_widget = QWidget()
        main_layout = QVBoxLayout()  # Top-level layout to hold friend input + chat body

        # === Friend Input Bar ===
        friend_bar = QHBoxLayout()
        self.friend_input = QLineEdit()
        self.friend_input.setPlaceholderText("Enter peer's nickname (case sensitive)...")
        send_friend_btn = QPushButton("Send Friend Request")
        send_friend_btn.clicked.connect(self.handle_add_friend)

        friend_bar.addWidget(self.friend_input)
        friend_bar.addWidget(send_friend_btn)

        main_layout.addLayout(friend_bar)

        # === Chat Interface Layout ===
        chat_body_layout = QHBoxLayout()

        self.friends_list = QListWidget()
        self.friends_list.itemClicked.connect(self.select_friend)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.chat_status = QLabel("Select a friend to chat with")
        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("Type a message...")
        self.input_box.returnPressed.connect(self.send_message)
        self.input_box.setEnabled(False)

        self.send_button = QPushButton("Send")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)

        self.connect_button = QPushButton("Reconnect (SSH)")
        self.connect_button.clicked.connect(self.handle_ssh_connect)

        right_side = QVBoxLayout()
        right_side.addWidget(self.chat_status)
        right_side.addWidget(self.chat_area)
        right_side.addWidget(self.input_box)
        right_side.addWidget(self.send_button)
        right_side.addWidget(self.connect_button)
        
        chat_body_layout.addWidget(self.friends_list, 1)
        chat_body_layout.addLayout(right_side, 4)

        main_layout.addLayout(chat_body_layout)

        self.chat_widget.setLayout(main_layout)
        self.layout.addWidget(self.chat_widget)


    def register_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()
        success, message = register_user(name, password)
        self.status_label.setText(message)

        # Register public IP in peer_registry.json
        if success:
            ip = get_public_ip()
            registry = {}

            if os.path.exists(PEER_REGISTRY):
                with open(PEER_REGISTRY, "r") as f:
                    registry = json.load(f)

            registry[name] = {
                "ssh_user": name,
                "ssh_host": ip,
                "listen_port": 6000,
                "peer_port": 6000
            }

            with open(PEER_REGISTRY, "w") as f:
                json.dump(registry, f, indent=4)

            print(f"[INFO] Registered {name} with public IP {ip}")


    def login_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()

        if not name or not password:
            self.status_label.setText("Enter your nickname and password.")
            return

        private_path = os.path.join(KEY_DIR, f"{name}_private.pem")
        if not os.path.exists(private_path):
            generate_rsa_keypair(name)

        self.private_key = load_private_key(name)
        success, message = login_user(name, password)
        self.status_label.setText(message)

        if success:
            try:
                self.nickname = name
                self.key_manager = KeyManager(name)

                # Update public IP in registry
                ip = get_public_ip()
                registry = {}
                if os.path.exists(PEER_REGISTRY):
                    with open(PEER_REGISTRY, "r") as f:
                        registry = json.load(f)

                registry[name] = {
                    "ssh_user": name,
                    "ssh_host": ip,
                    "listen_port": 6000,
                    "peer_port": 6000
                }

                with open(PEER_REGISTRY, "w") as f:
                    json.dump(registry, f, indent=4)

                print(f"[INFO] Updated peer_registery.json with {name}'s public IP: {ip}")

                self.session = UserSession(nickname=name)
                self.session.start()

                self.populate_friends()
                self.layout.setCurrentWidget(self.chat_widget)  #Switch to chat page here
            except Exception as e:
                print(f"[ERROR] Session initialization failed: {e}")
                self.status_label.setText("Something went wrong during session start.")



    def populate_friends(self):
        self.friends_list.clear()
        if self.key_manager:
            for friend in self.key_manager.list_friends():
                if friend != self.nickname:
                    self.friends_list.addItem(friend)

    def select_friend(self, item):
        peer_name = item.text()
        self.peer_public_key = self.key_manager.get_friend_key(peer_name)
        if self.peer_public_key:
            self.chat_status.setText(f"Connected to {peer_name}")
            self.active_peer = peer_name
            self.input_box.setEnabled(True)
            self.send_button.setEnabled(True)
        else:
            self.chat_status.setText("Peer public key not found.")
            self.peer_public_key = None
            self.input_box.setEnabled(False)
            self.send_button.setEnabled(False)

    def handle_ssh_connect(self):
        if self.session:
            self.session._start_ssh_tunnel()

    def send_friend_request_to_active(self):
        if not self.active_peer:
            self.chat_area.append("Select a user to send a friend request.")
            return

        if not self.session or not self.key_manager:
            self.chat_area.append("Session not started or key manager unavailable.")
            return

        peer_info = self.get_peer_info(self.active_peer)
        peer_ip = peer_info.get("ssh_host", "127.0.0.1")

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
            self.session.send_raw_packet(full_packet, peer_ip="127.0.0.1", peer_port=6000)
            timestamp = datetime.now().strftime("%I:%M %p")
            self.chat_area.append(f"[{timestamp}] You: {msg}")
            self.input_box.clear()
        except Exception as e:
            self.chat_area.append(f"Failed to send message: {e}")

    def handle_add_friend(self):
        target_name = self.friend_input.text().strip()
        if not target_name:
            self.chat_area.append("Please enter a valid nickname.")
            return

        if not self.session or not self.key_manager:
            self.chat_area.append("Session not active.")
            return

        # Get peer info from registry
        peer_info = self.get_peer_info(target_name)
        if not peer_info:
            self.chat_area.append(f"No peer info found for {target_name}.")
            return

        peer_ip = peer_info.get("ssh_host", "127.0.0.1")

        # Get sender's public key
        pubkey_path = os.path.join("..", "keys", f"{self.nickname}_public.pem")
        if not os.path.exists(pubkey_path):
            self.chat_area.append("Public key not found.")
            return

        with open(pubkey_path, "r") as f:
            public_key_pem = f.read()

        self.session.send_friend_request(peer_ip, target_name, public_key_pem)
        self.chat_area.append(f"Sent friend request to {target_name}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec_())