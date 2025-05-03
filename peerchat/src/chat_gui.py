import sys
import os
import socket
import json
import requests
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QStackedLayout, QListWidget
)
from PyQt5.QtCore import pyqtSignal

from key_manager import KeyManager
from user_session import UserSession
from core.crypto import (
    generate_aes_key, encrypt_message_with_aes,
    encrypt_aes_key_with_rsa, load_public_key_from_file
)
from core.auth import register_user, login_user

KEY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),"keys"))

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

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NeTalk (DHT P2P)")
        self.setGeometry(100, 100, 700, 500)

        self.nickname = ""
        self.session = None
        self.peer_public_key = None
        self.active_peer = ""
        self.key_manager = None

        self.new_message_signal.connect(self.display_incoming_message)

        self.layout = QStackedLayout()
        self.init_login_ui()
        self.init_chat_ui()
        self.setLayout(self.layout)

    def init_login_ui(self):
        self.login_widget = QWidget()
        layout = QVBoxLayout()

        title = QLabel("Welcome to NeTalk")
        title.setStyleSheet("font-size: 20px; font-weight: bold")
        layout.addWidget(title)

        self.nickname_input = QLineEdit()
        self.nickname_input.setPlaceholderText("Nickname")
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
        main_layout = QVBoxLayout()

        self.friends_list = QListWidget()
        self.friends_list.itemClicked.connect(self.select_peer)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.chat_status = QLabel("Select a user to chat with")
        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("Type a message...")
        self.input_box.returnPressed.connect(self.send_message)
        self.input_box.setEnabled(False)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)

        left = QVBoxLayout()
        left.addWidget(QLabel("Online Users"))
        left.addWidget(self.friends_list)

        right = QVBoxLayout()
        right.addWidget(self.chat_status)
        right.addWidget(self.chat_area)
        right.addWidget(self.input_box)
        right.addWidget(self.send_button)

        hbox = QHBoxLayout()
        hbox.addLayout(left, 2)
        hbox.addLayout(right, 5)

        main_layout.addLayout(hbox)
        self.chat_widget.setLayout(main_layout)
        self.layout.addWidget(self.chat_widget)

        def send_chat_request(self):
            if not self.active_peer:
                return

            packet = json.dumps({
                "type": "CHAT_REQUEST",
                "from": self.nickname,
                "msg": f"{self.nickname} would like to chat!"
            }).encode()

            peer_info = self.session.get_peer_info(self.active_peer)
            if peer_info:
                self.session.send_encrypted_message(packet, peer_info["ip"], peer_info["port"])
                self.chat_area.append(f"[System] Sent chat request to {self.active_peer}")


    def login_user(self):
        name = self.nickname_input.text().strip()
        password = self.password_input.text().strip()

        if not name or not password:
            self.status_label.setText("Nickname and password required.")
            return

        success, message = login_user(name, password)
        self.status_label.setText(message)

        if success:
            self.login_common(name)

    def register_user(self):
        name = self.nickname_input.text().strip()
        password = self.password_input.text().strip()

        if not name or not password:
            self.status_label.setText("Nickname and password required.")
            return

        success, message = register_user(name, password)
        self.status_label.setText(message)

        if success:
            self.login_common(name)

    def login_common(self, name):
        self.nickname = name
        self.key_manager = KeyManager(name)

        self.session = UserSession(
            nickname=name,
            on_message_callback=self.new_message_signal.emit,
            on_peer_update=self.update_active_user_list
        )

        self.update_active_user_list()
        self.layout.setCurrentWidget(self.chat_widget)

    def update_active_user_list(self, from_user=None, is_request=False):
        self.friends_list.clear()
        peers = self.session.dht.get_all_known_peers()
        for peer in peers:
            if peer != self.nickname:
                self.friends_list.addItem(peer)

        if is_request and from_user:
            self.chat_area.append(f"[System] {from_user} wants to chat! Click their name to accept.")

    def select_peer(self, item):
        peer_name = item.text()
        self.active_peer = peer_name

        # Try to get their public key from the DHT
        peer_key = self.session.get_peer_public_key(peer_name)
        if peer_key:
            self.peer_public_key = peer_key
            self.chat_status.setText(f"Connected to {peer_name}")
            self.input_box.setEnabled(True)
            self.send_button.setEnabled(True)
        else:
            self.chat_status.setText("Public key not found for selected user.")
            self.input_box.setEnabled(False)
            self.send_button.setEnabled(False)

        if self.peer_public_key is None and self.key_manager.public_key:
            public_key_pem = self.key_manager.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            response_packet = json.dumps({
                "type": "PUBLIC_KEY_SHARE",
                "from": self.nickname,
                "public_key": public_key_pem
            }).encode()

            peer_info = self.session.get_peer_info(peer_name)
            if peer_info:
                self.session.send_encrypted_message(response_packet, peer_info["ip"], peer_info["port"])
                self.chat_area.append(f"[System] Sent public key to {peer_name}")

    def display_incoming_message(self, msg):
        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_area.append(f"[{timestamp}] {msg}")

    def send_message(self):
        if not self.active_peer or not self.peer_public_key:
            self.chat_area.append("Select a user with valid public key.")
            return

        msg = self.input_box.text().strip()
        if not msg:
            return

        aes_key = generate_aes_key()
        encrypted_msg = encrypt_message_with_aes(aes_key, f"{self.nickname}:{msg}")
        encrypted_key = encrypt_aes_key_with_rsa(self.peer_public_key, aes_key)
        full_packet = len(encrypted_key).to_bytes(4, 'big') + encrypted_key + encrypted_msg

        peer_info = self.session.get_peer_info(self.active_peer)
        if not peer_info:
            self.chat_area.append("Failed to retrieve peer connection info.")
            return

        peer_ip = peer_info.get("ip")
        peer_port = peer_info.get("port")

        if not peer_ip or not peer_port:
            self.chat_area.append("Peer connection info incomplete.")
            return

        self.session.send_encrypted_message(full_packet, peer_ip, peer_port)

        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_area.append(f"[{timestamp}] You: {msg}")
        self.input_box.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec_())
