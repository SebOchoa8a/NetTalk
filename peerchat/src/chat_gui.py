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

from user_session import UserSession
from key_manager import KeyManager
from core.auth import register_user, login_user
from core.crypto import (
    generate_aes_key, encrypt_message_with_aes,
    encrypt_aes_key_with_rsa, load_private_key
)

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
        self.setWindowTitle("NeTalk (Peer-to-Peer)")
        self.setGeometry(100, 100, 700, 500)

        self.nickname = ""
        self.private_key = None
        self.peer_public_key = None
        self.active_peer = ""
        self.key_manager = None
        self.session = None
        self.active_users = {}

        self.new_message_signal.connect(self.display_incoming_message)
        self.layout = QStackedLayout()
        self.init_login_ui()
        self.init_chat_ui()
        self.setLayout(self.layout)

    def init_login_ui(self):
        self.login_widget = QWidget()
        layout = QVBoxLayout()

        self.nickname_input = QLineEdit()
        self.password_input = QLineEdit()
        self.status_label = QLabel()

        self.nickname_input.setPlaceholderText("Nickname")
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)

        register_btn = QPushButton("Register")
        login_btn = QPushButton("Login")
        register_btn.clicked.connect(self.register_user)
        login_btn.clicked.connect(self.login_user)

        layout.addWidget(QLabel("Welcome to NeTalk"))
        layout.addWidget(self.nickname_input)
        layout.addWidget(self.password_input)
        layout.addWidget(register_btn)
        layout.addWidget(login_btn)
        layout.addWidget(self.status_label)

        self.login_widget.setLayout(layout)
        self.layout.addWidget(self.login_widget)

    def init_chat_ui(self):
        self.chat_widget = QWidget()
        layout = QVBoxLayout()

        self.user_list = QListWidget()
        self.user_list.itemClicked.connect(self.select_user)

        self.chat_status = QLabel("Select a user to chat")
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("Type a message...")
        self.input_box.setEnabled(False)
        self.input_box.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)

        layout.addWidget(self.user_list)
        layout.addWidget(self.chat_status)
        layout.addWidget(self.chat_area)
        layout.addWidget(self.input_box)
        layout.addWidget(self.send_button)

        self.chat_widget.setLayout(layout)
        self.layout.addWidget(self.chat_widget)

    def register_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()
        success, msg = register_user(name, password)
        self.status_label.setText(msg)
        if success:
            self.login_common(name)

    def login_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()
        if not name or not password:
            self.status_label.setText("Please fill in both fields.")
            return

        self.private_key = load_private_key(name)
        success, msg = login_user(name, password)
        self.status_label.setText(msg)
        if success:
            self.login_common(name)

    def login_common(self, name):
        self.nickname = name
        self.key_manager = KeyManager(name)
        self.session = UserSession(
            nickname=name,
            on_message_callback=self.new_message_signal.emit,
            on_friend_update=self.update_active_users
        )
        self.session.start()
        self.update_active_users()
        self.layout.setCurrentWidget(self.chat_widget)

    def update_active_users(self):
        self.user_list.clear()
        self.active_users = self.session.peer_cache
        for user in self.active_users:
            if user != self.nickname:
                self.user_list.addItem(user)

    def select_user(self, item):
        peer_name = item.text()
        self.active_peer = peer_name

        peer_info = self.session.get_peer_connection_info(peer_name)
        if not peer_info:
            self.chat_status.setText("Waiting for peer info...")
            return

        self.peer_public_key = self.key_manager.get_friend_key(peer_name)
        if self.peer_public_key:
            self.chat_status.setText(f"Connected to {peer_name}")
            self.input_box.setEnabled(True)
            self.send_button.setEnabled(True)
        else:
            self.chat_status.setText("No public key yet.")
            self.input_box.setEnabled(False)
            self.send_button.setEnabled(False)

    def send_message(self):
        if not self.nickname or not self.peer_public_key:
            self.chat_area.append("No peer selected.")
            return

        msg = self.input_box.text().strip()
        if not msg:
            return

        aes_key = generate_aes_key()
        encrypted_msg = encrypt_message_with_aes(aes_key, f"{self.nickname}:{msg}")
        encrypted_key = encrypt_aes_key_with_rsa(self.peer_public_key, aes_key)
        full_packet = len(encrypted_key).to_bytes(4, 'big') + encrypted_key + encrypted_msg

        peer_info = self.session.get_peer_connection_info(self.active_peer)
        if not peer_info:
            self.chat_area.append("Missing peer info.")
            return

        self.session.send_raw_packet(full_packet, peer_info["ip"], peer_info["port"])
        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_area.append(f"[{timestamp}] You: {msg}")
        self.input_box.clear()

    def display_incoming_message(self, message):
        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_area.append(f"[{timestamp}] {message}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec_())
