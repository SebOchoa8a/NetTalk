import sys
import os
import socket
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QStackedLayout, QListWidget
)
from PyQt5.QtCore import pyqtSignal, QTimer

from key_manager import KeyManager
from user_session import UserSession
from core.auth import register_user, login_user
from core.crypto import (
    generate_aes_key, encrypt_message_with_aes,
    encrypt_aes_key_with_rsa
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
        self.setWindowTitle("NeTalk (DHT P2P)")
        self.setGeometry(100, 100, 700, 500)

        self.nickname = ""
        self.session = None
        self.active_peer = ""

        self.new_message_signal.connect(self.display_incoming_message)

        self.layout = QStackedLayout()
        self.init_login_ui()
        self.init_chat_ui()
        self.setLayout(self.layout)

    def init_login_ui(self):
        self.login_widget = QWidget()
        layout = QVBoxLayout()

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
        main_layout = QVBoxLayout()

        self.friends_list = QListWidget()
        self.friends_list.itemClicked.connect(self.select_peer)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

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
        right.addWidget(QLabel("Chat Log"))
        right.addWidget(self.chat_area)
        right.addWidget(self.input_box)
        right.addWidget(self.send_button)

        hbox = QHBoxLayout()
        hbox.addLayout(left, 2)
        hbox.addLayout(right, 5)

        main_layout.addLayout(hbox)
        self.chat_widget.setLayout(main_layout)
        self.layout.addWidget(self.chat_widget)

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
            name,
            ip=get_local_ip(),
            port=8000 + (hash(name) % 1000),
            key_manager=self.key_manager,  # Pass the key_manager
            on_message_callback=self.new_message_signal.emit,
            on_peer_discovered=self.update_active_user_list
        )

        self.layout.setCurrentWidget(self.chat_widget)
        QTimer.singleShot(2000, self.update_active_user_list)

    def update_active_user_list(self, from_user=None):
        print("update_active_user_list is happening")
        self.friends_list.clear()
        peers = self.session.dht.get_all_known_peers()
        for peer in peers:
            if peer != self.nickname:
                self.friends_list.addItem(peer)

    def select_peer(self):
        selected = self.friends_list.currentItem()
        if selected:
            peer_name = selected.text()
            self.active_peer = peer_name
            self.input_box.setEnabled(True)
            self.send_button.setEnabled(True)
            self.chat_area.append(f"[System] Chatting with {peer_name}...")

    def send_message(self):
        msg = self.input_box.text().strip()
        if not msg:
            return

        peer_info = self.session.get_peer_info(self.active_peer)
        if not peer_info:
            self.chat_area.append("[ERROR] Peer info not found.")
            return

        aes_key = generate_aes_key()
        encrypted_msg = encrypt_message_with_aes(aes_key, f"{self.nickname}:{msg}")

        peer_public_key = self.key_manager.load_peer_key(self.active_peer)
        encrypted_key = encrypt_aes_key_with_rsa(peer_public_key, aes_key)

        full_packet = len(encrypted_key).to_bytes(4, 'big') + encrypted_key + encrypted_msg

        self.session.send_encrypted_message(full_packet, peer_info['ip'], peer_info['port'] + 1000)

        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_area.append(f"[{timestamp}] You: {msg}")
        self.input_box.clear()

    def display_incoming_message(self, msg):
        timestamp = datetime.now().strftime("%I:%M %p")
        self.chat_area.append(f"[{timestamp}] {msg}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec_())
