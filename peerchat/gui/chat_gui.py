import sys
import threading
import socket
import os
import json
from datetime import datetime
<<<<<<< HEAD
from comm.communications import Communicator
=======
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QStackedLayout, QListWidget
)
>>>>>>> 48e13b9fd59b53a0548ed82cb4c72d47ed2e6f8c

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.crypto import (
    generate_rsa_keypair, load_private_key, load_public_key_from_file,
    generate_aes_key, encrypt_message_with_aes, decrypt_message_with_aes,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
)
from core.auth import register_user, login_user

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 6000
PEER_IP = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
PEER_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 6001
USER_DIR = os.path.join("..", "users")
KEY_DIR = os.path.join("..", "keys")

class ChatApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NeTalk (Encrypted P2P)")
        self.setGeometry(100, 100, 700, 500)

        self.nickname = ""
        self.private_key = None
        self.peer_public_key = None
        self.active_peer = ""
        
        

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
        threading.Thread(target=self.listen, daemon=True).start()

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
        layout = QHBoxLayout()

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

        right_side = QVBoxLayout()
        right_side.addWidget(self.chat_status)
        right_side.addWidget(self.chat_area)
        right_side.addWidget(self.input_box)
        right_side.addWidget(self.send_button)

        layout.addWidget(self.friends_list, 1)
        layout.addLayout(right_side, 4)

        self.chat_widget.setLayout(layout)
        self.layout.addWidget(self.chat_widget)

    def register_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()
        success, message = register_user(name, password)
        self.status_label.setText(message)

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
            self.nickname = name
            self.populate_friends()
            self.layout.setCurrentWidget(self.chat_widget)

    def populate_friends(self):
        self.friends_list.clear()
        for filename in os.listdir(USER_DIR):
            if filename.endswith(".json"):
                friend_name = filename.replace(".json", "")
                if friend_name != self.nickname:
                    self.friends_list.addItem(friend_name)

    def select_friend(self, item):
        peer_name = item.text()
        key_path = os.path.join(KEY_DIR, f"{peer_name}_public.pem")
        if os.path.exists(key_path):
            self.peer_public_key = load_public_key_from_file(key_path)
            self.chat_status.setText(f"Chatting with {peer_name}")
            self.active_peer = peer_name
            self.input_box.setEnabled(True)
            self.send_button.setEnabled(True)
        else:
            self.chat_status.setText("Peer public key not found.")
            self.peer_public_key = None
            self.input_box.setEnabled(False)
            self.send_button.setEnabled(False)

    def listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', LISTEN_PORT))
        s.listen()
        print(f"[Listening on port {LISTEN_PORT}]")
        while True:
            conn, addr = s.accept()
            data = conn.recv(4096)
            try:
                key_size = int.from_bytes(data[:4], byteorder='big')
                encrypted_key = data[4:4+key_size]
                encrypted_msg = data[4+key_size:]
                aes_key = decrypt_aes_key_with_rsa(self.private_key, encrypted_key)
                message = decrypt_message_with_aes(aes_key, encrypted_msg)
                sender, content = message.split(":", 1)
                timestamp = datetime.now().strftime("%I:%M %p")
                self.chat_area.append(f"[{timestamp}] {sender}: {content}")
            except Exception as e:
                self.chat_area.append("Encrypted or invalid message.")
                print(f"[ERROR] {e}")
            conn.close()

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
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((PEER_IP, PEER_PORT))
            s.send(full_packet)
            s.close()
            timestamp = datetime.now().strftime("%I:%M %p")
            self.chat_area.append(f"[{timestamp}] You: {msg}")
            self.input_box.clear()
        except ConnectionRefusedError:
            self.chat_area.append("Friend not connected.")
        except Exception as e:
            self.chat_area.append(f"Failed to send message: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec_())
