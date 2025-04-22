import sys
import threading
import socket
import os
from datetime import datetime
from comm.communications import Communicator

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel
)

from core.crypto import (
    generate_rsa_keypair, load_private_key, load_public_key_from_file,
    generate_aes_key, encrypt_message_with_aes, decrypt_message_with_aes,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
)

from core.auth import register_user, login_user

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 6000
PEER_IP = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
PEER_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 6001

class ChatApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("P2P Chat (Encrypted)")
        self.setGeometry(100, 100, 600, 500)

        self.nickname = ""
        self.private_key = None
        self.peer_public_key = None

        self.nickname_input = QLineEdit()
        self.nickname_input.setPlaceholderText("Enter your nickname")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.peer_nickname_input = QLineEdit()
        self.peer_nickname_input.setPlaceholderText("Enter peer nickname")

        self.status_label = QLabel("")

        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.register_user)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login_user)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("Type a message...")
        self.input_box.returnPressed.connect(self.send_message)
        self.input_box.setEnabled(False)

        self.send_button = QPushButton("Send")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Your Nickname:"))
        layout.addWidget(self.nickname_input)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_input)
        layout.addWidget(QLabel("Peer Nickname:"))
        layout.addWidget(self.peer_nickname_input)
        layout.addWidget(self.register_button)
        layout.addWidget(self.login_button)
        layout.addWidget(self.status_label)
        layout.addWidget(QLabel("Chat:"))
        layout.addWidget(self.chat_area)
        layout.addWidget(self.input_box)
        layout.addWidget(self.send_button)

        self.setLayout(layout)
        threading.Thread(target=self.listen, daemon=True).start()

    def register_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()
        success, message = register_user(name, password)
        self.status_label.setText(message)

    def login_user(self):
        name = self.nickname_input.text()
        password = self.password_input.text()
        peer_name = self.peer_nickname_input.text()

        if not name or not peer_name:
            self.status_label.setText(" Enter your and your peer's nickname.")
            return

        private_path = os.path.join("..", "keys", f"{name}_private.pem")
        public_path = os.path.join("..", "keys", f"{name}_public.pem")

        if not os.path.exists(private_path):
            generate_rsa_keypair(name)

        self.private_key = load_private_key(name)

        # Try to load peer's public key
        peer_key_path = os.path.join("..", "keys", f"{peer_name}_public.pem")
        if not os.path.exists(peer_key_path):
            self.status_label.setText(" Peer public key not found.")
            return

        self.peer_public_key = load_public_key_from_file(peer_key_path)

        success, message = login_user(name, password)
        self.status_label.setText(message)

        if success:
            self.nickname = name
            self.nickname_input.setDisabled(True)
            self.password_input.setDisabled(True)
            self.peer_nickname_input.setDisabled(True)
            self.login_button.setDisabled(True)
            self.register_button.setDisabled(True)
            self.input_box.setEnabled(True)
            self.send_button.setEnabled(True)

    def listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', LISTEN_PORT))
        s.listen()
        print(f"[GUI] Listening on port {LISTEN_PORT}")

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
                self.chat_area.append(" Failed to decrypt message.")
                print(f"[ERROR] {e}")
            conn.close()

    def send_message(self):
        if not self.nickname or not self.peer_public_key:
            self.chat_area.append("You must log in and load peer key first.")
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
        except Exception as e:
            self.chat_area.append(f" Could not send message: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec_())
