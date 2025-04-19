import socket
import threading
import sys
from cryptography.fernet import Fernet

# Get ports and IP from command line
LISTEN_PORT = int(sys.argv[1])
FRIEND_IP = sys.argv[2]
FRIEND_PORT = int(sys.argv[3])

# Ask for your nickname
nickname = input("Enter your nickname: ")

# Load shared encryption key
with open("shared.key", "rb") as f:
    key = f.read()
cipher = Fernet(key)

# 👂 Listener
def listen():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', LISTEN_PORT))
    s.listen()
    print(f"[Listening on port {LISTEN_PORT}]")

    while True:
        conn, addr = s.accept()
        data = conn.recv(4096)
        try:
            decrypted = cipher.decrypt(data).decode()
            sender_name, message = decrypted.split(":", 1)
            print(f"\n Message from {sender_name}: {message}")
        except Exception as e:
            print(f"\n Failed to decrypt/parse message: {e}")
        conn.close()

# 📤 Sender
def send_message():
    while True:
        msg = input("Type a message: ")
        full_msg = f"{nickname}:{msg}"  # Format: nickname:message
        encrypted = cipher.encrypt(full_msg.encode())

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((FRIEND_IP, FRIEND_PORT))
            s.send(encrypted)
            s.close()
        except Exception as e:
            print(f" Failed to send: {e}")

# Start it up
threading.Thread(target=listen, daemon=True).start()
send_message()
