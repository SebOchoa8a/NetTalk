import socket
import threading
import os

# Runtime peer info: this should come from your actual DHT/session
PEER_RUNTIME_INFO = {
    # Example: 'test2': {'ip': '127.0.0.1', 'port': 7000}
}

def send_file_to_peer(filepath, peer_nickname):
    """Send a file to a peer over TCP."""
    if peer_nickname not in PEER_RUNTIME_INFO:
        print(f"[!] No peer info for {peer_nickname}")
        return

    peer_ip = PEER_RUNTIME_INFO[peer_nickname]["ip"]
    peer_port = PEER_RUNTIME_INFO[peer_nickname]["port"]

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((peer_ip, peer_port))
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)

            s.send(f"{filename}:{filesize}".encode())

            with open(filepath, "rb") as f:
                while chunk := f.read(1024):
                    s.send(chunk)

        print(f"[✓] Sent {filename} to {peer_nickname}")
    except Exception as e:
        print(f"[!] File send failed: {e}")

def start_file_receiver_thread(nickname, port, save_folder="received_files"):
    """Start a thread to listen for incoming files."""
    os.makedirs(save_folder, exist_ok=True)

    def listener():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(('', port))
            server.listen(5)
            print(f"[{nickname}] File receiver on port {port}")

            while True:
                conn, addr = server.accept()
                with conn:
                    meta = conn.recv(1024).decode()
                    filename, filesize = meta.split(":")
                    filepath = os.path.join(save_folder, f"{nickname}__{filename}")

                    with open(filepath, "wb") as f:
                        received = 0
                        while received < int(filesize):
                            chunk = conn.recv(1024)
                            if not chunk:
                                break
                            f.write(chunk)
                            received += len(chunk)

                    print(f"[{nickname}] Received {filename} from {addr[0]}")

    threading.Thread(target=listener, daemon=True).start()