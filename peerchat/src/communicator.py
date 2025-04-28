
import socket
import threading

class Communicator:
    def __init__(self, listen_port, on_receive_callback=None):
        self.listen_port = listen_port
        self.on_receive_callback = on_receive_callback
        self.running = False
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('', listen_port))

    def start_listener(self):
        self.running = True
        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()

    def _listen(self):
        self.server_socket.listen()
        print(f"[TCP] Listening on port {self.listen_port}...")
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"[TCP] Listen error: {e}")

    def _handle_connection(self, conn, addr):
        with conn:
            try:
                data = conn.recv(4096)
                if data and self.on_receive_callback:
                    self.on_receive_callback(data, addr)
            except Exception as e:
                print(f"[TCP] Connection error: {e}")

    def send_message(self, data: bytes, peer_ip: str, peer_port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((peer_ip, peer_port))
            s.sendall(data)
            s.close()
        except Exception as e:
            print(f"[TCP] Send error: {e}")

    def stop(self):
        self.running = False
        self.server_socket.close()