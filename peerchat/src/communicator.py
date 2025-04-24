# peerchat/comm/communicator.py
import socket
import threading

class Communicator:
    def __init__(self, listen_port, key_manager=None):
        self.listen_port = listen_port
        self.key_manager = key_manager
        self.running = True

    def start_listener(self, handler_callback):
        def listen():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.bind(('0.0.0.0', self.listen_port))
                server.listen()
                print(f"[COMM] Listening on port {self.listen_port}...")

                while self.running:
                    try:
                        conn, addr = server.accept()
                        with conn:
                            data = conn.recv(8192)
                            if data:
                                handler_callback(data)
                    except Exception as e:
                        print(f"[COMM] Listener error: {e}")

        thread = threading.Thread(target=listen, daemon=True)
        thread.start()

    def stop(self):
        self.running = False
