import socket
import threading

class CommunicatorUDP:
    def __init__(self, listen_port, on_receive_callback=None):
        self.listen_port = listen_port
        self.on_receive_callback = on_receive_callback
        self.running = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', listen_port))

    def start_listener(self, on_receive_callback=None):
        if on_receive_callback:
            self.on_receive_callback = on_receive_callback
        self.running = True
        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()


    def _listen(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if self.on_receive_callback:
                    self.on_receive_callback(data, addr)
            except Exception as e:
                print(f"[UDP] Listen error: {e}")

    def send_message(self, data: bytes, peer_ip: str, peer_port: int):
        try:
            self.sock.sendto(data, (peer_ip, peer_port))
        except Exception as e:
            print(f"[UDP] Send error: {e}")

    def stop(self):
        self.running = False
        self.sock.close()