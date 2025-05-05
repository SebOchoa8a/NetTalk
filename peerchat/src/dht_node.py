import socket
import threading
import json
import hashlib
import time

class DHTNode:
    def __init__(self, username, ip, port, on_peer_discovered=None):
        self.username = username
        self.id = self.hash_username(username)
        self.ip = ip
        self.port = port
        self.on_peer_discovered = on_peer_discovered

        self.discovered_peers = set()
        self.routing_table = {}  # peer_id -> (ip, port, username)
        self.data_store = {}     # key_hash -> peer info

        threading.Thread(target=self.listen_for_messages, daemon=True).start()
        print(f"[DHTNode] Listening on {self.ip}:{self.port} for DHT messages")

    def hash_username(self, name):
        return hashlib.sha1(name.encode()).hexdigest()[:8]

    def listen_for_messages(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, self.port))

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                msg = json.loads(data.decode())
                self.handle_message(msg, addr, sock)
            except Exception as e:
                print(f"[DHTNode] Error handling message: {e}")

    def handle_message(self, msg, addr, sock):
        msg_type = msg.get("type")

        if msg_type == "HELLO":
            username = msg.get("from")
            ip = msg.get("ip")
            port = msg.get("port")

            self.add_peer(username, ip, port)

            # Store peer info
            key_hash = self.hash_username(username)
            self.data_store[key_hash] = {"username": username, "ip": ip, "port": port}

            if self.on_peer_discovered:
                self.on_peer_discovered(username)

            # Respond with HELLO
            response = {
                "type": "HELLO",
                "from": self.username,
                "ip": self.ip,
                "port": self.port
            }
            sock.sendto(json.dumps(response).encode(), addr)
            print(f"[DHTNode] HELLO from {username} stored and acknowledged")
            
            self.discovered_peers.add(username)

        elif msg_type == "GET_PEERS":
            response = {
                "type": "PEERS_LIST",
                "peers": list(self.data_store.values())
            }
            sock.sendto(json.dumps(response).encode(), addr)

    def broadcast_hello(self):
        for _, (ip, port, _) in self.routing_table.items():
            msg = {
                "type": "HELLO",
                "from": self.username,
                "ip": self.ip,
                "port": self.port
            }
            self.send_udp(ip, port, msg)

    def send_hello(self, to_username, to_ip, to_port):
        if to_username in self.discovered_peers:
            return  # Already discovered, don't send again

        msg = {
            "type": "HELLO",
            "from": self.username,
            "ip": self.ip,
            "port": self.port
        }
        print(f"[DHTNode] Sending HELLO to {to_username} at {to_ip}:{to_port}")
        self.send_udp(to_ip, to_port, msg)

    def schedule_hello(self, to_username, to_ip, to_port):
        def retry():
            while to_username not in self.discovered_peers:
                self.send_hello(to_username, to_ip, to_port)
                time.sleep(5)  # Retry every 5 seconds

        threading.Thread(target=retry, daemon=True).start()

    def send_udp(self, ip, port, msg):
        try:
            print(f"[DHTNode] Sending UDP to {ip}:{port} → {msg}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(msg).encode(), (ip, port))
            sock.close()
        except Exception as e:
            print(f"[DHTNode] Failed to send UDP: {e}")


    def add_peer(self, username, ip, port):
        peer_id = self.hash_username(username)
        self.routing_table[peer_id] = (ip, port, username)
        print(f"[DHTNode] Added peer {username} at {ip}:{port}")

    def get_peer_info(self, username):
        key_hash = self.hash_username(username)
        return self.data_store.get(key_hash)

    def get_all_known_peers(self):
        return [info["username"] for info in self.data_store.values() if info["username"] != self.username]
