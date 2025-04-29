import hashlib
import socket
import threading
import json

class DHTNode:
    def __init__(self, username, ip, port):
        self.username = username
        self.id = self.hash_username(username)
        self.ip = ip
        self.port = port

        self.routing_table = {}  # key: peer_id, value: (ip, port)
        self.data_store = {}     # key: hash of username, value: data

        self.server_thread = threading.Thread(target=self.listen_for_dht_messages)
        self.server_thread.daemon = True
        self.server_thread.start()

    def hash_username(self, name):
        return hashlib.sha1(name.encode()).hexdigest()[:8]

    def xor_distance(self, a, b):
        return int(a, 16) ^ int(b, 16)

    def find_closest_peer(self, key_hash):
        """Find peer whose ID is closest to the key hash."""
        if not self.routing_table:
            return self.id
        return min(self.routing_table.keys(), key=lambda peer_id: self.xor_distance(peer_id, key_hash))

    def get_own_peer_id(self):
        """Return my hashed username ID."""
        return self.id

    def listen_for_dht_messages(self):
        """Start UDP server to handle PUT and GET requests."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, self.port))
        print(f"[DHTNode] Listening on {self.ip}:{self.port} for DHT messages...")

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                message = json.loads(data.decode())
                self.handle_message(message, addr, sock)
            except Exception as e:
                print(f"[DHTNode] Error receiving DHT message: {e}")

    def handle_message(self, message, addr, sock):
        msg_type = message.get("type")
        key = message.get("key")

        if msg_type == "PUT":
            self.data_store[key] = message["value"]
            print(f"[DHTNode] Stored {key} → {message['value']}")

        elif msg_type == "GET":
            value = self.data_store.get(key)
            reply = {
                "type": "GET_RESPONSE",
                "key": key,
                "value": value
            }
            sock.sendto(json.dumps(reply).encode(), addr)
            print(f"[DHTNode] GET served for {key}: {value}")

    def put(self, username, value):
        """Store a (username -> value) mapping in the DHT."""
        key_hash = self.hash_username(username)
        responsible_peer = self.find_closest_peer(key_hash)

        if responsible_peer == self.get_own_peer_id():
            self.data_store[key_hash] = value
            print(f"[DHTNode] Stored {username} locally.")
        else:
            ip, port = self.routing_table.get(responsible_peer, (None, None))
            if ip:
                msg = {
                    "type": "PUT",
                    "key": key_hash,
                    "value": value
                }
                self.send_udp(ip, port, msg)
                print(f"[DHTNode] Sent PUT for {username} to {ip}:{port}")
            else:
                print(f"[DHTNode] No peer found for {username}, storing locally.")
                self.data_store[key_hash] = value

    def get(self, username):
        """Retrieve value for username from DHT."""
        key_hash = self.hash_username(username)
        responsible_peer = self.find_closest_peer(key_hash)

        if responsible_peer == self.get_own_peer_id():
            return self.data_store.get(key_hash)
        else:
            ip, port = self.routing_table.get(responsible_peer, (None, None))
            if ip:
                msg = {
                    "type": "GET",
                    "key": key_hash
                }
                return self.query_udp(ip, port, msg)
            else:
                print(f"[DHTNode] No peer found for {username}.")
                return None

    def send_udp(self, ip, port, msg):
        """Helper to send a UDP message."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(msg).encode(), (ip, port))
            sock.close()
        except Exception as e:
            print(f"[DHTNode] Failed to send UDP to {ip}:{port}: {e}")

    def query_udp(self, ip, port, msg):
        """Helper to send a UDP query and wait for a response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(json.dumps(msg).encode(), (ip, port))

            response, _ = sock.recvfrom(4096)
            sock.close()

            data = json.loads(response.decode())
            return data.get("value")
        except Exception as e:
            print(f"[DHTNode] UDP query failed: {e}")
            return None

    def add_peer(self, peer_username, ip, port):
        """Add a peer to my routing table."""
        peer_id = self.hash_username(peer_username)
        self.routing_table[peer_id] = (ip, port)
        print(f"[DHTNode] Added peer {peer_username} at {ip}:{port}")
