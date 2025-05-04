import socket
import threading
import json
import hashlib

class DHTNode:
    def __init__(self, username, ip, port,on_peer_discovered=None):
        self.username = username
        self.id = self.hash_username(username)
        self.ip = ip
        self.port = port
        self.on_peer_discovered = on_peer_discovered

        self.routing_table = {}   # peer_id → (ip, port)
        self.data_store = {}      # hashed_username → {ip, port, public_key}

        self.server_thread = threading.Thread(target=self.listen_for_messages)
        self.server_thread.daemon = True
        self.server_thread.start()

        print(f"[DHTNode] Listening on {self.ip}:{self.port} for DHT messages...")

    def hash_username(self, name):
        return hashlib.sha1(name.encode()).hexdigest()[:8]

    def xor_distance(self, a, b):
        return int(a, 16) ^ int(b, 16)

    def find_closest_peer(self, key_hash):
        if not self.routing_table:
            return self.id
        return min(self.routing_table.keys(), key=lambda pid: self.xor_distance(pid, key_hash))

    def get_own_peer_id(self):
        return self.id

    def listen_for_messages(self):
        print("[DHTNode] Message listener started")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, self.port))

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                decoded = json.loads(data.decode())
                self.handle_message(decoded, addr, sock)
            except Exception as e:
                print(f"[ERROR] DHT listener failed: {e}")

    def handle_message(self, message, addr, sock):
        print(f"[RECEIVED] {self.username} got: {message} from {addr}")
        msg_type = message.get("type")
        key = message.get("key")

        if msg_type == "PUT":
            self.data_store[key] = message["value"]
            print(f"[DHTNode] PUT: Stored key {key} → {message['value']}")

        elif msg_type == "GET":
            value = self.data_store.get(key)
            response = {
                "type": "GET_RESPONSE",
                "key": key,
                "value": value
            }
            sock.sendto(json.dumps(response).encode(), addr)

        elif msg_type == "HELLO":
            from_user = message.get("from")
            ip = message.get("ip")
            port = message.get("port")

            if self.on_peer_discovered:
                self.on_peer_discovered(from_user)

            # Step 1: Add to routing table
            self.add_peer(from_user, ip, port)
            print(f"[DHTNode] {from_user} said hello from {ip}:{port}")

            # Step 2: Store in data_store
            value = {
                "username": from_user,
                "ip": ip,
                "port": port,
                "public_key_path": f"/keys/{from_user}_public.pem"
            }
            key_hash = self.hash_username(from_user)
            self.data_store[key_hash] = value
            print(f"[DHTNode] HELLO → Stored {from_user} at {ip}:{port}")

            response_hello = {
                "type": "HELLO",
                "from": self.username,
                "ip": self.ip,
                "port": self.port
            }
            sock.sendto(json.dumps(response_hello).encode(), addr)
            print(f"[DHTNode] Sent HELLO response to {addr}")


    def put(self, username, value_dict):
        key_hash = self.hash_username(username)
        responsible_peer = self.find_closest_peer(key_hash)

        # Inject the username for retrieval
        value_dict["username"] = username

        # Always store locally to ensure we can serve GET requests
        self.data_store[key_hash] = value_dict
        print(f"[DHTNode] Stored {username} locally.")

        # Forward only if responsible_peer is different
        if responsible_peer != self.get_own_peer_id():
            ip, port = self.routing_table.get(responsible_peer, (None, None))
            if ip:
                msg = {
                    "type": "PUT",
                    "key": key_hash,
                    "value": value_dict
                }
                self.send_udp(ip, port, msg)
                print(f"[DHTNode] Forwarded PUT for {username} to {ip}:{port}")


    def get(self, username):
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
                return None

    def get_peer_public_key(self, username):
        entry = self.get(username)
        return entry.get("public_key") if entry else None

    def get_peer_info(self, username):
        entry = self.get(username)
        if entry:
            return {"ip": entry.get("ip"), "port": entry.get("port")}
        return None

    def send_udp(self, ip, port, msg):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(msg).encode(), (ip, port))
            sock.close()
        except Exception as e:
            print(f"[DHTNode] Failed to send UDP: {e}")

    def query_udp(self, ip, port, msg):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(json.dumps(msg).encode(), (ip, port))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return json.loads(response.decode()).get("value")
        except Exception as e:
            print(f"[DHTNode] UDP query failed: {e}")
            return None

    def add_peer(self, peer_username, ip, port):
        peer_id = self.hash_username(peer_username)
        self.routing_table[peer_id] = (ip, port)
        print(f"[DHTNode] Added peer {peer_username} at {ip}:{port}")

    def get_all_known_peers(self):
        """Return all usernames stored locally (not hashed)"""
        known = []
        for key_hash, data in self.data_store.items():
            for uname in [data.get("username")]:
                if uname and uname != self.username:
                    known.append(uname)
        return known
