import asyncio
import json
import threading
import socket
from bitbootpy.dht_manager import DHTManager

class DHTService:
    def __init__(self, username, ip, port, peer_registry_path="peer_registry.json", bootstrap_nodes=None):
        self.bootstrap_nodes = bootstrap_nodes
        self.username = username
        self.ip = ip
        self.port = port
        self.peer_registry_path = peer_registry_path
        self.loop = asyncio.new_event_loop()
        self.dht_manager = None
        self.running = False
        self.peer_list = {}

    def start(self):
        self.running = True
        threading.Thread(target=self._run_loop, daemon=True).start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._init_dht())

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    async def _init_dht(self):
        self.dht_manager = await DHTManager.create(bootstrap_nodes=self.bootstrap_nodes)
        local_ip = self.get_local_ip()
        peer_info = {
            "public_ip": self.ip,
            "local_ip": local_ip,
            "listen_port": self.port
        }
        await self.dht_manager._server.set(self.username, json.dumps(peer_info))
        print(f"[DHT] Stored {self.username} with: {peer_info}")


        # Register username in online users list
        existing_users_json = await self.dht_manager._server.get("__online_users__")
        existing_users = json.loads(existing_users_json) if existing_users_json else []

        if self.username not in existing_users:
            existing_users.append(self.username)

        await self.dht_manager._server.set("__online_users__", json.dumps(existing_users))

        await self._update_peers_forever()

    async def _update_peers_forever(self):
        while self.running:
            await self._update_peer_registry()
            await asyncio.sleep(10)  # every 10 seconds

    async def _update_peer_registry(self):
        keys_json = await self.dht_manager._server.get("__online_users__")
        keys = json.loads(keys_json) if keys_json else []
        print(f"[DEBUG] Raw online users JSON: {keys_json}")

        registry = {}
        for key in keys:
            if key == self.username:
                continue
            value = await asyncio.wait_for(self.dht_manager._server.get(key), timeout=3)
            if value:
                try:
                    data = json.loads(value)
                    registry[key] = {
                        "public_ip": data.get("public_ip", ""),
                        "local_ip": data.get("local_ip", ""),
                        "listen_port": data.get("listen_port", 6000)
                    }
                except json.JSONDecodeError:
                    # Fallback for old-format entries ("ip:port")
                    print(f"[WARN] Malformed DHT data for {key}: {value}")
                    ip, port = value.split(":")
                    registry[key] = {
                        "public_ip": ip,
                        "local_ip": "",
                        "listen_port": int(port)
                    }
                except asyncio.TimeoutError:
                    print(f"[DHT] Timeout while looking up key: {key}")
                except Exception as e:
                    print(f"[DHT] Error looking up {key}: {e}")

        self.peer_list = registry
        with open(self.peer_registry_path, "w") as f:
            json.dump(registry, f, indent=4)


    def get_online_users(self):
        return list(self.peer_list.keys())
