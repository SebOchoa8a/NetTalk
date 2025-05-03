import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "keys"))

class KeyManager:
    def __init__(self, username, dht=None):
        self.username = username
        self.dht = dht  # Reference to DHTNode

        # Ensure key directory exists
        os.makedirs(KEYS_DIR, exist_ok=True)

        # Load own public/private keys
        self.private_key = self._load_private_key()
        self.public_key = self._load_public_key()

    def _load_private_key(self):
        try:
            with open(os.path.join(KEYS_DIR, f"{self.username}_private.pem"), "rb") as key_file:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except Exception as e:
            print(f"[KEY_MANAGER] Failed to load private key: {e}")
            return None

    def _load_public_key(self):
        try:
            with open(os.path.join(KEYS_DIR, f"{self.username}_public.pem"), "rb") as key_file:
                return serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        except Exception as e:
            print(f"[KEY_MANAGER] Failed to load public key: {e}")
            return None

    def save_peer_key(self, peer_name, public_key_pem):
        """Save a peer's public key to a file for local caching (optional)."""
        try:
            path = os.path.join(KEYS_DIR, f"{peer_name}_public.pem")
            with open(path, "w") as f:
                f.write(public_key_pem)
            print(f"[KEY_MANAGER] Saved public key for {peer_name}.")
        except Exception as e:
            print(f"[KEY_MANAGER] Failed to save public key: {e}")

    def get_peer_key(self, peer_name):
        """Return the peer's public key, fetching from DHT if not cached."""
        try:
            # First try to load locally
            path = os.path.join(KEYS_DIR, f"{peer_name}_public.pem")
            if os.path.exists(path):
                with open(path, "rb") as f:
                    return serialization.load_pem_public_key(f.read(), backend=default_backend())

            # Otherwise, fetch from DHT
            if self.dht:
                peer_data = self.dht.get(peer_name)
                if peer_data and "public_key" in peer_data:
                    public_key_pem = peer_data["public_key"]
                    self.save_peer_key(peer_name, public_key_pem)
                    return serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        except Exception as e:
            print(f"[KEY_MANAGER] Failed to get key for {peer_name}: {e}")
        return None

    def list_all_peers(self):
        """Return all peers in the DHT, excluding self."""
        if self.dht:
            return [name for name in self.dht.get_all_known_peers() if name != self.username]
        return []

