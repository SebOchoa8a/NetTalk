import os
import json
from core.crypto import load_public_key_from_file
from cryptography.hazmat.primitives import serialization

KEY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "keys"))
FRIENDS_DIR = os.path.join(os.path.dirname(__file__), "friends")
FRIENDS_FILE = os.path.join(FRIENDS_DIR, "friends.json")

class KeyManager:
    def __init__(self, username):
        self.username = username
        self.friends = {}
        self._load_friends()

    def _load_friends(self):
        if not os.path.exists(FRIENDS_DIR):
            os.makedirs(FRIENDS_DIR)
        if os.path.exists(FRIENDS_FILE):
            with open(FRIENDS_FILE, "r") as f:
                self.friends = json.load(f)
        else:
            self.friends = {}

    def save(self):
        with open(FRIENDS_FILE, "w") as f:
            json.dump(self.friends, f, indent=4)

    def add_friend(self, friend_name, public_key_pem):
        """Store the friend's PEM and write it to disk."""
        pem_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        key_path = os.path.join(KEY_DIR, f"{friend_name}_public.pem")

        with open(key_path, "wb") as f:
            f.write(pem_bytes)

        self.friends.setdefault(self.username, [])
        if friend_name not in self.friends[self.username]:
            self.friends[self.username].append(friend_name)

        self.save()

    def get_friend_key(self, friend_name):
        key_path = os.path.join(KEY_DIR, f"{friend_name}_public.pem")
        if os.path.exists(key_path):
            return load_public_key_from_file(key_path)
        print(f"[KeyManager] Public key not found for {friend_name}")
        return None


    def list_friends(self):
        return self.friends.get(self.username, [])
