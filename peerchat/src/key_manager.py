import os
import json

KEY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "keys"))
FRIENDS_DIR = os.path.join(os.path.dirname(__file__), "friends")

class KeyManager:
    def __init__(self, username):
        self.username = username
        self.keys_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "keys"))

        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)

    def get_friend_key(self, friend_name):
        pubkey_path = os.path.join(self.keys_dir, f"{friend_name}_public.pem")
        if os.path.exists(pubkey_path):
            with open(pubkey_path, "rb") as f:
                return f.read()
        return None

    def list_friends(self):
        #list all public keys in the keys folder
        return [
            f.replace("_public.pem", "")
            for f in os.listdir(self.keys_dir)
            if f.endswith("_public.pem") and f != f"{self.username}_public.pem"
        ]

