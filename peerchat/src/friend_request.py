import json
import os
from core.crypto import load_public_key_from_file
from key_manager import KeyManager

FRIENDS_FILE = os.path.join(os.path.dirname(__file__), "friends", "friends.json")

def load_friends():
    if os.path.exists(FRIENDS_FILE):
        with open(FRIENDS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_friends(friends):
    with open(FRIENDS_FILE, "w") as f:
        json.dump(friends, f, indent=4)

def add_friend_to_file(current_user, friend_name):
    friends = load_friends()
    if current_user not in friends:
        friends[current_user] = []
    if friend_name not in friends[current_user]:
        friends[current_user].append(friend_name)
    save_friends(friends)

def handle_friend_request(data: dict, key_manager: KeyManager, current_user: str):
    sender = data["from"]
    pubkey_pem = data["pubkey"]
    print(f"[FRIEND REQUEST] Received request from {sender}")

    # Add key to manager and persist
    key_manager.add_friend(sender, pubkey_pem)

    # Save to friends.json
    add_friend_to_file(current_user, sender)

    # Save to PEM file for compatibility
    pem_path = os.path.join("..", "keys", f"{sender}_public.pem")
    with open(pem_path, "wb") as f:
        f.write(pubkey_pem.encode())

    print(f"[FRIEND REQUEST] {sender} added as friend.")
