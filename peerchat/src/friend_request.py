import os
import json

from PyQt5.QtWidgets import QMessageBox

KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "keys"))
FRIENDS_DIR = os.path.join(os.path.dirname(__file__), "friends")
FRIENDS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "friends", "friends.json"))
PEER_REGISTRY = os.path.join(os.path.dirname(__file__), "peer_registry.json")

def does_user_exist(target_name):
    return os.path.exists(os.path.join("users", f"{target_name}.json"))

def handle_friend_request(data, key_manager):
    sender = data["from"]
    pubkey_pem = data["pubkey"]
    known_peers = data.get("known_peers", {})

    print(f"[FRIEND REQUEST] {sender} wants to connect.")

    os.makedirs(KEYS_DIR, exist_ok=True)

    # Save public key
    pem_path = os.path.join(KEYS_DIR, f"{sender}_public.pem")
    with open(pem_path, "w") as f:
        f.write(pubkey_pem)
    print(f"[FRIEND REQUEST] Saved public key to {pem_path}")

    # Add to friends.json
    if not os.path.exists(FRIENDS_FILE):
        friends = {}
    else:
        with open(FRIENDS_FILE, "r") as f:
            friends = json.load(f)

    friends.setdefault(key_manager.username, [])
    if sender not in friends[key_manager.username]:
        friends[key_manager.username].append(sender)

    with open(FRIENDS_FILE, "w") as f:
        json.dump(friends, f, indent=4)

    print(f"[FRIEND REQUEST] Added {sender} to {key_manager.username}'s friend list.")

    # Merge known peers into peer_registry.json
    if os.path.exists(PEER_REGISTRY):
        with open(PEER_REGISTRY, "r") as f:
            registry = json.load(f)
    else:
        registry = {}

    for peer_name, peer_info in known_peers.items():
        if peer_name not in registry:
            registry[peer_name] = peer_info

    with open(PEER_REGISTRY, "w") as f:
        json.dump(registry, f, indent=4)

    print(f"[FRIEND REQUEST] Updated peer registry with new known peers.")
