import os
import json
import socket

from core.crypto import load_public_key_from_file

from PyQt5.QtWidgets import QMessageBox

KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "keys"))
FRIENDS_DIR = os.path.join(os.path.dirname(__file__), "friends")
FRIENDS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "friends", "friends.json"))
PEER_REGISTRY = os.path.join(os.path.dirname(__file__), "peer_registry.json")

def does_user_exist(target_name):
    return os.path.exists(os.path.join("users", f"{target_name}.json"))

def handle_friend_request(data, key_manager, update_ui_callback=None):
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

    # Send friend request BACK if not mutual
    if sender not in friends:
        pubkey_path = os.path.join(KEYS_DIR, f"{key_manager.username}_public.pem")
        if os.path.exists(pubkey_path):
            with open(pubkey_path, "r") as f:
                my_pubkey = f.read()

            # Find sender IP and port
            sender_info = registry.get(sender, {})
            sender_ip = sender_info.get("local_ip") or sender_info.get("public_ip", "127.0.0.1")
            sender_port = sender_info.get("listen_port", 6000)

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((sender_ip, sender_port))
                    s.sendall(json.dumps({
                        "type": "FRIEND_REQUEST",
                        "from": key_manager.username,
                        "pubkey": my_pubkey,
                        "known_peers": registry  # Optionally send known peers
                    }).encode())
                print(f"[FRIEND REQUEST] Sent friend request back to {sender}")
            except Exception as e:
                print(f"[FRIEND REQUEST] Failed to send friend request back: {e}")
