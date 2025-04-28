import os
import json

from PyQt5.QtWidgets import QMessageBox

KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "keys"))
FRIENDS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "friends", "friends.json"))

def does_user_exist(target_name):
    return os.path.exists(os.path.join("..", "users", f"{target_name}.json"))

def handle_friend_request(data, key_manager, parent_widget=None, chat_gui=None):
    sender = data["from"]
    pubkey_pem = data["pubkey"]

    print(f"[FRIEND REQUEST] {sender} wants to connect.")

    accept = True
    if parent_widget:
        reply = QMessageBox.question(
            parent_widget,
            "New Friend Request",
            f"{sender} wants to add you as a friend. Accept?",
            QMessageBox.Yes | QMessageBox.No
        )
        accept = (reply == QMessageBox.Yes)

    if not accept:
        print(f"[FRIEND REQUEST] Declined friend request from {sender}")
        return

    # Save sender's public key
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

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

    #VERY IMPORTANT: Tell GUI to refresh friends
    if chat_gui:
        chat_gui.populate_friends()
