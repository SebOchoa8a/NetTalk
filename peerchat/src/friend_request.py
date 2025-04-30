import os
import json

KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),"keys"))
FRIENDS_DIR = os.path.join(os.path.dirname(__file__), "friends")
FRIENDS_FILE = os.path.join(FRIENDS_DIR, "friends.json")

def handle_friend_request(data, key_manager, dht=None):
    sender = data["from"]
    pubkey_pem = data["pubkey"]

    print(f"[FRIEND REQUEST] {sender} wants to connect.")
    os.makedirs(KEYS_DIR, exist_ok=True)

    pem_path = os.path.join(KEYS_DIR, f"{sender}_public.pem")
    with open(pem_path, "w") as f:
        f.write(pubkey_pem)
    print(f"[FRIEND REQUEST] Saved public key for {sender} at {pem_path}")

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

    # NEW: Register in DHT
    if dht:
        peer_ip = data.get("dht_ip")
        peer_port = data.get("dht_port")
        if peer_ip and peer_port:
            dht.add_peer(sender, peer_ip, peer_port)
            dht.put(sender, {
                "ip": peer_ip,
                "port": peer_port
            })
            print(f"[FRIEND REQUEST] Registered {sender} in DHT with {peer_ip}:{peer_port}")

