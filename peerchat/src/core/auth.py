# core/auth.py

import hashlib
import json
import os

USER_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'users'))


# Ensure users/ exists
if not os.path.exists(USER_FOLDER):
    os.makedirs(USER_FOLDER)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def user_file(nickname):
    return os.path.join(USER_FOLDER, f"{nickname}.json")

def register_user(nickname, password):
    if os.path.exists(user_file(nickname)):
        return False, "User already exists."

    user_data = {
        "nickname": nickname,
        "password_hash": hash_password(password)
    }

    with open(user_file(nickname), "w") as f:
        json.dump(user_data, f)

    return True, "User registered successfully."

def login_user(nickname, password):
    path = user_file(nickname)
    if not os.path.exists(path):
        return False, "User does not exist."

    with open(path, "r") as f:
        user_data = json.load(f)

    if hash_password(password) == user_data["password_hash"]:
        return True, "Login successful."
    else:
        return False, "Incorrect password."
