# save_key.py
from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open("shared.key", "wb") as f:
    f.write(key)

print("🔑 Key generated and saved to shared.key")

