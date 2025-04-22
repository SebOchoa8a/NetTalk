# save_key.py
from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open("shared.key", "wb") as f:
    f.write(key)

<<<<<<< HEAD
print("Key generated and saved to shared.key")
=======
print(" Key generated and saved to shared.key")
>>>>>>> 48e13b9fd59b53a0548ed82cb4c72d47ed2e6f8c

