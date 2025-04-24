from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import os

KEYS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'keys'))


def generate_rsa_keypair(nickname):
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_path = os.path.join(KEYS_DIR, f"{nickname}_private.pem")
    public_path = os.path.join(KEYS_DIR, f"{nickname}_public.pem")

    # Save private key
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    public_key = private_key.public_key()
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_path, public_path


def load_private_key(nickname):
    with open(os.path.join(KEYS_DIR, f"{nickname}_private.pem"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key_from_file(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def generate_aes_key():
    return Fernet.generate_key()

def encrypt_message_with_aes(aes_key, message):
    return Fernet(aes_key).encrypt(message.encode())

def decrypt_message_with_aes(aes_key, encrypted_message):
    return Fernet(aes_key).decrypt(encrypted_message).decode()

def encrypt_aes_key_with_rsa(public_key, aes_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def decrypt_aes_key_with_rsa(private_key, encrypted_aes_key):
    return private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
