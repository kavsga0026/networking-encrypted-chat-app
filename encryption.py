import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def get_key(secret: str) -> bytes:
    """Derives a 16-byte AES key from a shared secret using SHA-256."""
    return hashlib.sha256(secret.encode()).digest()[:16]  # AES-128 bit key

def encrypt_message(message: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_message(encoded_msg: str, key: bytes) -> str:
    raw = base64.b64decode(encoded_msg)
    nonce = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()
