from cryptography.fernet import Fernet
import json
# Argon2id for password-based KDF
from argon2.low_level import Type, hash_secret_raw

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from a password using Argon2id (memory-hard).
    The returned bytes are fed to base64.urlsafe_b64encode in main.py for Fernet.
    """
    password_bytes = password.encode("utf-8")
    # Reasonable default parameters; tune to environment:
    # - time_cost: iterations (3–6 typical)
    # - memory_cost: KiB (e.g., 65536 = 64 MiB)
    # - parallelism: CPU lanes (match CPU cores if desired)
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=65536,   # 64 MiB
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )
    return key

def generate_database_key():
    """Generate a random database key for Fernet encryption"""
    return Fernet.generate_key()

def encrypt_database(data, key):
    """
    Encrypt the password database (Python dict) using Fernet symmetric encryption.
    Returns encrypted bytes.
    """
    f = Fernet(key)
    json_data = json.dumps(data).encode()  # Convert dict to JSON bytes
    encrypted = f.encrypt(json_data)
    return encrypted

def decrypt_database(encrypted_data, key):
    """
    Decrypt the password database using Fernet symmetric encryption.
    Returns the original Python dict.
    """
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    data = json.loads(decrypted_data.decode())
    return data
