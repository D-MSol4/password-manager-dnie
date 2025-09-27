from cryptography.fernet import Fernet
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from a password using HKDF."""
    password_bytes = password.encode('utf-8')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'password-manager-key-derivation',
        backend=default_backend()
    )
    derived_key = hkdf.derive(password_bytes)
    return derived_key


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

def derive_key_from_signature(signature, salt):
    """
    Derive a symmetric key from the smart card signature and salt,
    using HKDF with SHA256.
    Returns a 32-byte key suitable for Fernet.
    """
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'password-manager-key-derivation'
    )
    derived_key = kdf.derive(signature)
    return derived_key
