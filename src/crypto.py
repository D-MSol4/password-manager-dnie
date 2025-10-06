from cryptography.fernet import Fernet
import base64
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from a password using Argon2id (memory-hard).
    The returned bytes are fed to base64.urlsafe_b64encode in main.py for Fernet.
    """
    # Reasonable default parameters; tune to environment:
    # - time_cost: iterations (3–6 typical)
    # - memory_cost: KiB (e.g., 65536 = 64 MiB)
    # - parallelism: CPU lanes (match CPU cores if desired)
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,   # 64 MiB
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )
    return key
    

def combine_keys(dnie_key, password_key):
    """
    Combine DNIe-derived key and password-derived key into single database key.
    Uses XOR + HKDF for proper key combination.
    
    Args:
        dnie_key: 32-byte key from DNIe signature
        password_key: 32-byte key from password via Argon2
    
    Returns:
        bytes: 32-byte combined key
    """
    # XOR the two keys
    xor_key = bytes(a ^ b for a, b in zip(dnie_key, password_key))
    try:
        # Apply HKDF to ensure proper key distribution
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'dnie-password-combination',
            info=b'two-factor-database-key',
            backend=default_backend()
        )
    
        combined_key = kdf.derive(xor_key)
        return combined_key
    finally:
        del xor_key  # Ensure XOR key is deleted from memory

def wrap_database_key(k_db, dnie_wrapping_key, password_derived_key):
    """
    Wrap (encrypt) the random database key using DNIe + password.
    
    Args:
        k_db: 32-byte random database key (Fernet key)
        dnie_wrapping_key: 32-byte key from DNIe signature
        password_derived_key: 32-byte key from password (Argon2)
    
    Returns:
        bytes: Encrypted k_db
    """
    # Combine DNIe key and password key
    master_wrapping_key = combine_keys(dnie_wrapping_key, password_derived_key)
    
    # Create Fernet cipher with master wrapping key
    fernet_key = base64.urlsafe_b64encode(master_wrapping_key)
    del master_wrapping_key  # Remove combined key from memory

    f = Fernet(fernet_key)
    del fernet_key  # Remove Fernet key from memory

    # Encrypt k_db
    wrapped = f.encrypt(k_db)
    del f # Remove Fernet instance from memory

    return wrapped


def unwrap_database_key(wrapped_k_db, dnie_wrapping_key, password_derived_key):
    """
    Unwrap (decrypt) the database key using DNIe + password.
    
    Args:
        wrapped_k_db: Encrypted database key
        dnie_wrapping_key: 32-byte key from DNIe signature
        password_derived_key: 32-byte key from password (Argon2)
    
    Returns:
        bytes: Decrypted 32-byte database key
    """
    
    # Combine DNIe key and password key (same as wrapping)
    master_wrapping_key = combine_keys(dnie_wrapping_key, password_derived_key)
    
    # Create Fernet cipher with master wrapping key
    fernet_key = base64.urlsafe_b64encode(master_wrapping_key)
    del master_wrapping_key  # Remove combined key from memory

    f = Fernet(fernet_key)
    del fernet_key  # Remove Fernet key from memory

    # Decrypt k_db
    k_db = f.decrypt(wrapped_k_db)
    del f  # Remove Fernet instance from memory
    
    return k_db