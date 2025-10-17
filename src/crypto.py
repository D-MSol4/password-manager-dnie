from cryptography.fernet import Fernet
import base64
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

try:
    from zeroize import zeroize1
except ImportError:
    print("WARNING: zeroize not available")
    def zeroize1(data):
        """Fallback when zeroize not available"""
        pass

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
    xor_key = bytearray(a ^ b for a, b in zip(dnie_key, password_key))
    try:
        # Apply HKDF to ensure proper key distribution
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'dnie-password-combination',
            info=b'two-factor-database-key',
            backend=default_backend()
        )
    
        combined_key = kdf.derive(bytes(xor_key))
        return combined_key
    finally:
        zeroize1(xor_key)
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
    master_wrapping_key = bytearray(combine_keys(dnie_wrapping_key, password_derived_key))
    
    try:
        # Create Fernet cipher with master wrapping key
        fernet_key = bytearray(base64.urlsafe_b64encode(bytes(master_wrapping_key)))
        
        try:
            f = Fernet(bytes(fernet_key))
            
            # Encrypt k_db
            wrapped = f.encrypt(k_db)
            
            return wrapped
        finally:
            # Limpiar fernet_key con zeroize
            zeroize1(fernet_key)
            del fernet_key, f
    finally:
        # Limpiar master_wrapping_key con zeroize
        zeroize1(master_wrapping_key)
        del master_wrapping_key


def unwrap_database_key(wrapped_k_db, dnie_wrapping_key, password_derived_key):
    """
    Unwrap (decrypt) the database key using DNIe + password.
    """
    # Combine DNIe key and password key (same as wrapping)
    master_wrapping_key = bytearray(combine_keys(dnie_wrapping_key, password_derived_key))
    
    try:
        # Create Fernet cipher with master wrapping key
        fernet_key = bytearray(base64.urlsafe_b64encode(bytes(master_wrapping_key)))
        
        try:
            f = Fernet(bytes(fernet_key))
            
            # Decrypt k_db
            k_db = f.decrypt(wrapped_k_db)
            
            return k_db
        finally:
            # Limpiar fernet_key con zeroize
            zeroize1(fernet_key)
            del fernet_key, f
    finally:
        # Limpiar master_wrapping_key con zeroize
        zeroize1(master_wrapping_key)
        del master_wrapping_key