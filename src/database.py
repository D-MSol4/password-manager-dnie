import os
import sys
import threading
import shutil
import string
import secrets
import re
import json
import logging
import subprocess
from cryptography.fernet import Fernet

DB_FILENAME = "passwords.db"
BACKUP_FILENAME = "passwords_backup.db"

LOCK = threading.Lock()  # basic concurrency control

# Regex pattern for password validation
password_pattern = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s])[\S]{16,60}$',
    re.UNICODE
)

# Configure secure logging
LOG_FILENAME = 'password_manager.log'
logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def is_valid_password(password: str) -> bool:
    """Validate password matches policy."""
    return bool(password_pattern.match(password))


def is_valid_entry(service, username, password):
    """Validate entry fields:
    - service and username must be non-empty strings,
    - password must match password policy.
    """
    if not (isinstance(service, str) and service.strip()):
        return False
    if not (isinstance(username, str) and username.strip()):
        return False
    if not (isinstance(password, str) and is_valid_password(password)):
        return False
    return True

class EncryptedDatabase:
    """
    Database wrapper that keeps data encrypted in memory.
    Decrypts on-demand for operations, then immediately re-encrypts.
    """
    
    def __init__(self, fernet_key):
        """
        Initialize with encryption key.
        
        Args:
            fernet_key: bytes - Fernet encryption key
        """
        self.fernet_key = fernet_key
        self.encrypted_data = None
        self._load_encrypted()
    
    def _load_encrypted(self):
        """Load encrypted database from disk (stays encrypted)."""
        if os.path.exists(DB_FILENAME):
            with open(DB_FILENAME, 'rb') as f:
                self.encrypted_data = f.read()
        else:
            # New database - create empty encrypted dict
            self.encrypted_data = self._encrypt_db({})
    
    def _encrypt_db(self, db):
        """Encrypt database dict to bytes."""
        fernet = Fernet(self.fernet_key)
        db_bytes = json.dumps(db, indent=2).encode('utf-8')
        encrypted = fernet.encrypt(db_bytes)
        del fernet
        del db_bytes
        return encrypted
    
    def _decrypt_db(self):
        """Decrypt database bytes to dict."""
        fernet = Fernet(self.fernet_key)
        decrypted = fernet.decrypt(self.encrypted_data)
        db = json.loads(decrypted.decode('utf-8'))
        del fernet
        del decrypted
        return db
    
    def _save_encrypted(self):
        """Save encrypted database to disk."""
        with open(DB_FILENAME, 'wb') as f:
            f.write(self.encrypted_data)
        secure_file_permissions(DB_FILENAME)
    
    # === READ OPERATIONS ===
    
    def get_entry(self, service):
        """Get entry for a service (decrypt -> read -> cleanup)."""
        try:
            db = self._decrypt_db()
            entry = db.get(service)
            db.clear()
            del db
            return entry
        except Exception as e:
            logger.error(f"Failed to get entry: {e}")
            return None
    
    def list_services(self):
        """List all service names (decrypt -> list -> cleanup)."""
        try:
            db = self._decrypt_db()
            services = list(db.keys())
            db.clear()
            del db
            return services
        except Exception as e:
            logger.error(f"Failed to list services: {e}")
            return []
    
    def service_exists(self, service):
        """Check if service exists (decrypt -> check -> cleanup)."""
        try:
            db = self._decrypt_db()
            exists = service in db
            db.clear()
            del db
            return exists
        except Exception as e:
            logger.error(f"Failed to check service: {e}")
            return False
    
    # === WRITE OPERATIONS ===
    
    def add_entry(self, service, username, password):
        """Add new entry (decrypt -> modify -> encrypt -> save)."""
        try:
            db = self._decrypt_db()
            
            # Validate
            if not is_valid_entry(service, username, password):
                db.clear()
                del db
                return False
            
            # Add entry
            db[service] = {"username": username, "password": password}
            
            # Re-encrypt and save
            self.encrypted_data = self._encrypt_db(db)
            self._save_encrypted()
            
            # Cleanup
            db.clear()
            del db
            
            return True
        except Exception as e:
            logger.error(f"Failed to add entry: {e}")
            return False
    
    def edit_entry(self, service, username=None, password=None):
        """Edit existing entry (decrypt -> modify -> encrypt -> save)."""
        try:
            db = self._decrypt_db()
            
            # Check exists
            if service not in db:
                db.clear()
                del db
                return False
            
            # Prepare new values
            new_username = username if username is not None else db[service].get('username')
            new_password = password if password is not None else db[service].get('password')
            
            # Validate
            if not is_valid_entry(service, new_username, new_password):
                db.clear()
                del db
                return False
            
            # Update entry
            db[service]['username'] = new_username
            db[service]['password'] = new_password
            
            # Re-encrypt and save
            self.encrypted_data = self._encrypt_db(db)
            self._save_encrypted()
            
            # Cleanup
            db.clear()
            del db
            
            return True
        except Exception as e:
            logger.error(f"Failed to edit entry: {e}")
            return False
    
    def delete_entry(self, service):
        """Delete entry (decrypt -> modify -> encrypt -> save)."""
        try:
            db = self._decrypt_db()
            
            if service not in db:
                db.clear()
                del db
                return False
            
            # Delete entry
            del db[service]
            
            # Re-encrypt and save
            self.encrypted_data = self._encrypt_db(db)
            self._save_encrypted()
            
            # Cleanup
            db.clear()
            del db
            
            return True
        except Exception as e:
            logger.error(f"Failed to delete entry: {e}")
            return False
    
    def reload_from_disk(self):
        """Reload encrypted data from disk (after restore)."""
        self._load_encrypted()
    
    def clear(self):
        """Clear encrypted data from memory."""
        self.encrypted_data = None


def save_database(db, fernet_key):
    """Save database and secure permissions."""
    try:
        with LOCK:
            fernet = Fernet(fernet_key)
            db_bytes = json.dumps(db, indent=2).encode('utf-8')
            encrypted = fernet.encrypt(db_bytes)
            del fernet
            del db_bytes
            
            with open(DB_FILENAME, 'wb') as f:
                f.write(encrypted)
            del encrypted
            # Secure permissions immediately after creation
            secure_file_permissions(DB_FILENAME)
            
            return True
    except Exception:
        logger.error("Failed to save database", exc_info=True)
        return False


def backup_database():
    """Backup database and secure permissions."""
    try:
        with LOCK:
            if not os.path.exists(DB_FILENAME):
                return False
            
            shutil.copy2(DB_FILENAME, BACKUP_FILENAME)
            
            # Secure backup file permissions
            secure_file_permissions(BACKUP_FILENAME)
            
            return True
    except Exception:
        logger.error("Failed to backup database", exc_info=True)
        return False


def restore_database():
    """Restore the database from backup."""
    try:
        with LOCK:
            if os.path.exists(BACKUP_FILENAME):
                shutil.copy2(BACKUP_FILENAME, DB_FILENAME)
                return True
            else:
                return False
    except PermissionError:
        print("Error: Unable to restore backup (permission denied)")
        logger.error("Permission denied restoring backup", exc_info=True)
        return False
    except OSError:
        print("Error: Unable to restore backup (disk error)")
        logger.error("OS error restoring backup", exc_info=True)
        return False
    except Exception as e:
        print("Error: Restore failed")
        logger.error(f"Unexpected error in restore_database: {type(e).__name__}", exc_info=True)
        return False


def destroy_database_files():
    """Permanently delete ALL database-related files using secure deletion."""
    try:
        removed = False
        with LOCK:
            # Define all files to delete
            files_to_delete = [
                DB_FILENAME,           # passwords.db
                BACKUP_FILENAME,       # passwords_backup.db
                "db_salt.bin",         # Salt file
                "wrapped_key.bin"      # Wrapped K_db
            ]
            
            for file_path in files_to_delete:
                if os.path.exists(file_path):
                    if secure_delete(file_path):
                        print(f"Securely deleted {file_path}")
                        removed = True
                    else:
                        print(f"Warning: Could not securely delete {file_path}")
            
            return removed
    
    except PermissionError:
        print("Error: Unable to delete database files (permission denied)")
        logger.error("Permission denied deleting database files", exc_info=True)
        return False
    except OSError:
        print("Error: Unable to delete database files (disk error)")
        logger.error("OS error deleting database files", exc_info=True)
        return False
    except Exception as e:
        print("Error: Failed to delete database files")
        logger.error(f"Unexpected error in destroy_database_files: {type(e).__name__}", exc_info=True)
        return False


def secure_delete(file_path, passes=3):
    """Securely delete a file by overwriting it multiple times with random data before removal."""
    try:
        if not os.path.exists(file_path):
            return False
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Overwrite file multiple times
        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # Finally remove the file
        os.remove(file_path)
        return True
    except Exception as e:
        print(f"Error securely deleting {file_path}: {e}")
        logger.error(f"Failed to securely delete {file_path}", exc_info=True)
        return False

def generate_random_password(length=20):
    """
    Generate a cryptographically secure random password that meets policy requirements.
    
    Requirements:
    - Length: 16-60 characters
    - Must include: uppercase, lowercase, digit, special character
    
    Args:
        length: Desired password length (16-60), default 20
    
    Returns:
        str: Random password meeting all requirements
    """
    
    if length < 16 or length > 60:
        raise ValueError("Password length must be between 16 and 60 characters")
    
    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
    
    # Ensure at least one character from each required category
    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = uppercase + lowercase + digits + special
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_chars))
    
    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)


def secure_file_permissions(filepath):
    """
    Set restrictive permissions on a file (owner read/write only).
    
    Args:
        filepath: Path to the file to secure
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not os.path.exists(filepath):
        return False
    
    try:
        if sys.platform == 'win32':
            # Windows: Use icacls to set owner-only permissions
            
            # Remove all permissions
            subprocess.run(['icacls', filepath, '/inheritance:r'], 
                          capture_output=True, check=False)
            # Grant full control to current user only
            subprocess.run(['icacls', filepath, '/grant:r', f'{os.getlogin()}:F'], 
                          capture_output=True, check=False)
        else:
            # Unix/Linux/macOS: Use chmod 0600 (owner read/write only)
            os.chmod(filepath, 0o600)
        
        return True
    
    except Exception as e:
        logger.warning(f"Could not set restrictive permissions on {filepath}: {e}")
        return False


def secure_all_sensitive_files():
    """Secure permissions on all sensitive files in the database."""
    sensitive_files = [
        DB_FILENAME,              # passwords.db
        BACKUP_FILENAME,          # passwords_backup.db
        "wrapped_key.bin",        # Wrapped database key
        "db_salt.bin",            # Password salt
        LOG_FILENAME              # password_manager.log
    ]
    
    for filepath in sensitive_files:
        if os.path.exists(filepath):
            secure_file_permissions(filepath)

