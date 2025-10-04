import os
import sys
import threading
import shutil
import re
import json
import logging
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


def load_database(fernet_key):
    """
    Load and decrypt the password database.

    Returns:
        dict: The decrypted database dictionary

    Raises:
        cryptography.fernet.InvalidToken: If wrong password/key (wrong decryption)
        json.JSONDecodeError: If database format is corrupted
        Exception: For other errors

    Note: Only returns empty {} if file doesn't exist (not an error condition)
    """
    if not os.path.exists(DB_FILENAME):
        # File doesn't exist yet - return empty database (not an error)
        return {}

    with LOCK:
        with open(DB_FILENAME, "rb") as f:
            encrypted = f.read()

        fernet = Fernet(fernet_key)

        # This raises InvalidToken if wrong key - LET IT PROPAGATE!
        decrypted = fernet.decrypt(encrypted)

        db = json.loads(decrypted.decode('utf-8'))
        return db


def save_database(db, fernet_key):
    """Encrypt and save the password database."""
    try:
        data = json.dumps(db).encode('utf-8')
        fernet = Fernet(fernet_key)
        encrypted = fernet.encrypt(data)
        
        with LOCK:
            with open(DB_FILENAME, "wb") as f:
                f.write(encrypted)
        return True
    except PermissionError:
        print("Error: Unable to save database (permission denied)")
        logger.error(f"Permission denied writing to {DB_FILENAME}", exc_info=True)
        return False
    except OSError:
        print("Error: Unable to save database (disk error)")
        logger.error("OS error saving database", exc_info=True)
        return False
    except Exception as e:
        print("Error: Failed to save database")
        logger.error(f"Unexpected error in save_database: {type(e).__name__}", exc_info=True)
        return False


def backup_database():
    """Backup the database file."""
    try:
        with LOCK:
            if os.path.exists(DB_FILENAME):
                shutil.copy2(DB_FILENAME, BACKUP_FILENAME)
                return True
            else:
                return False
    except PermissionError:
        print("Error: Unable to create backup (permission denied)")
        logger.error("Permission denied creating backup", exc_info=True)
        return False
    except OSError:
        print("Error: Unable to create backup (disk error)")
        logger.error("OS error creating backup", exc_info=True)
        return False
    except Exception as e:
        print("Error: Backup failed")
        logger.error(f"Unexpected error in backup_database: {type(e).__name__}", exc_info=True)
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



def add_entry(db, service, username, password):
    """Add a new entry after validation."""
    if not is_valid_entry(service, username, password):
        return False
    db[service] = {"username": username, "password": password}
    return True


def edit_entry(db, service, username=None, password=None):
    """Edit username and/or password for an existing service with validation."""
    if service not in db:
        return False

    new_username = username if username is not None else db[service].get('username')
    new_password = password if password is not None else db[service].get('password')

    # Validate updated entry:
    if not is_valid_entry(service, new_username, new_password):
        return False

    # Apply changes:
    db[service]['username'] = new_username
    db[service]['password'] = new_password
    return True


def get_entry(db, service):
    """Retrieve entry for a service."""
    return db.get(service)


def delete_entry(db, service):
    """Delete entry if it exists, returning a boolean."""
    if service in db:
        del db[service]
        return True
    return False


def list_services(db):
    """List all stored service names."""
    return list(db.keys())


def destroy_database_files():
    """Permanently delete the encrypted database and its backup using secure deletion."""
    try:
        removed = False
        with LOCK:
            # Securely delete main database file
            if os.path.exists(DB_FILENAME):
                if secure_delete(DB_FILENAME):
                    print(f"Securely deleted {DB_FILENAME}")
                    removed = True
                else:
                    print(f"Warning: Could not securely delete {DB_FILENAME}")
            
            # Securely delete backup file
            if os.path.exists(BACKUP_FILENAME):
                if secure_delete(BACKUP_FILENAME):
                    print(f"Securely deleted {BACKUP_FILENAME}")
                    removed = True
                else:
                    print(f"Warning: Could not securely delete {BACKUP_FILENAME}")
        
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



def secure_log_file():
    """Ensure log file has restrictive permissions across all platforms."""
    if not os.path.exists(LOG_FILENAME):
        return
    
    try:
        if sys.platform == 'win32':
            # Windows: Use icacls to set owner-only ACL
            import subprocess
            username = os.getenv('USERNAME', '')
            if username:
                # Remove inherited permissions
                subprocess.run(
                    ['icacls', LOG_FILENAME, '/inheritance:r'],
                    capture_output=True,
                    check=False
                )
                # Grant read/write to owner only
                subprocess.run(
                    ['icacls', LOG_FILENAME, '/grant:r', f'{username}:(R,W)'],
                    capture_output=True,
                    check=False
                )
        else:
            # Unix-like (Linux, macOS): Use chmod
            import stat
            os.chmod(LOG_FILENAME, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            
    except Exception:
        # Best effort - fail gracefully
        pass

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
    import secrets
    import string
    
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
