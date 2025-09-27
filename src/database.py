import os
import threading
import shutil
import re
import json
from cryptography.fernet import Fernet
from crypto import encrypt_database, decrypt_database

DB_FILENAME = "passwords.db"
BACKUP_FILENAME = "passwords_backup.db"
LOCK = threading.Lock()  # basic concurrency control

# Regex pattern for password validation
password_pattern = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!"#$%&\'()*+,\-./:;<=>?@[\\\]^_`{|}~])[A-Za-z\d!"#$%&\'()*+,\-./:;<=>?@[\\\]^_`{|}~]{16,60}$'
)

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
    if not os.path.exists(DB_FILENAME):
        return {}
    try:
        with LOCK:
            with open(DB_FILENAME, "rb") as f:
                encrypted = f.read()
            fernet = Fernet(fernet_key)
            decrypted = fernet.decrypt(encrypted)
            db = json.loads(decrypted.decode('utf-8'))
            return db
    except Exception as e:
        print(f"Error loading database: {e}")
        return {}



def save_database(db, fernet_key):
    try:
        data = json.dumps(db).encode('utf-8')
        fernet = Fernet(fernet_key)
        encrypted = fernet.encrypt(data)
        with LOCK:
            with open(DB_FILENAME, "wb") as f:
                f.write(encrypted)
        print("Database saved.")
        return True
    except Exception as e:
        print(f"Error saving database: {e}")
        return False

def backup_database():
    """Backup the database file."""
    try:
        with LOCK:
            if os.path.exists(DB_FILENAME):
                shutil.copy2(DB_FILENAME, BACKUP_FILENAME)
                print("Database backup completed.")
            else:
                print("No database to backup.")
    except Exception as e:
        print(f"Error backing up: {e}")

def restore_database():
    """Restore the database from backup."""
    try:
        with LOCK:
            if os.path.exists(BACKUP_FILENAME):
                shutil.copy2(BACKUP_FILENAME, DB_FILENAME)
                print("Database restored from backup.")
            else:
                print("No backup found.")
    except Exception as e:
        print(f"Error restoring backup: {e}")

def add_entry(db, service, username, password):
    """Add a new entry after validation."""
    if not is_valid_entry(service, username, password):
        print("Invalid entry data. Please ensure all fields are non-empty and password meets policy.")
        return False
    db[service] = {"username": username, "password": password}
    print(f"Service '{service}' added.")
    return True


def edit_entry(db, service, username=None, password=None):
    """Edit username and/or password for an existing service with validation."""
    if service not in db:
        print(f"Service '{service}' not found.")
        return False

    new_username = username if username is not None else db[service].get('username')
    new_password = password if password is not None else db[service].get('password')

    # Validate updated entry:
    if not is_valid_entry(service, new_username, new_password):
        print("Invalid entry data. Please ensure username and password fulfill requirements.")
        return False

    # Apply changes:
    db[service]['username'] = new_username
    db[service]['password'] = new_password
    print(f"Service '{service}' updated.")
    return True


def get_entry(db, service):
    """Retrieve entry for a service."""
    return db.get(service)

def delete_entry(db, service):
    """Delete entry if it exists."""
    if service in db:
        del db[service]
        print(f"Service '{service}' deleted.")

def list_services(db):
    """List all stored service names."""
    return list(db.keys())
