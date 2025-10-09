import argparse
import os
import base64
import sys
import shlex
import json
import pyperclip
import time
import threading
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from crypto import derive_key_from_password, unwrap_database_key, wrap_database_key
from database import (
    EncryptedDatabase, DNIE_REGISTRY_FILE, is_valid_password, is_valid_entry, save_database, backup_database, restore_database, 
    destroy_database_files, generate_random_password, secure_file_permissions, secure_all_sensitive_files,
    get_db_filename, get_salt_filename, get_wrapped_key_filename, get_backup_filename, load_dnie_registry
)
from smartcard_dnie import DNIeCard, DNIeCardError
# Import secure memory handling
try:
    from zeroize import zeroize1, mlock, munlock
except ImportError:
    print("✗ CRITICAL ERROR: zeroize library is required but not installed.")
    print("Install it with: pip install zeroize")
    print("Exiting for security reasons.")
    import sys
    sys.exit(1)

# Masked password input with fallback
try:
    import maskpass
    
    def input_password_masked(prompt='Password: '):
        """Get password with masking using maskpass library."""
        try:
            return maskpass.askpass(prompt=prompt, mask='*')
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            raise
        # Remove the generic Exception catch - let errors propagate
        
except ImportError:
    # Only fallback if maskpass is not installed at all
    import getpass
    
    def input_password_masked(prompt='Password: '):
        """Fallback to getpass without masking."""
        return getpass.getpass(prompt)

# Force UTF-8 encoding on Windows (if not maskpass will give error with special chars)
if sys.platform == 'win32':
    # Set console to UTF-8 mode
    os.system('chcp 65001 > nul')
    # Also set Python's default encoding
    if sys.stdout.encoding != 'utf-8':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

DEFAULT_SESSION_MINUTES = 4 # default session inactivity timeout in minutes

# Memory locking limits
MAX_MLOCK_SIZE_LINUX = 2662 * 1024  # 2662 KB on Linux
MAX_MLOCK_SIZE_WINDOWS = 128 * 1024  # 128 KB default on Windows

def save_dnie_registry(registry):
    with open(DNIE_REGISTRY_FILE, 'w') as f:
        json.dump(registry, f, indent=2)
    secure_file_permissions(DNIE_REGISTRY_FILE)

def is_dnie_registered(dnie_hash):
    registry = load_dnie_registry()
    return dnie_hash in registry.get('dnies', {})

def get_user_id_from_dnie(dnie_hash):
    registry = load_dnie_registry()
    dnies = registry.get('dnies', {})
    if dnie_hash in dnies:
        return dnies[dnie_hash].get('user_id')
    return None

def register_dnie(dnie_hash, user_id, description=""):
    registry = load_dnie_registry()
    if 'dnies' not in registry:
        registry['dnies'] = {}
    if dnie_hash in registry['dnies']:
        return False
    registry['dnies'][dnie_hash] = {
        'user_id': user_id,
        'created': datetime.now().isoformat(),
        'description': description,
        'last_login': None
    }
    save_dnie_registry(registry)
    return True

def update_last_login(dnie_hash):
    registry = load_dnie_registry()
    if dnie_hash in registry.get('dnies', {}):
        registry['dnies'][dnie_hash]['last_login'] = datetime.now().isoformat()
        save_dnie_registry(registry)

def get_next_user_id():
    registry = load_dnie_registry()
    existing_ids = []
    for dnie_info in registry.get('dnies', {}).values():
        user_id = dnie_info.get('user_id', '')
        if user_id.startswith('user'):
            try:
                num = int(user_id.replace('user', ''))
                existing_ids.append(num)
            except:
                pass
    next_id = max(existing_ids, default=0) + 1
    return f"user{next_id:03d}"


class SecureSession:
    """
    Enhanced Session class with Zeroize integration.
    Locks sensitive data in memory to prevent swapping to disk.
    """

    def __init__(self, timeout_minutes=DEFAULT_SESSION_MINUTES):
        self.timeout = timedelta(minutes=timeout_minutes)
        self.fernet_key = None
        self.last_auth = None
        self._key_locked = False  # Track if memory is locked

    def expired(self):
        """Check if the session has expired."""
        return self.last_auth is None or datetime.now() - self.last_auth > self.timeout

    def clear_key(self):
        """Securely clear and unlock the stored Fernet key."""
        if self.fernet_key is not None:
            try:
                # Ensure key is bytearray before zeroizing
                if isinstance(self.fernet_key, bytearray):
                    # Unlock memory if it was locked (BEFORE zeroizing)
                    if self._key_locked:
                        try:
                            munlock(self.fernet_key)
                        except Exception as e:
                            print(f"Warning: Failed to unlock key: {e}")
                        self._key_locked = False

                    # Now zeroize
                    zeroize1(self.fernet_key)
                else:
                    # Should not happen if ensure_unlocked is correct,
                    # but handled just in case
                    print("Warning: Fernet key is not bytearray, cannot zeroize properly")
            except Exception as e:
                print(f"Warning: Failed to securely clear key: {e}")
            finally:
                self.fernet_key = None

    def ensure_unlocked(self, load_salt_fn, derive_fn, prompt_fn):
        """
        Ensure session is authenticated and return the Fernet key.
        Uses memory locking to prevent key from being swapped to disk.
        """
        if self.expired():
            # Clear old key before creating new one
            self.clear_key()

            # Get salt and password
            salt = load_salt_fn()
            password = prompt_fn()

            # Derive key from password
            key_bytes = derive_fn(password, salt)
            # Remove reference to original password
            del password

            # Encode for Fernet (still as bytearray)
            self.fernet_key = bytearray(base64.urlsafe_b64encode(key_bytes))
            del key_bytes  # Remove reference to original key bytes

            # Lock the final Fernet key in memory
            if len(self.fernet_key) <= MAX_MLOCK_SIZE_LINUX:
                try:
                    mlock(self.fernet_key)
                    self._key_locked = True
                except Exception as e:
                    print(f"Note: Could not lock fernet key memory: {e}")
                    self._key_locked = False

            self.last_auth = datetime.now()

        # Return as bytes for compatibility with Fernet
        return bytes(self.fernet_key)

    def __del__(self):
        """Ensure key is cleared when session is destroyed."""
        self.clear_key()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - secure cleanup."""
        self.clear_key()
        return False

def auto_expire_session(session, check_interval=30):
    """
    Background thread that proactively expires session after timeout.
    Checks every `check_interval` seconds and clears key if expired.
    """ 
    stop_event = threading.Event()
    
    def checker():
        while not stop_event.is_set():
            time.sleep(check_interval)
            if session.expired():
                print("\n⏱ Session expired due to inactivity. Clearing key...")
                session.clear_key()
                print("🔒 Session locked. Re-authentication required on next command.\n")
                break
    
    thread = threading.Thread(target=checker, daemon=True, name="SessionExpiry")
    thread.start()
    return stop_event


def prompt_master_password():
    """
    Prompt for master password with validation.
    """
    while True:
        password = input_password_masked(prompt="Enter master password: ")
        if is_valid_password(password):
            print("Password accepted.")
            return password
        else:
            del password  # Remove invalid password reference
            print("Invalid password. Password must be 16-60 chars with uppercase, lowercase, digits, and symbols. Try again.\n")

def prompt_and_verify_two_factor():
    """
    Two-factor authentication with DNIe registration verification.
    FIRST verifies that the DNIe is registered before attempting decryption.
    
    Returns:
        tuple: (kdb, user_id) if successful, None on failure
    """
    MAX_ATTEMPTS = 3

    # STEP 1: Connect to DNIe and get serial hash
    print("\n" + "="*80)
    print("DNIe VERIFICATION")
    print("="*80)
    print("\nInsert your DNIe into the reader...")
    
    card = None
    dnie_hash = None
    
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\n{'=' * 80}")
        print(f"TWO-FACTOR AUTHENTICATION (attempt {attempt}/{MAX_ATTEMPTS})")
        print("=" * 80)
        
        # Factor 1: DNIe Signature Challenge
        print("\nFACTOR 1: DNIe Signature Challenge")
        print("Please insert your DNIe card into the reader...")
        
        # Card detection retry loop (give user time to insert card)
        card = None
        dnie_wrapping_key = None
        
        while True:
            try:
                card = DNIeCard()
                card.connect()
                print("✓ DNIe card detected")

                # Get serial hash BEFORE authenticating
                dnie_hash = card.get_serial_hash()
                print(f"✓ DNIe identified: {dnie_hash[:8]}...")
                break  # Card detected, exit retry loop
                
            except DNIeCardError as e:
                if "not detected" in str(e).lower() or "no smart card" in str(e).lower():
                    print("⚠  Card not detected.")
                    retry = input("Press Enter to retry, or 'q' to quit: ").strip().lower()
                    if retry == 'q':
                        print("Authentication cancelled.")
                        return None
                    continue  # Retry card detection
                else:
                    # Other DNIe errors (not detection-related)
                    print(f"✗ DNIe error: {e}")
                    break  # Exit retry loop, count as failed attempt
            except Exception as e:
                print(f"✗ Error: {e}")
                break  # Exit retry loop, count as failed attempt
        
        # If card connection failed for non-detection reasons, try next attempt
        if card is None or not hasattr(card, 'session') or card.session is None:
            if attempt < MAX_ATTEMPTS:
                print(f"   {MAX_ATTEMPTS - attempt} attempts remaining.")
                continue
            else:
                break
        
        # STEP 2: Verify that the DNIe is registered
        if not is_dnie_registered(dnie_hash):
            print("\n" + "="*80)
            print("✗ DNIe NOT REGISTERED")
            print("="*80)
            print(f"\nThis DNIe ({dnie_hash[:8]}...) is not registered in the system.")
            print("Would you like to initialize a new database for this DNIe?")
            
            choice = input("\n(i)nitialize new database, or (q)uit? [i/q]: ").strip().lower()
            
            card.disconnect()
            
            if choice == 'i' or choice == '':
                # Redirect to initialization
                print("\nStarting database initialization...\n")
                from sys import exit as sys_exit
                result = init_database()
                if result:
                    print("\n✓ Initialization complete! You can now use the password manager.")
                    sys_exit(0)
                else:
                    print("\n✗ Initialization cancelled or failed.")
                    sys_exit(1)
            else:
                print("Exiting password manager.")
                return None
        
        print("✓ DNIe registered in the system")

        # Get user_id from registry
        user_id = get_user_id_from_dnie(dnie_hash)
        if not user_id:
            print("✗ Error: Could not retrieve user_id from registry")
            card.disconnect()
            return None
    
        # Update last login timestamp
        update_last_login(dnie_hash)

        # STEP 3: Get user-specific file names
        salt_file = get_salt_filename(user_id)
        wrapped_key_file = get_wrapped_key_filename(user_id)
        db_file = get_db_filename(user_id)

        # Verify that files exist
        if not os.path.exists(salt_file) or not os.path.exists(wrapped_key_file):
            print(f"\n✗ Error: Configuration files not found for this DNIe.")
            print("Database may be corrupted.")
            card.disconnect()
            return None
        
        # Load user-specific salt
        with open(salt_file, 'rb') as f:
            salt = f.read()

        # STEP 4: Authentication (PIN + Master Password)
        try:
            pin = input_password_masked("Enter DNIe PIN: ")
            dnie_wrapping_key = card.authenticate(pin)  # This signs the challenge
            del pin  # Remove reference to PIN
            card.disconnect()
            
        except DNIeCardError as e:
            print(f"✗ DNIe authentication error: {e}")
            if attempt < MAX_ATTEMPTS:
                print(f"   {MAX_ATTEMPTS - attempt} attempts remaining.")
                try:
                    card.disconnect()
                except:
                    pass
                continue
            else:
                try:
                    card.disconnect()
                except:
                    pass
                break
        except Exception as e:
            print(f"✗ Error: {e}")
            if attempt < MAX_ATTEMPTS:
                print(f"   {MAX_ATTEMPTS - attempt} attempts remaining.")
                try:
                    card.disconnect()
                except:
                    pass
                continue
            else:
                try:
                    card.disconnect()
                except:
                    pass
                break
        
        # Factor 2: Master Password
        print("\nFACTOR 2: Master Password")
        password = input_password_masked("Enter master password: ")
            
        # Derive password key
        password_key = derive_key_from_password(password, salt)
        del password  # Remove reference to password

        # Attempt to decrypt
        try:
            # Load wrapped K_db from file
            print("\nUnwrapping database key...")
            with open(wrapped_key_file, 'rb') as f:
                wrapped_k_db = f.read()
            
            # Unwrap K_db using DNIe + password keys
            k_db = unwrap_database_key(wrapped_k_db, dnie_wrapping_key, password_key)
            del dnie_wrapping_key
            del password_key
            del wrapped_k_db
            print("✓ K_db unwrapped successfully")
            
            # Try to decrypt database with K_db
            try:
                print("Verifying database key...")
                
                # Just verifying we can decrypt - don't keeping the data
                with open(db_file, 'rb') as f:
                    encrypted = f.read()
                
                fernet = Fernet(k_db)
                decrypted = fernet.decrypt(encrypted)
                
                # Verify it's valid JSON
                json.loads(decrypted.decode('utf-8'))
                
                # Immediately cleanup - don't keep in memory!
                del fernet
                del decrypted
                del encrypted
                
                print("\n✓ TWO-FACTOR AUTHENTICATION SUCCESSFUL!")
                print("=" * 80)
                
                # Return ONLY k_db (as bytearray for session management)
                return bytearray(k_db), user_id
            
            except Exception as e:
                print(f"✗ Authentication failed. Incorrect credentials or corrupted database.")
                print(f"   Error: {e}")
                if attempt < MAX_ATTEMPTS:
                    print(f"   {MAX_ATTEMPTS - attempt} attempts remaining.")

                del k_db # Clean up failed attempt     
                    
        except Exception as e:
            print(f"✗ Unwrapping failed: {e}")
            if attempt < MAX_ATTEMPTS:
                print(f"   {MAX_ATTEMPTS - attempt} attempts remaining.")
            # Clean up if variables exist
            if 'dnie_wrapping_key' in locals():
                del dnie_wrapping_key
            if 'password_key' in locals():
                del password_key
    
    print(f"\n✗ Authentication failed after {MAX_ATTEMPTS} attempts.")
    print("Exiting for security.")
    return None


def generate_salt():
    """Generate a cryptographically secure random salt."""
    return os.urandom(16)

def init_database():
    """Initialize database with random K_db protected by DNIe signature + password."""
    print("=" * 80)
    print("INITIALIZING PASSWORD MANAGER - SIGNATURE CHALLENGE")
    print("=" * 80)
    # STEP 1: Connect and get DNIe hash
    print("\nInsert the DNIe you'll use for this database...")
    
    card = None
    dnie_hash = None
    
    while True:
        try:
            card = DNIeCard()
            card.connect()
            print("✓ DNIe detected")
            
            dnie_hash = card.get_serial_hash()
            print(f"✓ DNIe identified: {dnie_hash[:8]}...")
            break
            
        except DNIeCardError as e:
            if "not detected" or "no smart card" in str(e).lower():
                retry = input("⚠ DNIe not detected. [Enter] retry, [q] cancel: ").strip().lower()
                if retry == 'q':
                    print("Initialization cancelled.")
                    return None
                continue
            else:
                print(f"✗ DNIe error: {e}")
                return None
    
    # Determine user_id
    if is_dnie_registered(dnie_hash):
        user_id = get_user_id_from_dnie(dnie_hash)
        print(f"\n⚠ This DNIe is already registered as: {user_id}")
    else:
        user_id = get_next_user_id()
        print(f"\n✓ New user: {user_id}")

    # Get user-specific file names
    salt_file = get_salt_filename(user_id)
    wrapped_key_file = get_wrapped_key_filename(user_id)
    db_file = get_db_filename(user_id)

    # STEP 2: Check if database already exists for this DNIe
    if os.path.exists(salt_file) or os.path.exists(wrapped_key_file):
        print(f"\n⚠ A database already exists for this user.")
        
        response = input("\nDo you want to OVERWRITE? (YOU'LL LOSE ALL DATA) [yes/no]: ").strip().lower()
        
        if response not in ['yes', 'y']:
            print("Initialization cancelled.")
            card.disconnect()
            return None
        
        print("\n⚠ WARNING: All current data will be deleted.")
        confirm = input("Type 'DELETE ALL' to confirm: ").strip()
        
        if confirm != 'DELETE ALL':
            print("Initialization cancelled.")
            card.disconnect()
            return None
        
    # STEP 3: Request description for new registration
    is_new_registration = not is_dnie_registered(dnie_hash)

    if is_new_registration:
        print(f"\n✓ New DNIe registration")
        
        while True:
            description = input("Enter a description for this DNIe (optional, e.g., 'Work Laptop', 'Personal'): ").strip()
            
            # Use default if empty
            if not description:
                description = f"User {user_id}"
                print(f"Using default description: {description}")
                break
            
            # Validate description length
            elif len(description) > 50:
                print("⚠ Description too long (max 50 characters). Please try again.")
                continue
            
            # Check for valid characters (optional)
            elif not all(c.isalnum() or c.isspace() or c in "-_.,'" for c in description):
                print("⚠ Description contains invalid characters. Use only letters, numbers, spaces, and -_.,")
                continue
            
            else:
                print(f"✓ Description set: {description}")
                break
    
    # STEP 4: Authenticate with PIN
    try:
        pin = input_password_masked("Enter DNIe PIN: ")
        dnie_wrapping_key = card.authenticate(pin)
        del pin  # Remove reference to PIN
        print("✓ Signature challenge successful")
        card.disconnect()
        
    except DNIeCardError as e:
        print(f"✗ DNIe error: {e}")
        print("Initialization failed.")
        try:
            card.disconnect()
        except:
            pass
        return None
    except Exception as e:
        print(f"✗ Error: {e}")
        print("Initialization failed.")
        try:
            card.disconnect()
        except:
            pass
        return None
    
    # STEP 5: Configure master password
    print("\nMaster Password Setup...")
    salt = generate_salt()
    
    password = prompt_master_password()
    
    try:
        password_key = derive_key_from_password(password, salt)
        del password  # Remove reference to password
        print("✓ Password key derived")
        
        # Step 6: Generate random K_db
        print("STEP 3: Generating random database key...")
        k_db = Fernet.generate_key()  # Random 32-byte key
        print(f"✓ Generated K_db ({len(k_db)} bytes)")

        # Step 7: Wrap K_db
        print("\nSTEP 4: Wrapping database key...")
        wrapped_k_db = wrap_database_key(k_db, dnie_wrapping_key, password_key)
        del dnie_wrapping_key   # Remove reference to DNIe key
        del password_key     # Remove reference to password key
        
        # Save user-specific files
        with open(salt_file, 'wb') as f:
            f.write(salt)
        secure_file_permissions(salt_file)
        
        with open(wrapped_key_file, 'wb') as f:
            f.write(wrapped_k_db)
        del wrapped_k_db
        secure_file_permissions(wrapped_key_file)
        
        # Step 8: Create empty database encrypted with K_db
        print("\nSTEP 5: Creating encrypted database...")
        empty_db = {}
        save_database(empty_db, k_db, db_file)
        print("✓ Database created and encrypted with K_db")
        
        # STEP 9: Register DNIe in registry (ADD THIS)
        if is_new_registration:
            register_dnie(dnie_hash, user_id, description)
            print(f"✓ DNIe registered in system")

            print("\n" + "=" * 80)
            print("✓ INITIALIZATION COMPLETE!")
            print("=" * 80)
            print("\n🔐 Your database is protected by:")
            print("  • Random K_db (stored encrypted)")
            print("  • DNIe signature challenge (requires card + PIN)")
            print("  • Master password (Argon2id-derived key)")

        # Return immediate session start
        return (bytearray(k_db), user_id)
    
    except Exception as e:
        print(f"\n✗ Initialization failed: {e}")

        # Clean up sensitive variables if they exist
        if 'k_db' in locals() and k_db is not None:
            del k_db
        if 'dnie_wrapping_key' in locals() and dnie_wrapping_key is not None:
            del dnie_wrapping_key
        if 'password_key' in locals() and password_key is not None:
            del password_key
        if 'wrapped_k_db' in locals() and wrapped_k_db is not None:
            del wrapped_k_db
        if 'password' in locals() and password is not None:
            del password
        # Clean up partial files if initialization failed
        try:
            if os.path.exists(wrapped_key_file):
                os.remove(wrapped_key_file)
            if os.path.exists(salt_file):
                os.remove(salt_file)
            if os.path.exists(db_file):
                os.remove(db_file)
        except:
            pass
    
        return None

def create_command_parser():
    """Create an argument parser for interactive session commands."""
    parser = argparse.ArgumentParser(
        prog='pm',
        description='Password Manager Interactive Commands',
        exit_on_error=False
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # ADD command
    add_p = subparsers.add_parser('add', 
        help='Add a new password entry',
        description='Add a new service with username and password to the database')
    add_p.add_argument('service', help='Service name (e.g., gmail, github, twitter)')
    add_p.add_argument('username', help='Username or email address for the service')
    
    # EDIT command
    edit_p = subparsers.add_parser('edit',
        help='Edit an existing entry',
        description='Edit username and/or password for an existing service. Provide at least one option.')
    edit_p.add_argument('service', help='Service name to edit (must exist in database)')
    edit_p.add_argument('--username', metavar='NEW_USERNAME', 
                       help='New username or email (leave unchanged if not provided)')
    edit_p.add_argument('--password', metavar='NEW_PASSWORD', 
                       help='New password meeting security requirements (leave unchanged if not provided)')
    
    # LIST command
    list_p = subparsers.add_parser('list',
        help='List all stored services',
        description='Display names of all services stored in the database')
    
    # SHOW command
    show_p = subparsers.add_parser('show',
        help='Show entry details',
        description='Display username and optionally password for a service')
    show_p.add_argument('service', help='Service name to display')
    show_p.add_argument('--reveal', action='store_true', 
                       help='Show password in plaintext (default: hidden for security)')
    
    # COPY command - copy password to clipboard
    copy_p = subparsers.add_parser('copy',
        help='Copy password to clipboard without displaying it',
        description='Copy a service password to clipboard securely (no screen output)')
    copy_p.add_argument('service', help='Service name whose password to copy')
    copy_p.add_argument('--timeout', type=int, default=10, 
        help='Seconds before auto-clearing clipboard (default: 10, 0 to disable)')
    
    # DELETE command
    delete_p = subparsers.add_parser('delete',
        help='Delete an entry',
        description='Permanently remove a service entry from the database')
    delete_p.add_argument('service', help='Service name to delete')
    delete_p.add_argument('--yes', '-y', action='store_true', 
                         help='Skip confirmation prompt (use with caution)')
    
    # BACKUP command
    backup_p = subparsers.add_parser('backup',
        help='Create database backup',
        description='Create a backup copy of the encrypted database file')
    
    # RESTORE command
    restore_p = subparsers.add_parser('restore',
        help='Restore from backup',
        description='Restore database from the most recent backup file')
    
    # LOCK command - immediately lock the session
    lock_p = subparsers.add_parser('lock',
        help='Lock the session immediately (requires re-authentication)',
        description='Lock the current session and clear sensitive data from memory')

    # INIT command
    init_p = subparsers.add_parser('init',
        help='Re-initialize database',
        description='⚠️  Destroy current database and create new one with new master password. ALL DATA WILL BE LOST!')
    
    # DESTROY-DB command
    destroy_p = subparsers.add_parser('destroy-db',
        help='Destroy database permanently',
        description='⚠️  Permanently delete database and all backups. This action is IRREVERSIBLE!')
    
    # HELP command
    help_p = subparsers.add_parser('help',
        help='Show help information',
        description='Display help for all commands or detailed help for a specific command')
    help_p.add_argument('command_name', nargs='?', metavar='COMMAND',
                       help='Specific command to get help for (optional)')
    
    return parser

def show_enhanced_help():
    """Show enhanced help with examples for all commands."""
    print("""
╔════════════════════════════════════════════════════════════════════╗
║           PASSWORD MANAGER - COMMAND REFERENCE                     ║
╚════════════════════════════════════════════════════════════════════╝

📝 MANAGING ENTRIES

  add <service> <username>
      Add a new password entry with optional random password generation
      Example: add gmail user@gmail.com
      → Prompts: Generate random password? (y/n)
      → If yes: Enter password length (16-60, default 20)
      → Shows generated password and asks for confirmation
      → If no: Prompts for manual password entry with masking

  edit <service>
      Edit username and/or password for existing entry
      Example: edit gmail
      → Prompts: Change username? (y/n)
      → Prompts: Change password? (y/n)
      → If changing password: Generate random password? (y/n)
      → Interactive flow for generation or manual entry

  show <service> [--reveal]
      Show entry details (password hidden by default)
      Example: show gmail
      Example: show gmail --reveal
          
  copy <service>
      Copy password to clipboard without displaying it
      Example: copy gmail

  delete <service> [-y]
      Delete an entry (prompts for confirmation)
      Example: delete gmail
      Example: delete gmail -y    (skip confirmation)

  list
      List all stored services
      Example: list

💾 DATABASE OPERATIONS

  backup
      Create a backup of the encrypted database

  restore
      Restore database from the most recent backup
          
  lock
      Lock the session immediately (requires re-authentication)
      Example: lock
      → Clears session and requires master password to continue
          
  init
      Re-initialize database with new master password
      ⚠️  WARNING: This destroys all existing data!

  destroy-db
      Permanently delete database and all backups
      ⚠️  WARNING: This is irreversible!

❓ HELP & EXIT

  help [command]
      Show this help or help for specific command
      Example: help
      Example: help add

  exit | quit
      Exit password manager (secure cleanup)

🔐 PASSWORD REQUIREMENTS

  • Length: 16-60 characters
  • Must include: uppercase, lowercase, digit, special character
  • Special characters: !@#$%^&*()-_=+[]{}|;:,.<>?/
  • International characters supported (UTF-8)

✨ PASSWORD GENERATOR FEATURES

  • Cryptographically secure random generation using secrets module
  • Customizable length (16-60 characters)
  • Automatic compliance with password policy
  • Preview before confirming
  • Option to regenerate or enter manually
  • Available in both 'add' and 'edit' commands

💡 TIP: Type 'help <command>' for detailed help on any command
      Example: help add
""")


def run_session(timeout_minutes, initial_result=None):
    """
    Main interactive session with two-factor authentication (DNIe + Password).
    Uses SecureSession for automatic memory locking and cleanup.
    """
    
    # Create command parser for interactive mode
    cmd_parser = create_command_parser()
    
    if initial_result is not None:
        # Result provided from initialization - use directly
        k_db, user_id = initial_result
    else:
        # Normal two-factor authentication
        result = prompt_and_verify_two_factor()
        if result is None:
            return
        k_db, user_id = result
    
    with SecureSession(timeout_minutes=timeout_minutes) as session:     
        # Store in session for management
        session.fernet_key = k_db
        session.user_id = user_id
        del k_db  # Remove reference to original k_db
        del user_id 
        session.last_auth = datetime.now()

        # Lock it in memory
        if len(session.fernet_key) <= MAX_MLOCK_SIZE_LINUX:
            try:
                mlock(session.fernet_key)
                session._key_locked = True
            except Exception as e:
                print(f"Note: Could not lock key in memory: {e}")
                session._key_locked = False
        
        # Start background thread to auto-expire session
        expiry_stop = auto_expire_session(session, check_interval=30)

        # Create on-demand database wrapper
        db_file = get_db_filename(session.user_id)
        encrypted_db = EncryptedDatabase(bytes(session.fernet_key), db_filename=db_file)

        # Get user info from registry for display
        registry = load_dnie_registry()
        dnie_info = registry.get('dnies', {})
        user_description = "Unknown User"
        for dnie_hash, info in dnie_info.items():
            if info.get('user_id') == session.user_id:
                user_description = info.get('description', session.user_id)
                break

        print(f"\n{'=' * 80}")
        print(f"PASSWORD MANAGER - SESSION ACTIVE")
        print(f"{'=' * 80}")
        print(f"User: {session.user_id} ({user_description})")
        print(f"Authentication: Two-Factor (DNIe + Password)")
        print(f"Session timeout: {timeout_minutes} minutes")
        print(f"Database: {db_file}")
        print(f"Commands: add, edit, list, show, copy, delete, backup, restore, lock, init, destroy-db, exit, help")
        print(f"{'=' * 80}\n")
        
        try:
            while True:
                try:
                    line = input("pm> ").strip()
                except EOFError:
                    break
                
                if not line:
                    continue
                
                if line in ("exit", "quit"):
                    break
                
                # Re-authenticate if session expired
                if session.expired():
                    print("\n⏱  Session expired. Re-authentication required.")
                    encrypted_db.clear()
                    
                    result = prompt_and_verify_two_factor()
                    
                    if result is None:
                        print("Re-authentication failed. Ending session.")
                        break
                    k_db, user_id = result

                    # Verify it's the same user
                    if user_id != session.user_id:
                        print(f"✗ Error: Different DNIe detected (expected {session.user_id}, got {user_id})")
                        print("Cannot continue session with different user. Ending session.")
                        del k_db
                        del user_id
                        break
                    del user_id  # No longer needed

                    session.clear_key()
                    session.fernet_key = k_db
                    del k_db  # Remove reference to temporary result

                    # Lock new key in memory
                    if len(session.fernet_key) <= MAX_MLOCK_SIZE_LINUX:
                        try:
                            mlock(session.fernet_key)
                            session._key_locked = True
                        except Exception as e:
                            print(f"Note: Could not lock key in memory: {e}")
                            session._key_locked = False

                    session.last_auth = datetime.now()

                    # Create new database wrapper with new key
                    db_file = get_db_filename(session.user_id)
                    encrypted_db = EncryptedDatabase(bytes(session.fernet_key), db_filename=db_file)
                    print("✓ Re-authenticated successfully.\n")
                
                # Handle help command with optional specific command
                if line == "help" or line.startswith("help "):
                    if line.startswith("help "):
                        parts = line.split(maxsplit=1)
                        if len(parts) > 1:
                            # Show help for specific command
                            try:
                                cmd_parser.parse_args([parts[1], '-h'])
                            except SystemExit:
                                pass
                        else:
                            show_enhanced_help()
                    else:
                        # Show general help
                        show_enhanced_help()
                    continue
                
                # Parse the command
                try:
                    args = cmd_parser.parse_args(shlex.split(line))
                except (argparse.ArgumentError, SystemExit):
                    print("Invalid command. Type 'help' for usage.")
                    continue
                
                cmd = args.command
                
                if cmd is None:
                    print("Unknown command. Type 'help' for usage.")
                    continue
                
                # Data-access commands using cached fernet_key/db
                if cmd == 'add':
                    # ADD command with password generation option
                    if hasattr(args, 'service') and hasattr(args, 'username'):
                        service = args.service
                        username = args.username

                        # Check if service already exists
                        if encrypted_db.service_exists(service):
                            print(f"✗ Service '{service}' already exists.")
                            print(f"   Use 'edit {service}' to modify it, or 'delete {service}' to remove it.")
                            continue
                        
                        password = None  # Initialize password variable
                        
                        # Ask if user wants to generate a random password
                        gen_choice = input("Generate random password? (y/n): ").strip().lower()
                        
                        if gen_choice == 'y':
                            # Ask for desired length
                            while True:
                                try:
                                    length_input = input("Enter password length (16-60, default 20): ").strip()
                                    if not length_input:
                                        length = 20
                                    else:
                                        length = int(length_input)
                                    if 16 <= length <= 60:
                                        break
                                    else:
                                        print("Length must be between 16 and 60.")
                                except ValueError:
                                    print("Invalid input. Please enter a number.")
                            
                            # Generation loop with regenerate option
                            while True:
                                password = generate_random_password(length)
                                print(f"\nGenerated password: {password}")
                                
                                choice = input("(u)se this, (r)egenerate, or (m)anual entry? [u/r/m]: ").strip().lower()
                                
                                if choice == 'u' or choice == '':
                                    # Use generated password
                                    break
                                elif choice == 'r':
                                    # Regenerate - loop continues
                                    continue
                                elif choice == 'm':
                                    # Switch to manual entry
                                    password = input_password_masked(prompt="Enter password manually: ")
                                    break
                                else:
                                    print("Invalid choice. Please enter 'u', 'r', or 'm'.")
                        else:
                            # Manual password entry
                            password = input_password_masked(prompt="Enter password manually: ")
                        
                        # Validate and add entry
                        if not is_valid_entry(service, username, password):
                            print("Invalid entry. Check service, username, and password validity.")
                            print("Password must be 16-60 chars with uppercase, lowercase, digits, and symbols.")
                            if password is not None:
                                del password  # Clean up password
                            continue
                        
                        # Add entry (automatically encrypts)
                        if encrypted_db.add_entry(service, username, password):
                            print(f"✓ Entry added for service {service}.")
                            session.last_auth = datetime.now()
                        else:
                            print(f"✗ Failed to add entry for {service}.")
                        
                        if password is not None:
                            del password
                    else:
                        print("Usage: add <service> <username>")
                
                elif cmd == 'edit':
                    # EDIT command with password generation option
                    if hasattr(args, 'service'):
                        service = args.service
                        
                        # Check if service exists
                        if not encrypted_db.service_exists(service):
                            print(f"Service '{service}' not found.")
                            continue
                        
                        new_username = None
                        new_password = None
                        
                        # Ask about username change
                        change_username = input("Change username? (y/n): ").strip().lower()
                        if change_username == 'y':
                            new_username = input("Enter new username: ").strip()
                            if not new_username:
                                print("Username cannot be empty.")
                                continue
                        
                        # Ask about password change
                        change_password = input("Change password? (y/n): ").strip().lower()
                        if change_password == 'y':
                            # Ask if user wants to generate a random password
                            gen_choice = input("Generate random password? (y/n): ").strip().lower()
                            
                            if gen_choice == 'y':
                                # Ask for desired length
                                while True:
                                    try:
                                        length_input = input("Enter password length (16-60, default 20): ").strip()
                                        if not length_input:
                                            length = 20
                                        else:
                                            length = int(length_input)
                                        if 16 <= length <= 60:
                                            break
                                        else:
                                            print("Length must be between 16 and 60.")
                                    except ValueError:
                                        print("Invalid input. Please enter a number.")
                                
                                # Generation loop with regenerate option
                                while True:
                                    new_password = generate_random_password(length)
                                    print(f"\nGenerated password: {new_password}")
                                    
                                    choice = input("(u)se this, (r)egenerate, or (m)anual entry? [u/r/m]: ").strip().lower()
                                    
                                    if choice == 'u' or choice == '':
                                        # Use generated password
                                        break
                                    elif choice == 'r':
                                        # Regenerate - loop continues
                                        continue
                                    elif choice == 'm':
                                        # Switch to manual entry
                                        new_password = input_password_masked(prompt="Enter password manually: ")
                                        break
                                    else:
                                        print("Invalid choice. Please enter 'u', 'r', or 'm'.")
                            else:
                                # Manual password entry
                                new_password = input_password_masked(prompt="Enter new password manually: ")
                        
                        # Check if anything to update
                        if new_username is None and new_password is None:
                            print("Nothing to update.")
                            continue
                        
                        # Validate new password if provided
                        if new_password is not None and not is_valid_password(new_password):
                            print("Invalid new password. Password must be 16-60 chars with uppercase, lowercase, digits, and symbols.")
                            if new_password is not None:
                                del new_password  # Clean up invalid password
                            continue
                        
                        # Update entry
                        if encrypted_db.edit_entry(service, username=new_username, password=new_password):
                            print(f"✓ Entry edited for service {service}.")
                            session.last_auth = datetime.now()
                        else:
                            print(f"✗ Failed to edit entry for {service}.")
                        
                        if new_password is not None:
                            del new_password
                    else:
                        print("Usage: edit <service>")
                
                elif cmd == 'list':
                    services = encrypted_db.list_services()
                    if services:
                        print("Stored services:")
                        for service in services:
                            print(f"  - {service}")
                        del services # Clean up
                        session.last_auth = datetime.now()
                    else:
                        print("No services stored.")
                
                elif cmd == 'show':
                    entry = encrypted_db.get_entry(args.service)
                    if entry:
                        print(f"Entry for '{args.service}':")
                        print(f"  Username: {entry['username']}")
                        session.last_auth = datetime.now()
                        if getattr(args, 'reveal', False):
                            print(f"  Password: {entry['password']}")
                        else:
                            print("  Password: [hidden] (use --reveal to display)")
                    else:
                        print(f"No entry found for service '{args.service}'.")
                
                elif cmd == 'copy':
                    # COPY command - copy password to clipboard
                    if hasattr(args, 'service'):
                        service = args.service
                        
                        # Check if service exists
                        entry = encrypted_db.get_entry(service)
                        if not entry:
                            print(f"Service '{service}' not found.")
                            continue
                        
                        # Get the password
                        password = entry['password']
                        del entry  # Clean up entry reference

                        try:
                            # Copy to clipboard
                            pyperclip.copy(password)
                            print(f"Password for '{service}' copied to clipboard.")
                            print("⚠️  Remember to clear clipboard after use (paste or copy something else)")
                            del password
                            
                            session.last_auth = datetime.now()
                            
                        except Exception as e:
                            print(f"Failed to copy to clipboard: {e}")
                            print("Make sure pyperclip is installed: pip install pyperclip")
                            del password
                    else:
                        print("Usage: copy <service>")
                
                elif cmd == 'delete':
                    if not getattr(args, 'yes', False):
                        confirm = input(f"Type the service name to confirm deletion ('{args.service}'): ").strip()
                        if confirm != args.service:
                            print("Deletion aborted: confirmation did not match.")
                            continue
                    
                    if encrypted_db.delete_entry(args.service):
                        print(f"✓ Entry deleted for service '{args.service}'.")
                        session.last_auth = datetime.now()
                    else:
                        print(f"✗ Failed to delete entry for '{args.service}'.")
                
                elif cmd == 'backup':
                    ok = backup_database(session.user_id)
                    print("Backup created." if ok else "Backup failed.")
                    session.last_auth = datetime.now()
                
                elif cmd == 'restore':
                    ok = restore_database(session.user_id)
                    if ok:
                        encrypted_db.reload_from_disk()
                        print("✓ Database restored from backup.")
                    else:
                        print("✗ Restore failed.")
                    session.last_auth = datetime.now()
                
                elif cmd == 'lock':
                    print("🔒 Session locked. All sensitive data cleared from memory.")
                    
                    # Stop the background expiry thread
                    expiry_stop.set()
                    
                    # Clear sensitive data
                    encrypted_db.clear()
                    session.clear_key()
                    session.last_auth = None
                    
                    # Re-authenticate immediately
                    print("\nRe-authentication required to unlock session.")
                    result = prompt_and_verify_two_factor()
                    if result is None:
                        print("Re-authentication failed. Ending session.")
                        break
                    
                    k_db, user_id = result
                    
                    # Verify same user
                    if user_id != session.user_id:
                        print(f"✗ Error: Different DNIe detected")
                        del k_db
                        del user_id
                        break
                    
                    del user_id
                    
                    # Restore session
                    session.fernet_key = k_db
                    del k_db
                    
                    # Lock key in memory
                    if len(session.fernet_key) <= MAX_MLOCK_SIZE_LINUX:
                        try:
                            mlock(session.fernet_key)
                            session._key_locked = True
                        except Exception as e:
                            print(f"Note: Could not lock key in memory: {e}")
                            session._key_locked = False
                    
                    session.last_auth = datetime.now()
                    
                    # Restart expiry thread
                    expiry_stop = auto_expire_session(session, check_interval=30)
                    
                    # Recreate database wrapper
                    db_file = get_db_filename(session.user_id)
                    encrypted_db = EncryptedDatabase(bytes(session.fernet_key), db_filename=db_file)
                    
                    print("✓ Session unlocked successfully.\n")
                    continue
                
                elif cmd == 'init':
                    confirm = input("Type 'INIT' to confirm re-initialization (this overwrites keys and data): ").strip()
                    if confirm != "INIT":
                        print("Initialization aborted: confirmation did not match.")
                        continue
                    
                    # Re-authenticate before reinit
                    result = prompt_and_verify_two_factor()
                    if result is None:
                        print("Re-authentication failed.")
                        break
                    
                    auth_k_db, auth_user_id = result
                    del auth_k_db
                    
                    # Verify it's the same user trying to reinit their own database
                    if auth_user_id != session.user_id:
                        print(f"✗ Error: Cannot reinit database of different user")
                        del auth_user_id
                        continue
                    
                    # Get DNIe hash for this user to unregister it
                    registry = load_dnie_registry()
                    dnie_hash_to_remove = None
                    for dnie_hash, info in registry.get('dnies', {}).items():
                        if info.get('user_id') == auth_user_id:
                            dnie_hash_to_remove = dnie_hash
                            break

                    del auth_user_id

                        # Delete only this user's files
                    user_files = [
                        get_db_filename(session.user_id),
                        get_salt_filename(session.user_id),
                        get_wrapped_key_filename(session.user_id),
                        get_backup_filename(session.user_id)
                    ]
                    
                    destroy_database_files(session.user_id)
                    
                    # Unregister the DNIe from the registry
                    if dnie_hash_to_remove:
                        registry = load_dnie_registry()
                        if dnie_hash_to_remove in registry.get('dnies', {}):
                            del registry['dnies'][dnie_hash_to_remove]
                            save_dnie_registry(registry)
                            print(f"✓ DNIe unregistered from system")

                    # Call init_database() which now handles two-factor setup
                    new_result = init_database()
                    if new_result is None:
                        print("Initialization failed.")
                        break
                    
                    new_k_db, new_user_id = new_result

                    # Verify it's still the same user
                    if new_user_id != session.user_id:
                        print(f"✗ Error: User mismatch after init")
                        del new_k_db
                        del new_user_id
                        break
                    
                    del new_user_id

                    # Update session with new key
                    session.clear_key()
                    session.fernet_key = new_k_db
                    del new_k_db  # Remove reference to temporary result
                    # Lock new key in memory
                    if len(session.fernet_key) <= MAX_MLOCK_SIZE_LINUX:
                        try:
                            mlock(session.fernet_key)
                            session._key_locked = True
                        except Exception as e:
                            print(f"Note: Could not lock key in memory: {e}")
                            session._key_locked = False

                    session.last_auth = datetime.now()

                    # Create new database wrapper with new key
                    encrypted_db = EncryptedDatabase(bytes(session.fernet_key), db_filename=db_file)
                    print("✓ Database re-initialized successfully.")
                
                elif cmd == 'destroy-db':
                    confirm = input("Type 'DELETE' to confirm database destruction: ").strip()
                    if confirm != "DELETE":
                        print("Destruction aborted: confirmation did not match.")
                        continue
                    
                    # Force re-authentication before destruction
                    result = prompt_and_verify_two_factor()
                    if result is None:
                        print("Re-authentication failed. Cannot destroy database.")
                        break
                    
                    auth_k_db, auth_user_id = result
                    del auth_k_db  # Don't need the key, just verify identity

                    # Verify it's the same user trying to destroy their own database
                    if auth_user_id != session.user_id:
                        print(f"✗ Error: Cannot destroy database of different user")
                        print(f"   Current session: {session.user_id}")
                        print(f"   Authenticated as: {auth_user_id}")
                        del auth_user_id
                        continue
                    
                    del auth_user_id
                    
                    print(f"\n⚠ WARNING: About to permanently delete all data for user {session.user_id}")
                    final_confirm = input("Type 'CONFIRM DELETE' to proceed: ").strip()
                    if final_confirm != "CONFIRM DELETE":
                        print("Destruction cancelled.")
                        continue

                    # Get DNIe hash for this user to unregister it
                    registry = load_dnie_registry()
                    dnie_hash_to_remove = None
                    for dnie_hash, info in registry.get('dnies', {}).items():
                        if info.get('user_id') == session.user_id:
                            dnie_hash_to_remove = dnie_hash
                            break

                    # Destroy this user's database files
                    removed = destroy_database_files(session.user_id)
                    
                    if removed:
                        print("✓ Database files securely deleted.")
                        # Unregister the DNIe from the registry
                        if dnie_hash_to_remove:
                            registry = load_dnie_registry()
                            if dnie_hash_to_remove in registry.get('dnies', {}):
                                del registry['dnies'][dnie_hash_to_remove]
                                save_dnie_registry(registry)
                                print(f"✓ DNIe unregistered from system")

                        print("  Session will now end.")
                    else:
                        print("✗ No database files found to remove.")
                    
                    break  # End session after destruction
                
                elif cmd == 'help':
                    cmd_parser.print_help()
        
        finally:
            # Secure cleanup on exit
            print("\nSecurely cleaning up sensitive data...")
            encrypted_db.clear()
            session.clear_key()
            print("Session ended. All sensitive data cleared from memory.")


def main():
    """Main entry point for the password manager."""

    # Secure all sensitive files on startup
    secure_all_sensitive_files()

    # Check if database exists (verify registry)
    if not os.path.exists(DNIE_REGISTRY_FILE) or len(load_dnie_registry().get('dnies', {})) == 0:
        # No database - run initialization
        print("=" * 80)
        print("WELCOME TO PASSWORD MANAGER")
        print("=" * 80)
        print("\nNo database found. Running first-time setup...\n")
        
        result = init_database()
        if result is None:
            return

        print("\n✓ Setup complete! Starting session...\n")
        
        # Start session with keys from init (skip authentication)
        run_session(timeout_minutes=4, initial_result=result)
        del result
    else:
        # Normal session (will authenticate)
        run_session(timeout_minutes=4)
    

if __name__ == "__main__":
    main()