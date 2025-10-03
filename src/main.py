import argparse
import os
import base64
import sys
import shlex
from datetime import datetime, timedelta
from crypto import derive_key_from_password
from database import (
    is_valid_password, is_valid_entry, load_database, save_database,
    add_entry, edit_entry, list_services, get_entry, delete_entry,
    backup_database, restore_database, destroy_database_files
)

# Import secure memory handling
try:
    from zeroize import zeroize1, mlock, munlock
except ImportError:
    print("✗ CRITICAL ERROR: zeroize library is required but not installed.")
    print("Install it with: pip install zeroize")
    print("Exiting for security reasons.")
    import sys
    sys.exit(1)


DEFAULT_SESSION_MINUTES = 4 # default session inactivity timeout in minutes
SALT_FILE = 'db_salt.bin'

# Memory locking limits
MAX_MLOCK_SIZE_LINUX = 2662 * 1024  # 2662 KB on Linux
MAX_MLOCK_SIZE_WINDOWS = 128 * 1024  # 128 KB default on Windows

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

            # Convert password to bytearray for secure handling
            password_bytes = bytearray(password.encode('utf-8'))
            password_locked = False
            key_bytearray_locked = False

            try:
                # Lock password in memory (if small enough)
                if len(password_bytes) < MAX_MLOCK_SIZE_LINUX:
                    try:
                        mlock(password_bytes)
                        password_locked = True
                    except Exception as e:
                        print(f"Note: Could not lock password memory: {e}")

                # Derive key from password
                key_bytes = derive_fn(password, salt)

                # Convert to bytearray and lock in memory
                key_bytearray = bytearray(key_bytes)

                if len(key_bytearray) < MAX_MLOCK_SIZE_LINUX:
                    try:
                        mlock(key_bytearray)
                        key_bytearray_locked = True
                    except Exception as e:
                        print(f"Note: Could not lock key memory: {e}")

                # Encode for Fernet (still as bytearray)
                self.fernet_key = bytearray(base64.urlsafe_b64encode(key_bytearray))

                # Lock the final Fernet key in memory
                if len(self.fernet_key) < MAX_MLOCK_SIZE_LINUX:
                    try:
                        mlock(self.fernet_key)
                        self._key_locked = True
                    except Exception as e:
                        print(f"Note: Could not lock fernet key memory: {e}")
                        self._key_locked = False

                # Securely zero intermediate values
                # CRITICAL: Unlock BEFORE zeroizing
                if key_bytearray_locked:
                    try:
                        munlock(key_bytearray)
                    except Exception:
                        pass
                zeroize1(key_bytearray)

            finally:
                # Always zero the password
                try:
                    if password_locked:
                        munlock(password_bytes)
                    zeroize1(password_bytes)
                except Exception:
                    pass

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
    

def input_password_masked(prompt='Password: ', mask_char='●'):
    """Read password from the user with masking for each key stroke."""
    print(prompt, end='', flush=True)
    password = ''
    try:
        import msvcrt
        while True:
            ch = msvcrt.getch()
            if ch in {b'\r', b'\n'}:  # Enter key
                print()
                break
            elif ch == b'\x08':  # Backspace
                if len(password) > 0:
                    password = password[:-1]
                    sys.stdout.write('\b \b')
            elif ch == b'\x03':  # Ctrl-C
                raise KeyboardInterrupt
            else:
                password += ch.decode('utf-8')
                sys.stdout.write(mask_char)
            sys.stdout.flush()
    except ImportError:
        import tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                ch = sys.stdin.read(1)
                if ch in {'\r', '\n'}:
                    print()
                    break
                elif ch == '\x7f':  # Backspace
                    if len(password) > 0:
                        password = password[:-1]
                        sys.stdout.write('\b \b')
                elif ch == '\x03':  # Ctrl-C
                    raise KeyboardInterrupt
                else:
                    password += ch
                    sys.stdout.write(mask_char)
                sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return password


def prompt_master_password():
    """
    Prompt for master password with validation.
    Returns password as string (will be converted to bytearray for secure handling).
    """
    while True:
        password = input_password_masked("Enter master password: ")
        if is_valid_password(password):
            print("Password accepted.")
            return password
        else:
            # Zero invalid password before continuing
            temp = bytearray(password.encode('utf-8'))
            zeroize1(temp)
            print("Invalid password. Password must be 16-60 chars with uppercase, lowercase, digits, and symbols. Try again.\n")

def prompt_and_verify_password(load_salt_fn, derive_fn):
    """
    Prompt for master password and verify it can decrypt the database.
    Returns (fernet_key, db) if successful, (None, None) on failure.
    Includes secure memory zeroing on failed attempts.
    """
    MAX_ATTEMPTS = 3
    
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\nAuthentication attempt {attempt}/{MAX_ATTEMPTS}")
        password = input_password_masked("Enter master password: ")
        
        # Validate format first
        if not is_valid_password(password):
            print("Invalid password format.")
            password_bytes = bytearray(password.encode('utf-8'))
            zeroize1(password_bytes)
            continue
        
        # Secure handling with cleanup
        password_bytes = bytearray(password.encode('utf-8'))
        password_locked = False
        key_bytes = None
        key_array = None
        fernet_key = None
        
        try:
            # Lock password in memory
            if len(password_bytes) < MAX_MLOCK_SIZE_LINUX:
                try:
                    mlock(password_bytes)
                    password_locked = True
                except Exception:
                    pass
            
            # Derive key
            salt = load_salt_fn()
            key_bytes = derive_fn(password, salt)
            key_array = bytearray(key_bytes)
            fernet_key_bytes = base64.urlsafe_b64encode(key_array)
            fernet_key = bytearray(fernet_key_bytes)
            
            # TRY TO DECRYPT DATABASE (this verifies the password!)
            try:
                db = load_database(bytes(fernet_key))
                print("Password accepted.")
                
                # Success! Clean up intermediates
                zeroize1(key_array)
                
                return fernet_key, db
                
            except Exception:
                # Wrong password - decryption failed
                print(f"✗ Incorrect password or database corruption.")
                if attempt < MAX_ATTEMPTS:
                    print(f"  {MAX_ATTEMPTS - attempt} attempt(s) remaining.")
                
                # Clean up wrong key
                if key_array:
                    zeroize1(key_array)
                if fernet_key:
                    zeroize1(fernet_key)
                
                key_array = None
                fernet_key = None
        
        finally:
            # ALWAYS zero password
            try:
                if password_locked:
                    munlock(password_bytes)
                zeroize1(password_bytes)
            except Exception:
                pass
            
            # Clean up key_array (may already be zeroed on success, harmless to zero again)
            if key_array:
                try:
                    zeroize1(key_array)
                except Exception:
                    pass

    
    # All attempts failed
    print(f"\n✗ Authentication failed after {MAX_ATTEMPTS} attempts.")
    print("Exiting for security.")
    return None, None

def secure_clear_database(db):
    """
    Securely clear passwords from the database dictionary.

    Args:
        db: Dictionary containing password entries
    """
    if db is None:
        return

    for service, entry in db.items():
        if isinstance(entry, dict) and 'password' in entry:
            password_str = entry['password']
            password_bytes = bytearray(password_str.encode('utf-8'))

            try:
                zeroize1(password_bytes)
            except Exception:
                pass


def generate_salt():
    """Generate a cryptographically secure random salt."""
    return os.urandom(16)

def save_salt(salt):
    """Save salt to file."""    
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)

def load_salt():
    """Load salt from file."""
    with open(SALT_FILE, 'rb') as f:
        return f.read()

def init_database():
    """Initialize a new password database with secure key generation."""
    if os.path.exists(SALT_FILE):
        print("Database already initialized. Use --reset to start fresh.")
        return

    print("Initializing new password database...")

    # Generate and save salt
    salt = generate_salt()
    save_salt(salt)

    # Prompt for master password
    password = prompt_master_password()
    password_bytes = bytearray(password.encode('utf-8'))

    try:
        # Lock password in memory temporarily
        if len(password_bytes) < MAX_MLOCK_SIZE_LINUX:
            try:
                mlock(password_bytes)
            except Exception as e:
                print(f"Note: Could not lock password memory: {e}")

        # Derive key
        key_bytes = derive_key_from_password(password, salt)
        fernet_key = base64.urlsafe_b64encode(key_bytes)

        # Create empty database
        empty_db = {}
        save_database(empty_db, fernet_key)

        print("Database initialized successfully!")

        # Securely zero key material
        key_array = bytearray(key_bytes)
        zeroize1(key_array)
        fernet_array = bytearray(fernet_key)
        zeroize1(fernet_array)

    finally:
        # Always zero password
        try:
            zeroize1(password_bytes)
            munlock(password_bytes)
        except Exception:
            pass

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
    add_p.add_argument('password', help='Password (16-60 chars, uppercase, lowercase, digit, symbol)')
    
    # EDIT command - ENHANCED
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
──────────────────────────────────────────────────────────────────────

  add <service> <username> <password>
    Add a new password entry
    Example: add gmail user@gmail.com MySecureP@ss123!

  edit <service> [--username NEW_USER] [--password NEW_PASS]
    Edit username and/or password for existing entry
    Example: edit gmail --password NewP@ssword456!
    Example: edit gmail --username newuser@gmail.com --password NewPass123!

  show <service> [--reveal]
    Show entry details (password hidden by default)
    Example: show gmail
    Example: show gmail --reveal

  delete <service> [-y]
    Delete an entry (prompts for confirmation)
    Example: delete gmail
    Example: delete gmail -y  (skip confirmation)

  list
    List all stored services
    Example: list

🔧 DATABASE OPERATIONS
──────────────────────────────────────────────────────────────────────

  backup
    Create a backup of the encrypted database

  restore
    Restore database from the most recent backup

  init
    Re-initialize database with new master password
    ⚠️  WARNING: This destroys all existing data!

  destroy-db
    Permanently delete database and all backups
    ⚠️  WARNING: This is irreversible!

ℹ️  HELP & EXIT
──────────────────────────────────────────────────────────────────────

  help [command]
    Show this help or help for specific command
    Example: help
    Example: help add

  exit / quit
    Exit password manager (secure cleanup)

📋 PASSWORD REQUIREMENTS
──────────────────────────────────────────────────────────────────────
  • Length: 16-60 characters
  • Must include: uppercase, lowercase, digit, special character
  • Special characters: ! @ # $ % ^ & * ( ) - _ = + [ ] { } ; : , . < > ? /
  • International characters supported: ñ á é ü ö etc.
  • No spaces allowed

💡 TIP: Type 'help <command>' for detailed help on any command
    Example: help add
""")


def run_session(timeout_minutes, parser):
    """
    Main interactive session with enhanced security.
    Uses SecureSession for automatic memory locking and cleanup.
    """
    if not os.path.exists(SALT_FILE):
        print("No database found. Run with --init first.")
        return
    
    # Create command parser for interactive mode
    cmd_parser = create_command_parser()


    # Authenticate with verification
    result = prompt_and_verify_password(load_salt, derive_key_from_password)
    if result[0] is None:
        return  # Authentication failed
    
    fernet_key, db = result

    # Use context manager for automatic cleanup
    with SecureSession(timeout_minutes=timeout_minutes) as session:
        fernet_key_bytes = bytes(fernet_key)  # Copy FIRST
        session.fernet_key = fernet_key  # Then assign to session
        session.last_auth = datetime.now()

        print(f"\nWelcome to Password Manager (session timeout: {timeout_minutes} minutes)")
        print("Commands: add, edit, list, show, delete, backup, restore, init, destroy-db, exit, help")

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
                    print("\nSession expired; please re-authenticate.")
                    secure_clear_database(db)
                    
                    result = prompt_and_verify_password(load_salt, derive_key_from_password)
                    if result[0] is None:
                        print("Re-authentication failed. Ending session.")
                        break
                    
                    session.clear_key()
                    session.fernet_key = result[0]
                    session.last_auth = datetime.now()
                    fernet_key_bytes = bytes(result[0])
                    db = result[1]
                    print("Re-authenticated successfully.\n")

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
                    if not is_valid_entry(args.service, args.username, args.password):
                        print("Invalid entry. Check service, username, and password validity.")
                        continue
                    if not add_entry(db, args.service, args.username, args.password):
                        print(f"Add failed for service '{args.service}'.")
                        continue
                    if save_database(db, fernet_key_bytes):
                        print(f"Entry added for service '{args.service}'.")
                        session.last_auth = datetime.now()
                    else:
                        print("Failed to save database after add.")

                elif cmd == 'edit':
                    if args.username is None and args.password is None:
                        print("Nothing to update. Provide --username and/or --password.")
                        continue
                    if args.password is not None and not is_valid_password(args.password):
                        print("Invalid new password. Password must be 16-60 chars with uppercase, lowercase, digits, and symbols.")
                        continue
                    if not edit_entry(db, args.service, username=args.username, password=args.password):
                        print(f"Edit failed for service '{args.service}'.")
                        continue
                    if save_database(db, fernet_key_bytes):
                        print(f"Entry edited for service '{args.service}'.")
                        session.last_auth = datetime.now()
                    else:
                        print("Failed to save database after edit.")

                elif cmd == 'list':
                    services = list_services(db)
                    if services:
                        print("Stored services:")
                        for service in services:
                            print(f" - {service}")
                            session.last_auth = datetime.now()
                    else:
                        print("No services stored.")

                elif cmd == 'show':
                    entry = get_entry(db, args.service)
                    if entry:
                        print(f"Entry for '{args.service}':")
                        print(f" Username: {entry['username']}")
                        session.last_auth = datetime.now()
                        if getattr(args, 'reveal', False):
                            print(f" Password: {entry['password']}")
                        else:
                            print(" Password: [hidden]  (use --reveal to display)")
                    else:
                        print(f"No entry found for service '{args.service}'.")

                elif cmd == 'delete':
                    if not getattr(args, 'yes', False):
                        confirm = input(f"Type the service name to confirm deletion ('{args.service}'): ").strip()
                        if confirm != args.service:
                            print("Deletion aborted: confirmation did not match.")
                            continue
                    if not delete_entry(db, args.service):
                        print(f"Delete failed for service '{args.service}'.")
                        continue
                    if save_database(db, fernet_key_bytes):
                        print(f"Entry deleted for service '{args.service}'.")
                        session.last_auth = datetime.now()
                    else:
                        print("Failed to save database after delete.")

                elif cmd == 'backup':
                    ok = backup_database()
                    print("Backup created." if ok else "Backup failed.")
                    session.last_auth = datetime.now()

                elif cmd == 'restore':
                    ok = restore_database()
                    print("Database restored from backup." if ok else "Restore failed; no backup found or operation error.")
                    session.last_auth = datetime.now()
                    if ok:
                        db = load_database(fernet_key_bytes)  # reload after restore
                        
                elif cmd == 'init':
                    confirm = input("Type 'INIT' to confirm re-initialization (this overwrites keys and data): ").strip()
                    if confirm != "INIT":
                        print("Initialization aborted: confirmation did not match.")
                        continue

                    _ = prompt_master_password()  # re-auth
                    salt = generate_salt()
                    save_salt(salt)
                    password = prompt_master_password()

                    # Secure handling with zeroize
                    password_bytes = bytearray(password.encode('utf-8'))
                    password_locked = False

                    try:
                        # Lock password temporarily
                        if len(password_bytes) < MAX_MLOCK_SIZE_LINUX:
                            try:
                                mlock(password_bytes)
                                password_locked = True
                            except Exception as e:
                                print(f"Note: Could not lock password memory: {e}")

                        key_bytes = derive_key_from_password(password, salt)
                        key_array = bytearray(key_bytes)
                        fernet_key_bytes = base64.urlsafe_b64encode(key_array)
                        fernet_key = bytearray(fernet_key_bytes)

                        # Securely zero intermediate values
                        zeroize1(key_array)

                        db = {}  # wipe to empty

                        if save_database(db, bytes(fernet_key)):
                            print("Database re-initialized.")
                            # Update session with new key
                            session.clear_key()
                            session.fernet_key = fernet_key
                            session._key_locked = False
                            session.last_auth = datetime.now()
                            fernet_key_bytes = bytes(fernet_key)
                        else:
                            print("Failed to save database after re-initialization.")
                            # Clean up fernet_key since we're not using it
                            zeroize1(fernet_key)

                    finally:
                        # Always clean up password
                        try:
                            if password_locked:
                                munlock(password_bytes)
                            zeroize1(password_bytes)
                        except Exception:
                            pass

                elif cmd == 'destroy-db':
                    confirm = input("Type 'DELETE' to confirm database destruction: ").strip()
                    if confirm != "DELETE":
                        print("Destruction aborted: confirmation did not match.")
                        continue
                    _ = prompt_master_password()  # force re-auth even if session active
                    removed = destroy_database_files()
                    print("Database files removed." if removed else "No database files found to remove.")
                    break  # end session after destruction

                elif cmd == 'help':
                    cmd_parser.print_help()

        finally:
            # Secure cleanup on exit
            print("\nSecurely cleaning up sensitive data...")
            secure_clear_database(db)

            # Session cleanup happens automatically via context manager
            print("Session ended. All sensitive data cleared from memory.")





def main():
    """Main entry point with command-line argument parsing."""

    # Secure the log file permissions
    from database import secure_log_file
    secure_log_file()

    parser = argparse.ArgumentParser(description="Secure Password Manager with Memory Protection")
    parser.add_argument("--init", action="store_true", help="Initialize a new database")
    parser.add_argument("--reset", action="store_true", help="Reset/destroy existing database")
    parser.add_argument("--timeout", type=int, default=DEFAULT_SESSION_MINUTES,
                        help=f"Session timeout in minutes (default: {DEFAULT_SESSION_MINUTES})")

    args = parser.parse_args()

    if args.reset:
        destroy_database_files()
        return

    if args.init:
        init_database()
        return

    # Run interactive session
    run_session(args.timeout, parser)

if __name__ == "__main__":
    main()