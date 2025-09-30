import argparse
import getpass
import os
import base64
import shlex
from datetime import datetime, timedelta

from crypto import derive_key_from_password
from database import (
    is_valid_password, is_valid_entry, load_database, save_database,
    add_entry, edit_entry, list_services, get_entry, delete_entry,
    backup_database, restore_database, destroy_database_files
)

DEFAULT_SESSION_MINUTES = 4 # default session inactivity timeout in minutes

SALT_FILE = 'db_salt.bin'

def prompt_master_password():
    while True:
        password = getpass.getpass("Enter master password: ")
        if is_valid_password(password):
            print("Password accepted.")
            return password
        else:
            print("Invalid password. Password must be 16-60 chars with uppercase, lowercase, digits, and symbols. Try again.\n")

def generate_salt():
    return os.urandom(16)

def save_salt(salt):
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)

def load_salt():
    with open(SALT_FILE, 'rb') as f:
        return f.read()

def init_database():
    # Check if salt exists, else generate and save it
    if not os.path.exists(SALT_FILE):
        salt = generate_salt()
        save_salt(salt)
        print("Salt generated and saved.")
    else:
        salt = load_salt()
        print("Salt loaded.")

    password = prompt_master_password()
    key_bytes = derive_key_from_password(password, salt)
    fernet_key = base64.urlsafe_b64encode(key_bytes)

    # Load encrypted DB or create new empty dict if nonexistent
    db = load_database(fernet_key)

    # Save immediately to confirm encrypted database creation/updating
    if save_database(db, fernet_key):
        print("Database initialized and saved securely.")

class Session:
    def __init__(self, timeout_minutes=DEFAULT_SESSION_MINUTES):
        self.timeout = timedelta(minutes=timeout_minutes)
        self.fernet_key = None
        self.last_auth = None

    def expired(self):
        return self.last_auth is None or datetime.now() - self.last_auth > self.timeout

    def ensure_unlocked(self, load_salt_fn, derive_fn, prompt_fn):
        if self.expired():
            salt = load_salt_fn()
            password = prompt_fn()
            key_bytes = derive_fn(password, salt)
            self.fernet_key = base64.urlsafe_b64encode(key_bytes)
            self.last_auth = datetime.now()
        return self.fernet_key

def run_session(timeout_minutes, parser):
    session = Session(timeout_minutes=timeout_minutes)
        # Initialize on first run if needed (all inside session)
    if not os.path.exists(SALT_FILE):
        print("No salt found; initializing a new database...")
        salt = generate_salt()
        save_salt(salt)
        password = prompt_master_password()
        key_bytes = derive_key_from_password(password, salt)
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        db = {}  # new, empty DB
        if save_database(db, fernet_key):
            print("Database initialized.")
        session.fernet_key = fernet_key
        session.last_auth = datetime.now()
    else:
        # Unlock once at session start
        fernet_key = session.ensure_unlocked(load_salt, derive_key_from_password, prompt_master_password)
        db = load_database(fernet_key)

    print(f"Session started; timeout set to {timeout_minutes} minutes; type 'help' or 'exit' to quit.")
    while True:
        try:
            line = input("pm> ").strip()
        except EOFError:
            break
        if not line:
            continue
        if line in ("exit", "quit"):
            break
        if line in ("help", "?"):
            print("Commands: init | add <service> <username> <password> | edit <service> [--username U] [--password P] | list | show <service> [--reveal] | delete <service> [--yes] | backup | restore | destroy-db")
            continue

        # Re-auth if session expired before executing the command
        if session.expired():
            print("Session expired; please re-authenticate.")
            fernet_key = session.ensure_unlocked(load_salt, derive_key_from_password, prompt_master_password)
            db = load_database(fernet_key)

        # Reuse the main parser to parse subcommands
        try:
            args = parser.parse_args(shlex.split(line))
        except SystemExit:
            continue

        cmd = args.command
        if cmd is None:
            print("Unknown command; type 'help' for usage.")
            continue


        # Data-access commands using cached fernet_key/db
        if cmd == 'add':
            if not is_valid_entry(args.service, args.username, args.password):
                print("Invalid entry. Check service, username, and password validity.")
                continue
            if not add_entry(db, args.service, args.username, args.password):
                print(f"Add failed for service '{args.service}'.")
                continue
            if save_database(db, fernet_key):
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
            if save_database(db, fernet_key):
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
            if save_database(db, fernet_key):
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
                db = load_database(fernet_key)  # reload after restore
                
        elif cmd == 'init':
            confirm = input("Type 'INIT' to confirm re-initialization (this overwrites keys and data): ").strip()
            if confirm != "INIT":
                print("Initialization aborted: confirmation did not match.")
                continue
            _ = prompt_master_password()  # re-auth
            salt = generate_salt()
            save_salt(salt)
            password = prompt_master_password()
            key_bytes = derive_key_from_password(password, salt)
            fernet_key = base64.urlsafe_b64encode(key_bytes)
            db = {}  # wipe to empty
            if save_database(db, fernet_key):
                print("Database re-initialized.")
                session.fernet_key = fernet_key
                session.last_auth = datetime.now()
            else:
                print("Failed to save database after re-initialization.")

        elif cmd == 'destroy-db':
            confirm = input("Type 'DELETE' to confirm database destruction: ").strip()
            if confirm != "DELETE":
                print("Destruction aborted: confirmation did not match.")
                continue
            _ = prompt_master_password()  # force re-auth even if session active
            removed = destroy_database_files()
            print("Database files removed." if removed else "No database files found to remove.")
            break  # end session after destruction


    print("Session ended.")


def build_cli_parser():
    # Minimal CLI: only a flag to control the session timeout
    parser = argparse.ArgumentParser(description='Password Manager CLI')
    parser.add_argument(
        '--session-timeout',
        type=int,
        default=DEFAULT_SESSION_MINUTES,
        help='Session timeout in minutes (default: 10)'
    )
    return parser

def build_repl_parser():
    # Parser used only inside the REPL
    parser = argparse.ArgumentParser(prog='pm', add_help=False)
    subparsers = parser.add_subparsers(dest='command')

    # Session commands only
    sp = subparsers.add_parser('add');              sp.add_argument('service'); sp.add_argument('username'); sp.add_argument('password')
    sp = subparsers.add_parser('edit');             sp.add_argument('service'); sp.add_argument('--username'); sp.add_argument('--password')
    subparsers.add_parser('list')
    sp = subparsers.add_parser('show');             sp.add_argument('service'); sp.add_argument('--reveal', action='store_true')
    sp = subparsers.add_parser('delete');           sp.add_argument('service'); sp.add_argument('--yes', action='store_true')
    subparsers.add_parser('backup')
    subparsers.add_parser('restore')
    subparsers.add_parser('destroy-db')
    subparsers.add_parser('init')
    return parser


def main():
    # Build minimal CLI parser and the REPL parser
    cli_parser = build_cli_parser()
    repl_parser = build_repl_parser()

    # Parse only --session-timeout, then auto-start the session
    args = cli_parser.parse_args()
    run_session(args.session_timeout, repl_parser)

if __name__ == "__main__":
    main()