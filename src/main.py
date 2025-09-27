import argparse
import getpass
import os
import base64
from crypto import derive_key_from_password
from database import (
    is_valid_password, is_valid_entry, load_database, save_database,
    add_entry, edit_entry, list_services, get_entry
)


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

    print("Derived encryption key:", fernet_key.decode())

    # Load encrypted DB or create new empty dict if nonexistent
    db = load_database(fernet_key)

    # Save immediately to confirm encrypted database creation/updating
    if save_database(db, fernet_key):
        print("Database initialized and saved securely with derived key.")

    

def main():
    parser = argparse.ArgumentParser(description='Password Manager CLI')
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('init', help='Initialize the password database')

    parser_add = subparsers.add_parser('add', help='Add a password entry')
    parser_add.add_argument('service', help='Service name')
    parser_add.add_argument('username', help='Username/email for the service')
    parser_add.add_argument('password', help='Password for the service')

    parser_edit = subparsers.add_parser('edit', help='Edit a password entry')
    parser_edit.add_argument('service', help='Service to edit')
    parser_edit.add_argument('--username', help='New username/email')
    parser_edit.add_argument('--password', help='New password')

    subparsers.add_parser('list', help='List all services')

    parser_show = subparsers.add_parser('show', help='Show entry details')
    parser_show.add_argument('service', help='Service to show')


    args = parser.parse_args()

    if args.command == 'init':
        init_database()
    elif args.command in ['add', 'edit', 'list', 'show']:
        if not os.path.exists(SALT_FILE):
            print("Error: Database not initialized. Run 'init' first.")
            return
        salt = load_salt()
        password = prompt_master_password()
        key_bytes = derive_key_from_password(password, salt)
        fernet_key = base64.urlsafe_b64encode(key_bytes)

        db = load_database(fernet_key)

        if args.command == 'add':
            if not is_valid_entry(args.service, args.username, args.password):
                print("Invalid entry. Check service, username, and password validity.")
                return
            add_entry(db, args.service, args.username, args.password)
            save_database(db, fernet_key)
            print(f"Entry added for service '{args.service}'.")

        elif args.command == 'edit':
            if args.username is None and args.password is None:
                print("Nothing to update. Provide --username and/or --password.")
                return
            if args.password is not None and not is_valid_password(args.password):
                print("Invalid new password.")
                return
            edit_entry(db, args.service, username=args.username, password=args.password)
            save_database(db, fernet_key)
            print(f"Entry edited for service '{args.service}'.")

        elif args.command == 'list':
            services = list_services(db)
            if services:
                print("Stored services:")
                for service in services:
                    print(f" - {service}")
            else:
                print("No services stored.")

        elif args.command == 'show':
            entry = get_entry(db, args.service)
            if entry:
                print(f"Entry for '{args.service}':")
                print(f" Username: {entry['username']}")
                print(f" Password: {entry['password']}")
            else:
                print(f"No entry found for service '{args.service}'.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()