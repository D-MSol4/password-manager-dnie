import tkinter as tk
from tkinter import scrolledtext
from tkinter import font
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk, messagebox, simpledialog

import argparse
import os
import sys
import shlex
import json
import pyperclip
import time
import threading
import msvcrt
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from crypto import derive_key_from_password, unwrap_database_key, wrap_database_key
from database import (
    EncryptedDatabase, DNIE_REGISTRY_FILE, is_valid_password, is_valid_entry, save_database, backup_database, restore_database, 
    destroy_database_files, generate_random_password, secure_file_permissions, secure_all_sensitive_files,
    get_db_filename, get_salt_filename, get_wrapped_key_filename, get_backup_filename, load_dnie_registry
)
from smartcard_dnie import DNIeCard, DNIeCardError

# Símbolos adaptativos según el terminal
if sys.platform == 'win32' and 'WT_SESSION' not in os.environ:
    # cmd.exe tradicional - usar ASCII
    CHECK = '[OK]'
    CROSS = '[X]'
    WARNING = '[!]'
else:
    # Windows Terminal, Linux, Mac - usar Unicode
    CHECK = '✓'
    CROSS = '✗'
    WARNING = '⚠'

# Import secure memory handling
try:
    from zeroize import zeroize1, mlock, munlock
except ImportError:
    print(f"{CROSS} CRITICAL ERROR: zeroize library is required but not installed.")
    print("Install it with: pip install zeroize")
    print("Exiting for security reasons.")
    import sys
    sys.exit(1)

def input_password_masked(prompt="Password: "):
    """Get password with masking using msvcrt.getwch() for proper Unicode support."""
    print(prompt, end='', flush=True)
    password = ""
    
    while True:
        char = msvcrt.getwch()  # getwch() en lugar de getch() para Unicode
        
        if char in ('\r', '\n'):  # Enter
            print()
            break
        elif char == '\b':  # Backspace
            if len(password) > 0:
                password = password[:-1]
                # Borrar el asterisco en pantalla
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        elif char == '\x03':  # Ctrl+C
            print()
            raise KeyboardInterrupt
        else:
            password += char
            sys.stdout.write('*')
            sys.stdout.flush()
    
    return password

# Force UTF-8 encoding on Windows
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

class Session:
    """
    Enhanced Session class with Zeroize integration and key rotation support.
    Stores wrapping keys for automatic K_db rotation on logout.
    """
    
    def __init__(self, fernet_key, user_id, dnie_wrapping_key, password_key, timeout_minutes=DEFAULT_SESSION_MINUTES):
        self.timeout = timedelta(minutes=timeout_minutes)
        self.fernet_key = bytearray(fernet_key)
        self.user_id = user_id
        self.last_auth = datetime.now()
        self.key_locked = False
        
        # Store wrapping keys for auto-rotation on logout
        self.dnie_wrapping_key = bytearray(dnie_wrapping_key)
        self.password_key = bytearray(password_key)
        
    def expired(self):
        """Check if the session has expired."""
        return self.last_auth is None or datetime.now() - self.last_auth > self.timeout
    
    def clear_key(self):
        """Securely clear and unlock all stored keys."""
        if self.fernet_key is not None:
            try:
                if isinstance(self.fernet_key, bytearray):
                    if self.key_locked:
                        try:
                            munlock(self.fernet_key)
                        except Exception as e:
                            print(f"Warning: Failed to unlock key: {e}")
                        self.key_locked = False
                    zeroize1(self.fernet_key)
            except Exception as e:
                print(f"Warning: Failed to securely clear fernet key: {e}")
            finally:
                self.fernet_key = None
        
        # Clear wrapping keys
        if self.dnie_wrapping_key is not None:
            try:
                if isinstance(self.dnie_wrapping_key, bytearray):
                    zeroize1(self.dnie_wrapping_key)
            except Exception as e:
                print(f"Warning: Failed to clear DNIe wrapping key: {e}")
            finally:
                self.dnie_wrapping_key = None
                
        if self.password_key is not None:
            try:
                if isinstance(self.password_key, bytearray):
                    zeroize1(self.password_key)
            except Exception as e:
                print(f"Warning: Failed to clear password key: {e}")
            finally:
                self.password_key = None
    
    def __del__(self):
        """Ensure keys are cleared when session is destroyed."""
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
            for _ in range(check_interval):
                if stop_event.is_set():
                    return
                time.sleep(1)

            if session.expired():
                print("\nSession expired due to inactivity. Clearing key...")
                session.clear_key()
                print("Session locked. Re-authentication required on next command.\n")
                break
    
    thread = threading.Thread(target=checker, daemon=True, name="SessionExpiry")
    thread.start()
    return stop_event, thread

def prompt_and_verify_two_factor():
    """
    Autenticación DNIe + Master Password con GUI,
    idéntica a la versión consola.
    """
    MAX_ATTEMPTS = 3
    result = None

    # Ventana principal
    root = tk.Tk()
    root.title("Autenticación DNIe + Contraseña Maestra")
    root.geometry("600x520")
    root.configure(bg="#1e1e2f")
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('TLabel', background="#1e1e2f", foreground="#e0e0e0", font=('Segoe UI', 12))
    style.configure('TButton', font=('Segoe UI', 12), padding=6)

    frame = ttk.Frame(root, padding=10)
    frame.pack(fill='both', expand=True)
    log = ScrolledText(frame, height=12, bg="#2e2e3f", fg="white", font=('Consolas', 11))
    log.pack(fill='both', expand=True, pady=5)

    def append(msg):
        log.insert(tk.END, msg + "\n"); log.see(tk.END); root.update_idletasks()

    # Widgets
    pin_label = ttk.Label(frame, text="Ingrese PIN del DNIe:")
    pin_entry = ttk.Entry(frame, show="*")
    pin_btn = ttk.Button(frame, text="Enviar PIN")
    pass_label = ttk.Label(frame, text="Ingrese contraseña maestra:")
    pass_entry = ttk.Entry(frame, show="*")
    pass_btn = ttk.Button(frame, text="Enviar contraseña")

    for w in (pin_label, pin_entry, pin_btn, pass_label, pass_entry, pass_btn):
        w.pack_forget()

    # Estado
    attempt = 1
    card = dnie_hash = user_id = salt = wrapped_key_file = db_file = None
    dnie_wrapping_key = password_key = None

    # Funciones
    def process_pin():
        nonlocal attempt, dnie_wrapping_key
        pin = pin_entry.get().strip()
        if not pin:
            append("⚠️ Ingrese su PIN.")
            return
        try:
            dnie_wrapping_key = card.authenticate(pin)
            card.disconnect()
            append("[✓] PIN correcto")
            pin_label.pack_forget(); pin_entry.pack_forget(); pin_btn.pack_forget()
            pass_label.pack(pady=8); pass_entry.pack(pady=5); pass_btn.pack(pady=5)
        except Exception as e:
            append(f"[X] Error PIN: {e}")
            attempt += 1
            if attempt > MAX_ATTEMPTS:
                append("☠️ Máximos intentos alcanzados.")
                root.destroy()

    def process_password():
        nonlocal result, password_key, attempt
        pw = pass_entry.get()
        if not pw:
            append("⚠️ Ingrese contraseña maestra.")
            return
        try:
            append("🔑 Derivando clave de contraseña...")
            password_key = derive_key_from_password(pw, salt)
            del pw
            append("🔐 Leyendo wrapped key...")
            wrapped = open(wrapped_key_file, 'rb').read()
            append("🔓 Descifrando K_db...")
            k_db = unwrap_database_key(wrapped, dnie_wrapping_key, password_key)
            del wrapped
            append("🔍 Verificando base de datos...")
            enc = open(db_file, 'rb').read()
            Fernet(k_db).decrypt(enc)
            append("[✓] Autenticación exitosa")
            result = (bytearray(k_db), user_id, bytearray(dnie_wrapping_key), bytearray(password_key))
            root.destroy()
        except Exception as e:
            append(f"[X] Falló autenticación: {e}")
            attempt += 1
            if attempt > MAX_ATTEMPTS:
                append("☠️ Máximos intentos alcanzados.")
                root.destroy()
            else:
                pass_entry.delete(0, tk.END)

    pin_btn.config(command=process_pin)
    pass_btn.config(command=process_password)

    # STEP 1–3: Detectar DNIe, registro, cargar salt & archivos
    append(f"Intento {attempt}/{MAX_ATTEMPTS}")
    try:
        card = DNIeCard(); card.connect()
        append("[✓] DNIe detectado")
        dnie_hash = card.get_serial_hash()
        append(f"[✓] Identificado: {dnie_hash[:8]}…")
        if not is_dnie_registered(dnie_hash):
            if messagebox.askyesno("No registrado", "Inicializar nueva base?", parent=root):
                card.disconnect(); root.destroy()
                return init_database()
            else:
                card.disconnect(); root.destroy()
                return None
        append("[✓] DNIe registrado")
        user_id = get_user_id_from_dnie(dnie_hash)
        update_last_login(dnie_hash)
        salt_file = get_salt_filename(user_id)
        wrapped_key_file = get_wrapped_key_filename(user_id)
        db_file = get_db_filename(user_id)
        if not os.path.exists(salt_file) or not os.path.exists(wrapped_key_file):
            append("[X] Configuración faltante.")
            card.disconnect(); root.destroy()
            return None
        with open(salt_file, 'rb') as f:
            salt = f.read()
        pin_label.pack(pady=8); pin_entry.pack(pady=5); pin_btn.pack(pady=5)
    except Exception as e:
        append(f"[X] Error inicial: {e}")
        root.destroy()
        return None

    root.mainloop()
    return result




def auto_rotate_on_logout(session):
    """
    Automatically rotate K_db on logout for forward secrecy.
    
    Steps:
    1. Generate new random K_db
    2. Decrypt database with old K_db
    3. Re-encrypt database with new K_db
    4. Wrap new K_db with stored wrapping keys
    5. Save new wrapped key
    
    Args:
        session: Active session object containing keys
        
    Returns:
        bool: True if rotation succeeded, False otherwise
    """
    try:
        # Get files
        db_file = get_db_filename(session.user_id)
        wrapped_key_file = get_wrapped_key_filename(session.user_id)
        
        if not os.path.exists(db_file):
            print(f"{CROSS} Database file not found. Skipping rotation.")
            return False
        
        # Step 1: Generate new random K_db
        k_db_new_raw = Fernet.generate_key()
        k_db_new = bytearray(k_db_new_raw)
        del k_db_new_raw
        
        # Step 2: Load and decrypt database with old K_db
        k_db_old = bytes(session.fernet_key)
        fernet_old = Fernet(k_db_old)
        
        with open(db_file, 'rb') as f:
            encrypted_data_old = f.read()
        
        decrypted_data = fernet_old.decrypt(encrypted_data_old)
        del fernet_old
        del encrypted_data_old
        
        # Step 3: Re-encrypt with new K_db
        fernet_new = Fernet(bytes(k_db_new))
        encrypted_data_new = fernet_new.encrypt(decrypted_data)
        del fernet_new
        del decrypted_data
        
        # Step 4: Wrap new K_db with stored wrapping keys
        wrapped_k_db_new = wrap_database_key(
            bytes(k_db_new),
            bytes(session.dnie_wrapping_key),
            bytes(session.password_key)
        )
        
        # Step 5: Save new wrapped key and encrypted database
        with open(wrapped_key_file, 'wb') as f:
            f.write(wrapped_k_db_new)
        secure_file_permissions(wrapped_key_file)
        
        with open(db_file, 'wb') as f:
            f.write(encrypted_data_new)
        secure_file_permissions(db_file)
        
        # Cleanup
        del k_db_new
        del wrapped_k_db_new
        del encrypted_data_new
        
        return True
        
    except Exception as e:
        print(f"{CROSS} Key rotation failed: {e}")
        return False


def generate_salt():
    """Generate a cryptographically secure random salt."""
    return os.urandom(16)

def init_database():
    """Inicializa base de datos con K_db aleatorio protegido por firma DNIe + contraseña."""
    
    result_data = None
    
    root = tk.Tk()
    root.title("Inicialización - Gestor de Contraseñas con DNIe")
    root.geometry("700x550")
    root.configure(bg="#1e1e2f")
    
    # Estilo consistente con run_session y prompt_and_verify_two_factor
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('TFrame', background="#1e1e2f")
    style.configure('TLabel', background="#1e1e2f", foreground="#e0e0e0", font=('Segoe UI', 11))
    style.configure('TButton', font=('Segoe UI', 11), padding=8)
    
    # Frame principal
    frame = ttk.Frame(root, padding=20)
    frame.pack(fill='both', expand=True)
    
    # Título
    ttk.Label(frame, text="INICIALIZACIÓN - DESAFÍO DE FIRMA DNIe", 
              font=('Segoe UI', 16, 'bold')).pack(pady=(0, 10))
    
    # Área de log
    log_text = ScrolledText(frame, height=12, bg="#2e2e3f", fg="white", 
                           font=('Consolas', 10), wrap=tk.WORD, relief='flat')
    log_text.pack(fill='both', expand=True, pady=10)
    
    # Frame para inputs dinámicos
    input_frame = ttk.Frame(frame)
    input_frame.pack(fill='x', pady=10)
    
    # Variables globales
    card = None
    dnie_hash = None
    user_id = None
    
    # Widgets de entrada (ocultos inicialmente) - Usando ttk como en las otras funciones
    desc_label = ttk.Label(input_frame, text="Descripción del DNIe (opcional):")
    desc_entry = ttk.Entry(input_frame, width=40)
    
    pin_label = ttk.Label(input_frame, text="PIN del DNIe:")
    pin_entry = ttk.Entry(input_frame, show="*", width=40)
    
    pass_label = ttk.Label(input_frame, text="Contraseña maestra (mín. 16 caracteres):")
    pass_entry = ttk.Entry(input_frame, show="*", width=40)
    
    pass_confirm_label = ttk.Label(input_frame, text="Confirmar contraseña:")
    pass_confirm_entry = ttk.Entry(input_frame, show="*", width=40)
    
    confirm_label = ttk.Label(input_frame, text="⚠️ Escriba 'DELETE ALL' para sobrescribir:")
    confirm_label.configure(foreground="#ff5555")
    confirm_entry = ttk.Entry(input_frame, width=40)
    
    retry_label = ttk.Label(input_frame, text="DNIe no detectado. Inserte su tarjeta.")
    
    action_button = ttk.Button(input_frame, text="Continuar")
    cancel_button = ttk.Button(input_frame, text="Cancelar")
    
    def log(msg, tag=None):
        log_text.insert(tk.END, msg + "\n")
        if tag:
            # Configurar colores para tags
            if tag == 'success':
                start_idx = log_text.index(f"{tk.END}-{len(msg)+1}c")
                log_text.tag_add('success', start_idx, tk.END)
                log_text.tag_config('success', foreground='#e0e0e0')
            elif tag == 'error':
                start_idx = log_text.index(f"{tk.END}-{len(msg)+1}c")
                log_text.tag_add('error', start_idx, tk.END)
                log_text.tag_config('error', foreground='#ff5555')
            elif tag == 'warning':
                start_idx = log_text.index(f"{tk.END}-{len(msg)+1}c")
                log_text.tag_add('warning', start_idx, tk.END)
                log_text.tag_config('warning', foreground='#ffaa00')
        log_text.see(tk.END)
        root.update()
    
    def hide_all_inputs():
        for widget in [desc_label, desc_entry, pin_label, pin_entry, 
                      pass_label, pass_entry, pass_confirm_label, pass_confirm_entry,
                      confirm_label, confirm_entry, retry_label, action_button, cancel_button]:
            widget.pack_forget()
    
    def step1_detect_dnie():
        nonlocal card, dnie_hash, user_id
        
        log("=" * 70)
        log("Paso 1: Detección de DNIe")
        log("=" * 70)
        log("Conectando con el DNIe...")
        
        try:
            card = DNIeCard()
            card.connect()
            log("[✓] DNIe card detected", 'success')
            
            dnie_hash = card.get_serial_hash()
            log(f"[✓] DNIe identificado: {dnie_hash[:8]}...", 'success')
            
            if is_dnie_registered(dnie_hash):
                user_id = get_user_id_from_dnie(dnie_hash)
                log(f"⚠ Este DNIe ya está registrado como: {user_id}", 'warning')
                step2_check_existing()
            else:
                user_id = get_next_user_id()
                log(f"[✓] Nuevo usuario: {user_id}", 'success')
                step3_get_description()
                
        except DNIeCardError as e:
            if "not detected" in str(e).lower() or "no smart card" in str(e).lower():
                log("[✗] DNIe no detectado. Por favor inserte su DNIe.", 'error')
                hide_all_inputs()
                retry_label.pack(pady=10)
                action_button.config(text="Reintentar", command=step1_detect_dnie)
                action_button.pack(pady=10)
                cancel_button.config(command=lambda: [log("Inicialización cancelada"), root.destroy()])
                cancel_button.pack(pady=10)
            else:
                log(f"[✗] Error DNIe: {e}", 'error')
                root.after(2000, root.destroy)
    
    def step2_check_existing():
        salt_file = get_salt_filename(user_id)
        wrapped_key_file = get_wrapped_key_filename(user_id)
        
        if os.path.exists(salt_file) or os.path.exists(wrapped_key_file):
            log("=" * 70)
            log("⚠ ADVERTENCIA: Base de datos existente", 'warning')
            log("=" * 70)
            log("Ya existe una base de datos para este usuario.")
            log("Se eliminarán TODOS los datos actuales.", 'error')
            
            hide_all_inputs()
            confirm_label.pack(pady=10)
            confirm_entry.pack(fill='x', pady=5)
            action_button.config(text="Confirmar sobrescritura", 
                               command=lambda: [
                                   step3_get_description() if confirm_entry.get() == "DELETE ALL" else (
                                       log("[✗] Confirmación incorrecta. Cancelado.", 'error'),
                                       card.disconnect() if card else None,
                                       root.after(1500, root.destroy)
                                   )
                               ])
            action_button.pack(pady=10)
            cancel_button.config(command=lambda: [
                log("Inicialización cancelada"),
                card.disconnect() if card else None,
                root.destroy()
            ])
            cancel_button.pack(pady=10)
            confirm_entry.focus()
        else:
            step3_get_description()
    
    def step3_get_description():
        is_new = not is_dnie_registered(dnie_hash)
        
        if is_new:
            log("\n[✓] Nuevo registro de DNIe", 'success')
            
            hide_all_inputs()
            desc_label.pack(pady=5)
            desc_entry.pack(fill='x', pady=5)
            desc_entry.insert(0, f"User {user_id}")
            action_button.config(text="Continuar", command=step4_authenticate)
            action_button.pack(pady=10)
            desc_entry.focus()
        else:
            step4_authenticate()
    
    def step4_authenticate():
        nonlocal card
        
        description = desc_entry.get() if desc_entry.get() else f"User {user_id}"
        if len(description) > 50:
            log("⚠ Descripción demasiado larga, usando por defecto", 'warning')
            description = f"User {user_id}"
        else:
            log(f"[✓] Descripción: {description}", 'success')
        
        setattr(step4_authenticate, 'description', description)
        
        log("\n" + "=" * 70)
        log("Paso 2: Autenticación con PIN DNIe")
        log("=" * 70)
        
        hide_all_inputs()
        pin_label.pack(pady=5)
        pin_entry.pack(fill='x', pady=5)
        action_button.config(text="Autenticar", command=lambda: [
            log("Autenticando DNIe..."),
            root.update(),
            (lambda dw: [
                log("[✓] Desafío de firma exitoso", 'success'),
                card.disconnect(),
                setattr(step4_authenticate, 'dnie_wrapping_key', dw),
                step5_setup_password()
            ] if dw else [
                log(f"[✗] Error: PIN incorrecto o error de autenticación", 'error'),
                pin_entry.delete(0, tk.END),
                pin_entry.focus()
            ])(
                (lambda: [card.authenticate(pin_entry.get()), card.authenticate(pin_entry.get())][1] 
                 if pin_entry.get() else None)() if pin_entry.get() else (
                    log("[✗] Por favor ingrese el PIN", 'error'),
                    None
                )[1]
            )
        ])
        action_button.pack(pady=10)
        cancel_button.config(command=lambda: [
            card.disconnect() if card else None,
            root.destroy()
        ])
        cancel_button.pack(pady=10)
        pin_entry.focus()
        pin_entry.bind('<Return>', lambda e: action_button.invoke())
    
    def step5_setup_password():
        log("\n" + "=" * 70)
        log("Paso 3: Configuración de contraseña maestra")
        log("=" * 70)
        log("La contraseña debe tener al menos 16 caracteres")
        
        hide_all_inputs()
        pass_label.pack(pady=5)
        pass_entry.pack(fill='x', pady=5)
        pass_confirm_label.pack(pady=5)
        pass_confirm_entry.pack(fill='x', pady=5)
        
        action_button.config(text="Crear base de datos", command=lambda: [
            (lambda p1, p2: [
                (lambda: [
                    log("[✓] Contraseñas coinciden", 'success'),
                    (lambda salt: [
                    log("[✓] Clave de contraseña derivada", 'success'),
                    step6_create_database(salt, getattr(step4_authenticate, 'dnie_wrapping_key'),
                                        derive_key_from_password(p1, salt),
                                        getattr(step4_authenticate, 'description'))
                ])(generate_salt())

                ] if is_valid_password(p1) else [
                    log("[✗] Contraseña debe tener al menos 16 caracteres", 'error'),
                    pass_entry.delete(0, tk.END),
                    pass_confirm_entry.delete(0, tk.END),
                    pass_entry.focus()
                ])() if p1 == p2 else [
                    log("[✗] Las contraseñas no coinciden", 'error'),
                    pass_entry.delete(0, tk.END),
                    pass_confirm_entry.delete(0, tk.END),
                    pass_entry.focus()
                ]
            ])(pass_entry.get(), pass_confirm_entry.get()) if pass_entry.get() and pass_confirm_entry.get() else [
                log("[✗] Por favor complete ambos campos", 'error')
            ]
        ])
        action_button.pack(pady=10)
        pass_entry.focus()
        pass_entry.bind('<Return>', lambda e: pass_confirm_entry.focus())
        pass_confirm_entry.bind('<Return>', lambda e: action_button.invoke())
    
    def step6_create_database(salt, dnie_wrapping_key, password_key, description):
        nonlocal result_data
        
        try:
            log("\n" + "=" * 70)
            log("Paso 4: Generando clave aleatoria de base de datos...")
            k_db = Fernet.generate_key()
            log(f"[✓] K_db generado ({len(k_db)} bytes)", 'success')
            
            log("\nPaso 5: Envolviendo clave de base de datos...")
            wrapped_k_db = wrap_database_key(k_db, dnie_wrapping_key, password_key)
            log("[✓] K_db envuelto correctamente", 'success')
            
            salt_file = get_salt_filename(user_id)
            wrapped_key_file = get_wrapped_key_filename(user_id)
            db_file = get_db_filename(user_id)
            
            with open(salt_file, 'wb') as f:
                f.write(salt)
            secure_file_permissions(salt_file)
            
            with open(wrapped_key_file, 'wb') as f:
                f.write(wrapped_k_db)
            del wrapped_k_db
            secure_file_permissions(wrapped_key_file)
            
            log("\nPaso 6: Creando base de datos cifrada...")
            empty_db = {}
            save_database(empty_db, k_db, db_file)
            log("[✓] Base de datos creada y cifrada con K_db", 'success')
            
            if description is not None:
                register_dnie(dnie_hash, user_id, description)
                log(f"[✓] DNIe registrado en el sistema", 'success')
            
            log("\n" + "=" * 70)
            log("✓ ¡INICIALIZACIÓN COMPLETA!", 'success')
            log("=" * 70)
            log("\n🔐 Su base de datos está protegida por:")
            log("  • K_db aleatorio (almacenado cifrado)")
            log("  • Desafío de firma DNIe (requiere tarjeta + PIN)")
            log("  • Contraseña maestra (clave derivada Argon2id)")
            log("\nCerrando ventana...")
            
            result_data = (bytearray(k_db), user_id, bytearray(dnie_wrapping_key), bytearray(password_key))
            
            hide_all_inputs()
            root.after(3000, root.destroy)
            
        except Exception as e:
            log(f"\n[✗] Inicialización fallida: {e}", 'error')
            
            try:
                for f in [get_salt_filename(user_id), get_wrapped_key_filename(user_id), get_db_filename(user_id)]:
                    if os.path.exists(f):
                        os.remove(f)
            except:
                pass
            
            root.after(2000, root.destroy)
    
    # Iniciar proceso automáticamente
    log("Iniciando configuración inicial del gestor de contraseñas...")
    log("Por favor espere...\n")
    root.after(500, step1_detect_dnie)
    
    root.mainloop()
    
    return result_data



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
        description='{WARNING}  Destroy current database and create new one with new master password. ALL DATA WILL BE LOST!')
    
    # DESTROY-DB command
    destroy_p = subparsers.add_parser('destroy-db',
        help='Destroy database permanently',
        description='{WARNING}  Permanently delete database and all backups. This action is IRREVERSIBLE!')
    
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

 MANAGING ENTRIES

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

 DATABASE OPERATIONS

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
      WARNING: This destroys all existing data!

  destroy-db
      Permanently delete database and all backups
      WARNING: This is irreversible!

 HELP & EXIT

  help [command]
      Show this help or help for specific command
      Example: help
      Example: help add

  exit | quit
      Exit password manager (secure cleanup)

 PASSWORD REQUIREMENTS

  • Length: 16-60 characters
  • Must include: uppercase, lowercase, digit, special character
  • Special characters: !@#$%^&*()-_=+[]{}|;:,.<>?/
  • International characters supported (UTF-8)

 PASSWORD GENERATOR FEATURES

  • Cryptographically secure random generation using secrets module
  • Customizable length (16-60 characters)
  • Automatic compliance with password policy
  • Preview before confirming
  • Option to regenerate or enter manually
  • Available in both 'add' and 'edit' commands

 TIP: Type 'help <command>' for detailed help on any command
      Example: help add
""")


def run_session(timeout_minutes, initial_result=None):
    """Interfaz gráfica moderna para el gestor de contraseñas con Session management completo"""
    
    if initial_result is not None:
        k_db, user_id, dnie_wrapping_key, password_key = initial_result
    else:
        result = prompt_and_verify_two_factor()
        if result is None:
            return
        k_db, user_id, dnie_wrapping_key, password_key = result
    
    # Crear Session con context manager para gestión segura
    with Session(k_db, user_id, dnie_wrapping_key, password_key, timeout_minutes=timeout_minutes) as session:
        # Limpiar referencias temporales
        del k_db, user_id, dnie_wrapping_key, password_key
        session.last_auth = datetime.now()
        
        # Lock en memoria
        if len(session.fernet_key) <= MAX_MLOCK_SIZE_LINUX:
            try:
                mlock(session.fernet_key)
                session._key_locked = True
            except Exception:
                session._key_locked = False
        
        # Thread de auto-expiración
        expiry_stop, expiry_thread = auto_expire_session(session, check_interval=30)
        
        # Base de datos
        db_file = get_db_filename(session.user_id)
        encrypted_db = EncryptedDatabase(bytes(session.fernet_key), db_filename=db_file)
        
        # Info usuario
        registry = load_dnie_registry()
        user_description = "Usuario"
        for dnie_hash, info in registry.get('dnies', {}).items():
            if info.get('user_id') == session.user_id:
                user_description = info.get('description', session.user_id)
                break
        
        try:
            # Pequeño delay para evitar conflictos de ventanas
            time.sleep(0.1)
            
            # Ventana principal
            root = tk.Tk()
            root.title("🔐 Gestor de Contraseñas")
            root.geometry("950x650")
            root.configure(bg="#1e1e2f")
            
            # Estilos
            style = ttk.Style(root)
            style.theme_use('clam')
            style.configure('TFrame', background="#1e1e2f")
            style.configure('TLabel', background="#1e1e2f", foreground="#e0e0e0", font=('Segoe UI', 11))
            style.configure('TButton', font=('Segoe UI', 10), padding=5)
            style.configure('Danger.TButton', foreground='#e0e0e0', font=('Segoe UI', 10, 'bold'))
            style.configure('Treeview', background="#2e2e3f", fieldbackground="#2e2e3f", 
                            foreground="#e0e0e0", font=('Segoe UI', 10))
            style.configure('Treeview.Heading', font=('Segoe UI', 11, 'bold'))
            
            # Header
            header_frame = ttk.Frame(root)
            header_frame.pack(fill='x', padx=10, pady=10)
            
            ttk.Label(header_frame, text=f"🔐 Gestor de Contraseñas - {user_description}", 
                      font=('Segoe UI', 16, 'bold')).pack(side='left')
            
            ttk.Button(header_frame, text="🔒 Cerrar sesión", 
                       command=lambda: close_session()).pack(side='right', padx=5)
            
            # Búsqueda
            search_frame = ttk.Frame(root)
            search_frame.pack(fill='x', padx=10, pady=5)
            
            ttk.Label(search_frame, text="🔍 Buscar:").pack(side='left', padx=5)
            search_var = tk.StringVar()
            search_entry = ttk.Entry(search_frame, textvariable=search_var, width=40)
            search_entry.pack(side='left', padx=5)
            
            # Botones principales
            btn_frame = ttk.Frame(root)
            btn_frame.pack(fill='x', padx=10, pady=5)
            
            ttk.Button(btn_frame, text="➕ Añadir", command=lambda: add_entry_dialog()).pack(side='left', padx=3)
            ttk.Button(btn_frame, text="✏️ Editar", command=lambda: edit_entry_dialog()).pack(side='left', padx=3)
            ttk.Button(btn_frame, text="🗑️ Eliminar", command=lambda: delete_entry()).pack(side='left', padx=3)
            ttk.Button(btn_frame, text="📋 Copiar", command=lambda: copy_password()).pack(side='left', padx=3)
            ttk.Button(btn_frame, text="💾 Backup", command=lambda: do_backup()).pack(side='left', padx=3)
            ttk.Button(btn_frame, text="♻️ Restaurar", command=lambda: do_restore()).pack(side='left', padx=3)
            
            # Separador
            ttk.Separator(root, orient='horizontal').pack(fill='x', padx=10, pady=5)
            
            # Treeview
            tree_frame = ttk.Frame(root)
            tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
            
            tree = ttk.Treeview(tree_frame, columns=('Servicio', 'Usuario'), show='headings', selectmode='browse')
            tree.heading('Servicio', text='Servicio')
            tree.heading('Usuario', text='Usuario')
            tree.column('Servicio', width=350)
            tree.column('Usuario', width=350)
            
            scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            
            tree.pack(side='left', fill='both', expand=True)
            scrollbar.pack(side='right', fill='y')
            
            tree.bind('<Double-1>', lambda e: show_entry_details())
            
            # ===== FUNCIONES AUXILIARES =====
            
            def load_services():
                """Cargar servicios en el treeview"""
                for item in tree.get_children():
                    tree.delete(item)
                
                services = encrypted_db.list_services()
                search_text = search_var.get().lower()
                
                for service in services:
                    entry = encrypted_db.get_entry(service)
                    if not search_text or search_text in service.lower() or search_text in entry['username'].lower():
                        tree.insert('', 'end', values=(service, entry['username']))
                
                session.last_auth = datetime.now()
            
            def add_entry_dialog():
                """Diálogo añadir entrada"""
                dialog = tk.Toplevel(root)
                dialog.title("➕ Añadir Entrada")
                dialog.geometry("450x350")
                dialog.configure(bg="#1e1e2f")
                dialog.transient(root)
                dialog.grab_set()
                
                frame = ttk.Frame(dialog, padding=20)
                frame.pack(fill='both', expand=True)
                
                ttk.Label(frame, text="Servicio:").grid(row=0, column=0, sticky='w', pady=5)
                service_entry = ttk.Entry(frame, width=30)
                service_entry.grid(row=0, column=1, pady=5, padx=5)
                
                ttk.Label(frame, text="Usuario:").grid(row=1, column=0, sticky='w', pady=5)
                username_entry = ttk.Entry(frame, width=30)
                username_entry.grid(row=1, column=1, pady=5, padx=5)
                
                ttk.Label(frame, text="Contraseña:").grid(row=2, column=0, sticky='w', pady=5)
                password_entry = ttk.Entry(frame, width=30, show="*")
                password_entry.grid(row=2, column=1, pady=5, padx=5)
                
                def generate_pwd():
                    pwd = generate_random_password(20)
                    password_entry.delete(0, tk.END)
                    password_entry.insert(0, pwd)
                    messagebox.showinfo("Contraseña generada", f"Contraseña: {pwd}", parent=dialog)
                
                ttk.Button(frame, text="🎲 Generar", command=generate_pwd).grid(row=3, column=1, pady=10)
                
                def save_entry():
                    service = service_entry.get().strip()
                    username = username_entry.get().strip()
                    password = password_entry.get()
                    
                    if not service or not username or not password:
                        messagebox.showerror("Error", "Todos los campos son obligatorios", parent=dialog)
                        return
                    
                    if encrypted_db.service_exists(service):
                        messagebox.showerror("Error", f"El servicio '{service}' ya existe", parent=dialog)
                        return
                    
                    if not is_valid_entry(service, username, password):
                        messagebox.showerror("Error", "Entrada inválida. Contraseña debe tener 16-60 caracteres.", parent=dialog)
                        return
                    
                    if encrypted_db.add_entry(service, username, password):
                        messagebox.showinfo("Éxito", f"✓ Entrada añadida: '{service}'", parent=dialog)
                        dialog.destroy()
                        load_services()
                        session.last_auth = datetime.now()
                    else:
                        messagebox.showerror("Error", "No se pudo añadir", parent=dialog)
                
                ttk.Button(frame, text="💾 Guardar", command=save_entry).grid(row=4, column=0, columnspan=2, pady=20)
            
            def edit_entry_dialog():
                """Diálogo editar entrada"""
                selected = tree.selection()
                if not selected:
                    messagebox.showwarning("Advertencia", "Seleccione un servicio")
                    return
                
                service = tree.item(selected[0])['values'][0]
                entry = encrypted_db.get_entry(service)
                
                dialog = tk.Toplevel(root)
                dialog.title(f"✏️ Editar: {service}")
                dialog.geometry("450x350")
                dialog.configure(bg="#1e1e2f")
                dialog.transient(root)
                dialog.grab_set()
                
                frame = ttk.Frame(dialog, padding=20)
                frame.pack(fill='both', expand=True)
                
                ttk.Label(frame, text="Servicio:").grid(row=0, column=0, sticky='w', pady=5)
                ttk.Label(frame, text=service, font=('Segoe UI', 11, 'bold')).grid(row=0, column=1, sticky='w', pady=5)
                
                ttk.Label(frame, text="Nuevo usuario:").grid(row=1, column=0, sticky='w', pady=5)
                username_entry = ttk.Entry(frame, width=30)
                username_entry.insert(0, entry['username'])
                username_entry.grid(row=1, column=1, pady=5, padx=5)
                
                ttk.Label(frame, text="Nueva contraseña:").grid(row=2, column=0, sticky='w', pady=5)
                password_entry = ttk.Entry(frame, width=30, show="*")
                password_entry.grid(row=2, column=1, pady=5, padx=5)
                
                def generate_pwd():
                    pwd = generate_random_password(20)
                    password_entry.delete(0, tk.END)
                    password_entry.insert(0, pwd)
                    messagebox.showinfo("Contraseña generada", f"Contraseña: {pwd}", parent=dialog)
                
                ttk.Button(frame, text="🎲 Generar", command=generate_pwd).grid(row=3, column=1, pady=10)
                
                def save_changes():
                    new_username = username_entry.get().strip()
                    new_password = password_entry.get()
                    
                    if not new_username:
                        messagebox.showerror("Error", "El usuario no puede estar vacío", parent=dialog)
                        return
                    
                    if new_password and not is_valid_password(new_password):
                        messagebox.showerror("Error", "Contraseña inválida", parent=dialog)
                        return
                    
                    if encrypted_db.edit_entry(service, username=new_username, password=new_password if new_password else None):
                        messagebox.showinfo("Éxito", f"✓ '{service}' actualizado", parent=dialog)
                        dialog.destroy()
                        load_services()
                        session.last_auth = datetime.now()
                    else:
                        messagebox.showerror("Error", "No se pudo editar", parent=dialog)
                
                ttk.Button(frame, text="💾 Guardar", command=save_changes).grid(row=4, column=0, columnspan=2, pady=20)
            
            def delete_entry():
                """Eliminar entrada seleccionada"""
                selected = tree.selection()
                if not selected:
                    messagebox.showwarning("Advertencia", "Seleccione un servicio")
                    return
                
                service = tree.item(selected[0])['values'][0]
                
                if messagebox.askyesno("Confirmar", f"¿Eliminar '{service}'?"):
                    if encrypted_db.delete_entry(service):
                        messagebox.showinfo("Éxito", f"✓ '{service}' eliminado")
                        load_services()
                        session.last_auth = datetime.now()
                    else:
                        messagebox.showerror("Error", "No se pudo eliminar")
            
            def copy_password():
                """Copiar contraseña al portapapeles"""
                selected = tree.selection()
                if not selected:
                    messagebox.showwarning("Advertencia", "Seleccione un servicio")
                    return
                
                service = tree.item(selected[0])['values'][0]
                entry = encrypted_db.get_entry(service)
                
                try:
                    pyperclip.copy(entry['password'])
                    messagebox.showinfo("Copiado", f"✓ Contraseña de '{service}' copiada")
                    session.last_auth = datetime.now()
                except:
                    messagebox.showerror("Error", "No se pudo copiar al portapapeles")
            
            def show_entry_details():
                """Mostrar detalles de entrada (doble clic)"""
                selected = tree.selection()
                if not selected:
                    return
                
                service = tree.item(selected[0])['values'][0]
                entry = encrypted_db.get_entry(service)
                
                dialog = tk.Toplevel(root)
                dialog.title(f"👁️ Detalles: {service}")
                dialog.geometry("400x250")
                dialog.configure(bg="#1e1e2f")
                dialog.transient(root)
                
                frame = ttk.Frame(dialog, padding=20)
                frame.pack(fill='both', expand=True)
                
                ttk.Label(frame, text=service, font=('Segoe UI', 14, 'bold')).pack(pady=10)
                ttk.Label(frame, text=f"Usuario: {entry['username']}").pack(pady=5)
                
                pwd_var = tk.StringVar(value="●" * 12)
                pwd_label = ttk.Label(frame, textvariable=pwd_var, font=('Courier', 11))
                pwd_label.pack(pady=10)
                
                def toggle_pwd():
                    if pwd_var.get() == "●" * 12:
                        pwd_var.set(entry['password'])
                    else:
                        pwd_var.set("●" * 12)
                
                ttk.Button(frame, text="👁️ Mostrar/Ocultar", command=toggle_pwd).pack(pady=10)
                session.last_auth = datetime.now()
            
            def do_backup():
                """Crear backup"""
                if backup_database(session.user_id):
                    messagebox.showinfo("Éxito", "✓ Backup creado")
                    session.last_auth = datetime.now()
                else:
                    messagebox.showerror("Error", "No se pudo crear backup")
            
            def do_restore():
                """Restaurar desde backup"""
                if messagebox.askyesno("Confirmar", "¿Restaurar desde backup?\n(Se sobrescribirán los datos actuales)"):
                    if restore_database(session.user_id):
                        encrypted_db.reload_from_disk()
                        load_services()
                        messagebox.showinfo("Éxito", "✓ Restaurado desde backup")
                        session.last_auth = datetime.now()
                    else:
                        messagebox.showerror("Error", "No se pudo restaurar")
            
            def reinit_database():
                """Reinicializar base de datos (borra contenido, mantiene estructura)"""
                nonlocal encrypted_db
                
                if not messagebox.askyesno("⚠️ ADVERTENCIA", 
                                           "REINICIALIZAR BASE DE DATOS\n\n"
                                           "Esto borrará TODAS las contraseñas\n"
                                           "y creará nueva base con nueva contraseña maestra.\n\n"
                                           "¿Continuar?",
                                           icon='warning'):
                    return
                
                confirm = simpledialog.askstring("Confirmación", 
                                                "Esta acción es IRREVERSIBLE.\n\n"
                                                "Escriba 'INIT' para confirmar:", parent=root)
                
                if confirm != "INIT":
                    messagebox.showinfo("Cancelado", "Reinicialización cancelada")
                    return
                
                messagebox.showinfo("Re-autenticación", "Por seguridad, autentíquese de nuevo")
                result = prompt_and_verify_two_factor()
                
                if result is None:
                    messagebox.showerror("Error", "Re-autenticación fallida")
                    return
                
                auth_k_db, auth_user_id, *_ = result
                del auth_k_db
                
                if auth_user_id != session.user_id:
                    messagebox.showerror("Error", f"No puede reinicializar BD de otro usuario")
                    del auth_user_id
                    return
                
                registry = load_dnie_registry()
                dnie_hash_to_remove = None
                for dnie_hash, info in registry.get('dnies', {}).items():
                    if info.get('user_id') == auth_user_id:
                        dnie_hash_to_remove = dnie_hash
                        break
                
                del auth_user_id
                
                destroy_database_files(session.user_id)
                
                if dnie_hash_to_remove:
                    registry = load_dnie_registry()
                    if dnie_hash_to_remove in registry.get('dnies', {}):
                        del registry['dnies'][dnie_hash_to_remove]
                        save_dnie_registry(registry)
                
                messagebox.showinfo("Inicialización", "Configurando nueva base de datos...")
                new_result = init_database()
                
                if new_result is None:
                    messagebox.showerror("Error", "Inicialización fallida")
                    root.destroy()
                    return
                
                new_k_db, new_user_id, new_dnie_key, new_pass_key = new_result
                
                if new_user_id != session.user_id:
                    messagebox.showerror("Error", "Error de usuario tras inicialización")
                    del new_k_db, new_user_id, new_dnie_key, new_pass_key
                    root.destroy()
                    return
                
                del new_user_id
                
                session.clear_key()
                session.fernet_key = new_k_db
                session.dnie_wrapping_key = new_dnie_key
                session.password_key = new_pass_key
                del new_k_db, new_dnie_key, new_pass_key
                
                if len(session.fernet_key) <= MAX_MLOCK_SIZE_LINUX:
                    try:
                        mlock(session.fernet_key)
                        session._key_locked = True
                    except:
                        session._key_locked = False
                
                session.last_auth = datetime.now()
                encrypted_db = EncryptedDatabase(bytes(session.fernet_key), db_filename=db_file)
                
                messagebox.showinfo("Éxito", "✓ Base de datos reinicializada")
                load_services()
            
            def destroy_database():
                """Eliminar completamente la base de datos"""
                if not messagebox.askyesno("⚠️ PELIGRO", 
                                           "ELIMINAR BASE DE DATOS PERMANENTEMENTE\n\n"
                                           "• Eliminará TODAS las contraseñas\n"
                                           "• Eliminará archivos de configuración\n"
                                           "• Desregistrará su DNIe\n"
                                           "• ES IRREVERSIBLE\n\n"
                                           "¿Está SEGURO?",
                                           icon='warning'):
                    return
                
                confirm = simpledialog.askstring("Confirmación CRÍTICA",
                                                "⚠️ ÚLTIMA ADVERTENCIA ⚠️\n\n"
                                                "Todo se perderá para siempre.\n\n"
                                                "Escriba 'DELETE':", parent=root)
                
                if confirm != "DELETE":
                    messagebox.showinfo("Cancelado", "Eliminación cancelada")
                    return
                
                messagebox.showinfo("Re-autenticación", "Autentíquese de nuevo")
                result = prompt_and_verify_two_factor()
                
                if result is None:
                    messagebox.showerror("Error", "Re-autenticación fallida")
                    return
                
                messagebox.showinfo("pasado1")
                auth_k_db, auth_user_id, *_ = result
                messagebox.showinfo("pasado2")
                del auth_k_db
                messagebox.showinfo("pasado3")

                
                if auth_user_id != session.user_id:
                    messagebox.showerror("Error", f"No puede eliminar BD de otro usuario")
                    del auth_user_id
                    return
                messagebox.showinfo("pasado4")
                del auth_user_id
                messagebox.showinfo("pasado5")
                # Forzar actualización de la ventana después de la re-autenticación
                root.update()
                messagebox.showinfo("pasado6")
                root.deiconify()  # Asegurar que root está visible
                messagebox.showinfo("pasado7")
                time.sleep(0.2)   # Pequeño delay para estabilizar el loop de eventos
                messagebox.showinfo("pasado8")
                
                final_confirm = simpledialog.askstring("Confirmación FINAL",
                                                       f"⚠️ PUNTO DE NO RETORNO ⚠️\n\n"
                                                       f"Eliminará datos de: {session.user_id}\n\n"
                                                       f"Escriba 'CONFIRM DELETE':", parent=root)
                messagebox.showinfo("pasado9")
                
                if final_confirm != "CONFIRM DELETE":
                    messagebox.showinfo("Cancelado", "Eliminación cancelada")
                    return
                
                registry = load_dnie_registry()
                dnie_hash_to_remove = None
                for dnie_hash, info in registry.get('dnies', {}).items():
                    if info.get('user_id') == session.user_id:
                        dnie_hash_to_remove = dnie_hash
                        break
                
                removed = destroy_database_files(session.user_id)
                
                if removed:
                    if dnie_hash_to_remove:
                        registry = load_dnie_registry()
                        if dnie_hash_to_remove in registry.get('dnies', {}):
                            del registry['dnies'][dnie_hash_to_remove]
                            save_dnie_registry(registry)
                    
                    messagebox.showinfo("Completado", 
                                      "✓ Base de datos eliminada\n"
                                      "✓ DNIe desregistrado\n\n"
                                      "La sesión se cerrará.")
                    
                    expiry_stop.set()
                    expiry_thread.join(timeout=2)
                    encrypted_db.clear()
                    root.destroy()
                else:
                    messagebox.showerror("Error", "No se encontraron archivos")
            
            def close_session():
                """Cerrar sesión de forma segura"""
                if messagebox.askyesno("Cerrar sesión", "¿Cerrar sesión de forma segura?"):
                    success = auto_rotate_on_logout(session)
                    
                    if success:
                        messagebox.showinfo("Seguridad", 
                                          "✓ Base de datos protegida con nueva clave\n"
                                          "✓ Forward secrecy activado")
                    
                    expiry_stop.set()
                    expiry_thread.join(timeout=2)
                    encrypted_db.clear()
                    root.destroy()
            
            # Operaciones avanzadas (peligrosas)
            advanced_frame = ttk.Frame(root)
            advanced_frame.pack(fill='x', padx=10, pady=5)
            
            ttk.Label(advanced_frame, text="⚠️ Operaciones Avanzadas:", 
                     font=('Segoe UI', 10, 'bold'), foreground='#ff9800').pack(side='left', padx=5)
            
            ttk.Button(advanced_frame, text="🔄 Reinicializar BD", style='Danger.TButton',
                       command=lambda: reinit_database()).pack(side='left', padx=3)
            ttk.Button(advanced_frame, text="💥 Eliminar BD", style='Danger.TButton',
                       command=lambda: destroy_database()).pack(side='left', padx=3)

            # Vincular búsqueda
            search_var.trace_add('write', lambda *args: load_services())
            
            # Cargar servicios inicialmente
            load_services()
            
            # Controlar cierre de ventana
            root.protocol("WM_DELETE_WINDOW", close_session)
            
            root.mainloop()
        
        finally:
            # Limpieza final segura
            try:
                expiry_stop.set()
                expiry_thread.join(timeout=2)
            except:
                pass
            
            encrypted_db.clear()
            session.clear_key()



def main():
    """Punto de entrada principal - VERSION CORREGIDA"""
    
    secure_all_sensitive_files()
    
    if not os.path.exists(DNIE_REGISTRY_FILE) or len(load_dnie_registry().get('dnies', {})) == 0:
        
        # Crear ventana
        root = tk.Tk()
        root.title("Gestor de Contraseñas - Bienvenida")
        root.geometry("650x550")
        root.configure(bg="#1e1e2f")
        
        # Estilos
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('TFrame', background="#1e1e2f")
        style.configure('TLabel', background="#1e1e2f", foreground="#e0e0e0")
        style.configure('TButton', font=('Segoe UI', 11), padding=10)
        
        # Contenedor principal
        main_frame = tk.Frame(root, bg="#1e1e2f")
        main_frame.pack(fill='both', expand=True, padx=40, pady=40)
        
        # Título
        title_label = tk.Label(main_frame, 
                               text="🔐 GESTOR DE CONTRASEÑAS CON DNIe",
                               font=('Segoe UI', 18, 'bold'),
                               bg="#1e1e2f",
                               fg="#e0e0e0")
        title_label.pack(pady=(0, 30))
        
        # Mensaje
        message = """No se encontró una base de datos configurada.

Es necesario realizar la configuración inicial para:
  • Registrar su DNIe en el sistema
  • Crear una contraseña maestra
  • Generar claves de cifrado seguras

Este proceso solo se realizará una vez."""
        
        message_label = tk.Label(main_frame,
                                text=message,
                                font=('Segoe UI', 11),
                                bg="#1e1e2f",
                                fg="#c0c0c0",
                                justify='left')
        message_label.pack(pady=(0, 40))
        
        # Frame para botones
        button_frame = tk.Frame(main_frame, bg="#1e1e2f")
        button_frame.pack(pady=20)
        
        # Funciones
        def on_start():
            root.destroy()
            result = init_database()
            if result:
                run_session(timeout_minutes=4, initial_result=result)
        
        def on_cancel():
            root.destroy()
        
        # BOTONES con tk.Button en lugar de ttk.Button
        start_button = tk.Button(button_frame,
                                text="🚀 Iniciar Configuración",
                                command=on_start,
                                font=('Segoe UI', 12, 'bold'),
                                bg="#4a90e2",
                                fg="white",
                                padx=30,
                                pady=10,
                                relief='flat',
                                cursor='hand2')
        start_button.pack(pady=10)
        
        cancel_button = tk.Button(button_frame,
                                 text="✗ Cancelar",
                                 command=on_cancel,
                                 font=('Segoe UI', 11),
                                 bg="#555555",
                                 fg="white",
                                 padx=30,
                                 pady=10,
                                 relief='flat',
                                 cursor='hand2')
        cancel_button.pack(pady=10)
        
        # Centrar ventana
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')
        
        root.mainloop()
        
    else:
        run_session(timeout_minutes=4)

if __name__ == "__main__":
    main()