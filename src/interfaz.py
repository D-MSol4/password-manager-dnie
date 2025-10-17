import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget,
    QSpinBox, QMessageBox, QTableWidget, QTableWidgetItem,
    QProgressDialog, QDialog, QDialogButtonBox, QHeaderView
)
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont
from datetime import datetime
import time

from main import (
    Session,
    EncryptedDatabase,
    get_db_filename,
    generate_random_password,
    auto_expire_session,
    is_valid_password,
    get_user_id_from_dnie,
    update_last_login,
    load_dnie_registry
)
from smartcard_dnie import DNIeCard
from crypto import derive_key_from_password, unwrap_database_key
from database import get_wrapped_key_filename, get_salt_filename, secure_file_permissions, save_database, DNIE_REGISTRY_FILE

# Configuración de codificación para Windows
if sys.platform == 'win32':
    # Protección para cuando no hay stdout (PyInstaller con console=False)
    if sys.stdout and hasattr(sys.stdout, 'encoding') and sys.stdout.encoding != 'utf-8':
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    if sys.stderr and hasattr(sys.stderr, 'encoding') and sys.stderr.encoding != 'utf-8':
        import codecs
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

class AuthenticationDialog(QDialog):
    """Diálogo personalizado para autenticación de dos factores"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Autenticación de Dos Factores")
        self.setModal(True)
        self.setMinimumWidth(500)
        
        # Resultado de autenticación
        self.result = None
        self.dnie_hash = None
        self.card_found = False
        self.detection_thread = None
        
        self.init_ui()
    
    def init_ui(self):
        """Crear interfaz del diálogo"""
        layout = QVBoxLayout()
        
        # Título
        title = QLabel("🔐 Autenticación DNIe + Contraseña Maestra")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Separador
        layout.addSpacing(20)
        
        # Instrucciones
        instructions = QLabel(
            "Paso 1: Inserte su DNIe en el lector\n"
            "Paso 2: Introduzca el PIN del DNIe\n"
            "Paso 3: Introduzca su contraseña maestra"
        )
        instructions.setStyleSheet("color: #555; padding: 10px;")
        layout.addWidget(instructions)
        
        # Estado de conexión DNIe
        self.status_label = QLabel("⏳ Buscando DNIe...")
        self.status_label.setStyleSheet("color: orange; font-weight: bold; padding: 10px;")
        layout.addWidget(self.status_label)
        
        # Campo: PIN del DNIe
        layout.addWidget(QLabel("PIN del DNIe:"))
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_input.setMaxLength(16)
        self.pin_input.setPlaceholderText("Introduzca su PIN del DNIe")
        self.pin_input.setEnabled(False)
        layout.addWidget(self.pin_input)
        
        # Campo: Contraseña maestra
        layout.addWidget(QLabel("Contraseña Maestra:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Introduzca su contraseña maestra")
        self.password_input.setEnabled(False)
        layout.addWidget(self.password_input)
        
        # Checkbox para mostrar contraseñas
        self.show_passwords_checkbox = QPushButton("👁️ Mostrar contraseñas")
        self.show_passwords_checkbox.setCheckable(True)
        self.show_passwords_checkbox.toggled.connect(self.toggle_password_visibility)
        layout.addWidget(self.show_passwords_checkbox)
        
        # Botones
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.on_ok_pressed)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        
        # Iniciar detección de DNIe
        self.start_detection()
    
    def on_ok_pressed(self):
        """Cuando se presiona OK, verificar que el DNIe esté detectado y registrado"""
        if not self.dnie_hash:
            QMessageBox.warning(
                self,
                "Error",
                "No se ha detectado ningún DNIe. Por favor, inserte su tarjeta."
            )
            return
        
        # Verificar que haya PIN y contraseña
        pin = self.pin_input.text().strip()
        master_password = self.password_input.text()
        
        if not pin or len(pin) < 4:
            QMessageBox.warning(self, "Error", "El PIN debe tener al menos 4 dígitos")
            return
        
        if not master_password:
            QMessageBox.warning(self, "Error", "Debe introducir la contraseña maestra")
            return
        
        if not is_valid_password(master_password):
            QMessageBox.warning(
                self,
                "Contraseña inválida",
                "La contraseña debe tener 16-60 caracteres con mayúsculas, "
                "minúsculas, dígitos y símbolos."
            )
            return
        
        # Mostrar progreso
        progress = QProgressDialog("Autenticando con DNIe...", None, 0, 0, self)
        progress.setWindowTitle("Autenticación")
        progress.setModal(True)
        progress.show()
        
        # Autenticar en thread separado
        auth_thread = AuthenticationThread(
            self.dnie_hash,
            pin,
            master_password
        )
        auth_thread.finished.connect(lambda result: self.on_auth_finished(result, progress))
        auth_thread.start()
        auth_thread.wait()

    def start_detection(self):
        """Iniciar thread de detección de DNIe"""
        self.detection_thread = CardDetectionThread()
        self.detection_thread.card_detected.connect(self.on_card_detected)
        self.detection_thread.still_searching.connect(self.on_still_searching)
        self.detection_thread.card_error.connect(self.on_card_error)
        self.detection_thread.start()
        
        print("DEBUG: Thread de detección iniciado")
    
    def toggle_password_visibility(self, checked):
        """Alternar visibilidad de contraseñas"""
        if checked:
            self.pin_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_passwords_checkbox.setText("🔒 Ocultar contraseñas")
        else:
            self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_passwords_checkbox.setText("👁️ Mostrar contraseñas")
    
    def on_card_detected(self, dnie_hash):
        """Callback cuando se detecta una tarjeta DNIe"""
        print(f"DEBUG: DNIe detectado: {dnie_hash[:16]}...")
        self.dnie_hash = dnie_hash
        self.card_found = True
        
        # Verificar si el DNIe está registrado
        user_id = get_user_id_from_dnie(dnie_hash)
        
        if user_id is None:
            # DNIe NO registrado
            self.status_label.setText(f"⚠️ DNIe NO registrado: {dnie_hash[:16]}...")
            self.status_label.setStyleSheet("color: orange; font-weight: bold; padding: 10px;")
            
            # Mostrar mensaje y cerrar diálogo para iniciar registro
            QMessageBox.information(
                self,
                "DNIe No Registrado",
                f"DNIe detectado: {dnie_hash[:16]}...\n\n"
                "Este DNIe no está registrado en el sistema.\n"
                "Se iniciará el proceso de registro."
            )
            
            self.result = None
            self.accept()  # Cerrar con accepted pero sin resultado
        else:
            # DNIe registrado - permitir autenticación
            self.status_label.setText(f"✅ DNIe detectado: {dnie_hash[:16]}...")
            self.status_label.setStyleSheet("color: green; font-weight: bold; padding: 10px;")
            self.pin_input.setEnabled(True)
            self.password_input.setEnabled(True)
            self.pin_input.setFocus()

    
    def on_still_searching(self):
        """Callback mientras sigue buscando el DNIe"""
        if not self.card_found:
            print("DEBUG: Aún buscando DNIe...")
            self.status_label.setText("⏳ Esperando DNIe... (Inserte su tarjeta)")
            self.status_label.setStyleSheet("color: orange; font-weight: bold; padding: 10px;")
    
    def on_card_error(self, error_msg):
        """Callback cuando hay error de detección de tarjeta"""
        print(f"DEBUG: Error de detección: {error_msg}")
        self.status_label.setText(f"❌ {error_msg}")
        self.status_label.setStyleSheet("color: red; font-weight: bold; padding: 10px;")
    
    
    def on_auth_finished(self, result, progress):
        """Callback cuando termina la autenticación"""
        progress.close()
        
        if result is None:
            QMessageBox.critical(
                self,
                "Error de autenticación",
                "La autenticación falló. Verifique su PIN y contraseña maestra."
            )
            return
        
        self.result = result
        self.accept()
    
    def reject(self):
        """Override reject para asegurar que se cierra correctamente"""
        print("DEBUG: Diálogo de autenticación cancelado")
        super().reject()
    
    def closeEvent(self, event):
        """Limpiar al cerrar"""
        print("DEBUG: Cerrando diálogo de autenticación")
        if self.detection_thread and self.detection_thread.isRunning():
            print("DEBUG: Deteniendo thread de detección")
            self.detection_thread.stop()
            self.detection_thread.wait(2000)  # Esperar máximo 2 segundos
        event.accept()


class CardDetectionThread(QThread):
    """Thread para detectar tarjeta DNIe en segundo plano con polling continuo"""
    card_detected = pyqtSignal(str)
    still_searching = pyqtSignal()
    card_error = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self._stop = False
    
    def run(self):
        """Intentar detectar DNIe continuamente hasta que se encuentre"""
        search_count = 0
        
        print("DEBUG: Iniciando búsqueda de DNIe...")
        
        while not self._stop:
            try:
                print(f"DEBUG: Intento de detección #{search_count + 1}")
                
                # Crear nueva instancia para detección
                card = DNIeCard()
                card.connect()
                dnie_hash = card.get_serial_hash()
                
                # Cerrar inmediatamente
                card.disconnect()
                
                print(f"DEBUG: ¡DNIe encontrado! Hash: {dnie_hash[:16]}...")
                self.card_detected.emit(dnie_hash)
                break
                
            except Exception as e:
                error_str = str(e).lower()
                print(f"DEBUG: Excepción capturada: {error_str}")
                
                # Lista ampliada de keywords para detectar "no encontrado"
                # Ahora incluye keywords individuales para mayor flexibilidad
                not_found_keywords = [
                    "no smart card",      # Detecta "no smart card detected"
                    "not found",
                    "not detected",
                    "no readers",
                    "scard_e_no_readers",
                    "no card",
                    "card not present",
                    "insert your dnie",   # Específico del mensaje que vimos
                    "please insert"
                ]
                
                is_not_found = any(keyword in error_str for keyword in not_found_keywords)
                
                if is_not_found:
                    # Tarjeta no encontrada - seguir buscando
                    print("DEBUG: DNIe no encontrado, continuando búsqueda...")
                    search_count += 1
                    if search_count % 2 == 0:  # Emitir cada 2 segundos
                        self.still_searching.emit()
                    time.sleep(1)
                    continue
                else:
                    # Error real e inesperado
                    print(f"DEBUG: Error real detectado: {e}")
                    self.card_error.emit(str(e))
                    break
        
        print("DEBUG: Thread de detección finalizado")
    
    def stop(self):
        """Detener thread"""
        print("DEBUG: Solicitando detención del thread")
        self._stop = True


class AuthenticationThread(QThread):
    """Thread para autenticación sin bloquear UI"""
    finished = pyqtSignal(object)
    
    def __init__(self, dnie_hash, pin, master_password):
        super().__init__()
        self.dnie_hash = dnie_hash
        self.pin = pin
        self.master_password = master_password
    
    def run(self):
        """Realizar autenticación completa"""
        card = None
        dnie_wrapping_key = None
        password_key = None
        k_db = None
        
        try:
            card = DNIeCard()
            card.connect()
            
            print(f"🔐 Autenticando con DNIe...")
            dnie_wrapping_key = bytearray(card.authenticate(self.pin))
            print(f"✓ DNIe autenticado correctamente")
            
            user_id = get_user_id_from_dnie(self.dnie_hash)
            if user_id is None:
                print("❌ DNIe no registrado")
                self.finished.emit(None)
                return
            
            print(f"✓ Usuario identificado: {user_id}")
            print("🔑 Derivando clave de contraseña maestra...")
            
            salt_file = get_salt_filename(user_id)
            with open(salt_file, 'rb') as f:
                salt = f.read()
            
            password_key = bytearray(derive_key_from_password(self.master_password, salt))
            print("✓ Clave de contraseña derivada")
            
            print("🔓 Desencriptando clave de base de datos...")
            wrapped_key_file = get_wrapped_key_filename(user_id)
            with open(wrapped_key_file, 'rb') as f:
                wrapped_key = f.read()

            k_db = unwrap_database_key(wrapped_key, bytes(dnie_wrapping_key), bytes(password_key))
            print("✓ Clave de base de datos desencriptada")
            
            update_last_login(self.dnie_hash)
            
            # Emitir resultado
            self.finished.emit((k_db, user_id, dnie_wrapping_key, password_key))
            
        except Exception as e:
            print(f"❌ Error de autenticación: {e}")
            import traceback
            traceback.print_exc()
            self.finished.emit(None)
        
        finally:
            
            # Limpiar PIN y contraseña
            if hasattr(self, 'pin'):
                self.pin = None  # String - no necesita zeroize
                del self.pin
            
            if hasattr(self, 'master_password'):
                self.master_password = None  # String - no necesita zeroize
                del self.master_password 
            
            # Desconectar tarjeta de forma robusta
            if card:
                try:
                    print("DEBUG: Desconectando tarjeta DNIe...")
                    card.disconnect()
                    del card
                    print("DEBUG: Tarjeta desconectada correctamente")
                except Exception as e:
                    print(f"DEBUG: Error al desconectar tarjeta: {e}")


class PasswordManagerWindow(QMainWindow):
    """Ventana principal del gestor de contraseñas"""
    
    def __init__(self):
        super().__init__()
        
        self.session = None
        self.encrypted_db = None
        self.expiry_stop = None
        self.expiry_thread = None
        self.selected_service = None
        self.authenticated = False
        
        self.setWindowTitle("Password Manager - Gestor de Contraseñas")
        self.setGeometry(100, 100, 1000, 700)
        
        self.init_ui()
        
        self.session_timer = QTimer(self)
        self.session_timer.timeout.connect(self.update_session_status)
        self.session_timer.start(1000)
        
        # Autenticar al iniciar - CON QTimer para que la ventana se muestre primero
        QTimer.singleShot(100, self.authenticate_and_load)
    
    def init_ui(self):
        """Crear interfaz de usuario"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        
        self.session_label = QLabel("🔒 Sesión: No autenticado")
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.session_label.setFont(font)
        self.session_label.setStyleSheet("color: red; padding: 10px; background-color: #f0f0f0;")
        main_layout.addWidget(self.session_label)
        
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self.on_tab_changed)
        
        self.tabs.addTab(self.create_manage_tab(), "📋 Gestionar Entradas")
        self.tabs.addTab(self.create_add_tab(), "➕ Añadir")
        self.tabs.addTab(self.create_advanced_tab(), "⚙️ Acciones Avanzadas")
        
        main_layout.addWidget(self.tabs)
        
        central_widget.setLayout(main_layout)
    
    def create_manage_tab(self):
        """Pestaña integrada para gestionar entradas"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        control_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Actualizar Lista")
        refresh_btn.clicked.connect(self.on_list_services)
        control_layout.addWidget(refresh_btn)
        
        self.show_password_btn = QPushButton("👁️ Mostrar Contraseña")
        self.show_password_btn.clicked.connect(self.on_show_selected_password)
        control_layout.addWidget(self.show_password_btn)
        
        control_layout.addStretch()

        # Botón de bloquear sesión alineado a la derecha
        lock_btn = QPushButton("🔒 Bloquear Sesión")
        lock_btn.clicked.connect(self.on_lock)
        control_layout.addWidget(lock_btn)

        layout.addLayout(control_layout)
        
        self.list_table = QTableWidget()
        self.list_table.setColumnCount(3)
        self.list_table.setHorizontalHeaderLabels(["Servicio", "Usuario", "Contraseña"])
        
        header = self.list_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        self.list_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.list_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.list_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.list_table.itemSelectionChanged.connect(self.on_entry_selected)
        
        layout.addWidget(self.list_table)
        
        action_layout = QHBoxLayout()
        
        copy_user_btn = QPushButton("📋 Copiar Usuario")
        copy_user_btn.clicked.connect(self.on_copy_username_from_table)
        action_layout.addWidget(copy_user_btn)
        
        copy_pass_btn = QPushButton("📋 Copiar Contraseña")
        copy_pass_btn.clicked.connect(self.on_copy_password_from_table)
        action_layout.addWidget(copy_pass_btn)
        
        layout.addLayout(action_layout)
        
        separator = QLabel("──────────────────────────────────")
        separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(separator)
        
        edit_label = QLabel("✏️ Editar entrada seleccionada:")
        edit_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(edit_label)
        
        layout.addWidget(QLabel("Nuevo usuario (vacío = sin cambios):"))
        self.edit_username = QLineEdit()
        layout.addWidget(self.edit_username)
        
        layout.addWidget(QLabel("Nueva contraseña (vacío = sin cambios):"))
        
        edit_password_layout = QHBoxLayout()
        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.EchoMode.Password)
        edit_password_layout.addWidget(self.edit_password)
        
        self.edit_reveal_btn = QPushButton("👁️")
        self.edit_reveal_btn.setCheckable(True)
        self.edit_reveal_btn.setMaximumWidth(40)
        self.edit_reveal_btn.toggled.connect(self.toggle_edit_password_visibility)
        self.edit_reveal_btn.setToolTip("Mostrar/Ocultar contraseña")
        edit_password_layout.addWidget(self.edit_reveal_btn)
        
        edit_generate_btn = QPushButton("🎲")
        edit_generate_btn.setMaximumWidth(40)
        edit_generate_btn.clicked.connect(self.on_generate_edit_password)
        edit_generate_btn.setToolTip("Generar contraseña aleatoria")
        edit_password_layout.addWidget(edit_generate_btn)
        
        layout.addLayout(edit_password_layout)
        
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Longitud (generación):"))
        self.edit_password_length = QSpinBox()
        self.edit_password_length.setMinimum(16)
        self.edit_password_length.setMaximum(60)
        self.edit_password_length.setValue(20)
        self.edit_password_length.setMaximumWidth(100)
        length_layout.addWidget(self.edit_password_length)
        length_layout.addStretch()
        layout.addLayout(length_layout)
        
        edit_btn = QPushButton("✏️ Actualizar Entrada")
        edit_btn.clicked.connect(self.on_edit_entry_from_table)
        layout.addWidget(edit_btn)
        
        delete_btn = QPushButton("🗑️ Eliminar Entrada Seleccionada")
        delete_btn.setStyleSheet(
            "background-color: #ff4444; color: white; font-weight: bold; padding: 8px;"
        )
        delete_btn.clicked.connect(self.on_delete_entry_from_table)
        layout.addWidget(delete_btn)
        
        widget.setLayout(layout)
        return widget
    
    def create_add_tab(self):
        """Pestaña para añadir entradas"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Servicio:"))
        self.add_service = QLineEdit()
        layout.addWidget(self.add_service)
        
        layout.addWidget(QLabel("Usuario/Email:"))
        self.add_username = QLineEdit()
        layout.addWidget(self.add_username)
        
        layout.addWidget(QLabel("Contraseña:"))
        password_layout = QHBoxLayout()
        self.add_password = QLineEdit()
        self.add_password.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.add_password)
        
        self.add_reveal_btn = QPushButton("👁️")
        self.add_reveal_btn.setCheckable(True)
        self.add_reveal_btn.setMaximumWidth(40)
        self.add_reveal_btn.toggled.connect(self.toggle_add_password_visibility)
        self.add_reveal_btn.setToolTip("Mostrar/Ocultar contraseña")
        password_layout.addWidget(self.add_reveal_btn)
        
        generate_btn = QPushButton("🎲 Generar")
        generate_btn.clicked.connect(self.on_generate_password)
        password_layout.addWidget(generate_btn)
        layout.addLayout(password_layout)
        
        layout.addWidget(QLabel("Longitud (generación):"))
        self.add_length = QSpinBox()
        self.add_length.setMinimum(16)
        self.add_length.setMaximum(60)
        self.add_length.setValue(20)
        layout.addWidget(self.add_length)
        
        button_container = QHBoxLayout()
        button_container.addStretch()  # Espacio a la izquierda
        add_btn = QPushButton("➕ Añadir Entrada")
        add_btn.clicked.connect(self.on_add_entry)
        # Hacer el botón más alto y más estrecho
        add_btn.setMinimumHeight(60)  # Más alto
        add_btn.setMaximumWidth(250)   # Más estrecho
        add_btn.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                padding: 15px 20px;
            }
        """)
        
        button_container.addWidget(add_btn)
        button_container.addStretch()  # Espacio a la derecha
        
        layout.addLayout(button_container)
        # FIN DE LA MODIFICACIÓN
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_advanced_tab(self):
        """Pestaña para acciones avanzadas (reinicializar y destruir base de datos)"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Título y advertencia
        warning_label = QLabel("⚠️ ACCIONES AVANZADAS - ZONA DE PELIGRO ⚠️")
        warning_label.setStyleSheet(
            "font-size: 16px; font-weight: bold; color: #ff6600; "
            "padding: 15px; background-color: #fff3cd; border: 2px solid #ff6600;"
        )
        warning_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(warning_label)
        
        layout.addSpacing(20)
        
        # Sección: Cambiar Contraseña Maestra
        change_pass_group = QLabel("🔑 Cambiar Contraseña Maestra")
        change_pass_group.setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 10px;")
        layout.addWidget(change_pass_group)
        
        change_pass_description = QLabel(
            "Cambia la contraseña maestra que protege tu base de datos. Los datos existentes se mantendrán intactos."
        )
        change_pass_description.setWordWrap(True)
        change_pass_description.setStyleSheet("color: #666; padding: 10px; margin-bottom: 10px;")
        layout.addWidget(change_pass_description)
        
        change_pass_btn = QPushButton("🔑 Cambiar Contraseña Maestra")
        change_pass_btn.setStyleSheet(
            "background-color: #2196F3; color: white; font-weight: bold; "
            "padding: 12px; font-size: 13px;"
        )
        change_pass_btn.clicked.connect(self.on_change_master_password)
        layout.addWidget(change_pass_btn)
        
        layout.addSpacing(30)
        
        # Separador
        separator1 = QLabel("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        separator1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        separator1.setStyleSheet("color: #ccc;")
        layout.addWidget(separator1)
        
        layout.addSpacing(30)

        # Sección: Reinicializar Base de Datos
        init_group = QLabel("🔄 Reinicializar Base de Datos")
        init_group.setStyleSheet("font-size: 18px; font-weight: bold; margin-top: 10px;")
        layout.addWidget(init_group)
        
        init_description = QLabel(
            "Destruye la base de datos actual y crea una nueva con una nueva contraseña maestra.\n"
            "⚠️ ADVERTENCIA: ¡Todos los datos actuales se perderán permanentemente!"
        )
        init_description.setWordWrap(True)
        init_description.setStyleSheet("font-size: 14px; color: #ff9800; padding: 10px; margin-bottom: 10px;")
        layout.addWidget(init_description)
        
        init_btn = QPushButton("🔄 Reinicializar Base de Datos")
        init_btn.setStyleSheet(
            "background-color: #ff9800; color: white; font-weight: bold; "
            "padding: 12px; font-size: 13px;"
        )
        init_btn.clicked.connect(self.on_reinit_database)
        layout.addWidget(init_btn)
        
        layout.addSpacing(30)
        
        # Separador
        separator = QLabel("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        separator.setStyleSheet("color: #ccc;")
        layout.addWidget(separator)
        
        layout.addSpacing(30)
        
        # Sección: Destruir Base de Datos
        destroy_group = QLabel("💣 Destruir Base de Datos Permanentemente")
        destroy_group.setStyleSheet("font-size: 18px; font-weight: bold; margin-top: 10px;")
        layout.addWidget(destroy_group)
        
        destroy_description = QLabel(
            "Elimina permanentemente la base de datos del usuario actual.\n"
            "⚠️ ADVERTENCIA CRÍTICA: ¡Esta acción es IRREVERSIBLE! No hay manera de recuperar los datos."
        )
        destroy_description.setWordWrap(True)
        destroy_description.setStyleSheet("font-size: 14px; color: #d32f2f; padding: 10px; margin-bottom: 10px;")
        layout.addWidget(destroy_description)
        
        destroy_btn = QPushButton("💣 Destruir Base de Datos Permanentemente")
        destroy_btn.setStyleSheet(
            "background-color: #d32f2f; color: white; font-weight: bold; "
            "padding: 12px; font-size: 13px;"
        )
        destroy_btn.clicked.connect(self.on_destroy_database)
        layout.addWidget(destroy_btn)
        
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget


    def on_tab_changed(self, index):
        """Callback cuando cambia la pestaña activa"""
        if index == 0:
            self.on_list_services()
    
    def toggle_add_password_visibility(self, checked):
        """Alternar visibilidad de contraseña en pestaña añadir"""
        if checked:
            self.add_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.add_reveal_btn.setText("🔒")
        else:
            self.add_password.setEchoMode(QLineEdit.EchoMode.Password)
            self.add_reveal_btn.setText("👁️")
    
    def toggle_edit_password_visibility(self, checked):
        """Alternar visibilidad de contraseña en pestaña editar"""
        if checked:
            self.edit_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.edit_reveal_btn.setText("🔒")
        else:
            self.edit_password.setEchoMode(QLineEdit.EchoMode.Password)
            self.edit_reveal_btn.setText("👁️")
    
    def on_show_selected_password(self):
        """Mostrar la contraseña de la entrada seleccionada"""
        if not self.check_session():
            return
        
        if not self.selected_service:
            QMessageBox.warning(self, "Error", "Selecciona una entrada de la tabla")
            return
        
        entry = self.encrypted_db.get_entry(self.selected_service)
        
        if entry:
            row = self.list_table.currentRow()
            
            if row >= 0:
                password_item = self.list_table.item(row, 2)
                
                if password_item.text().startswith('•'):
                    password_item.setText(entry['password'])
                    self.show_password_btn.setText("🔒 Ocultar Contraseña")
                else:
                    password_item.setText('•' * len(entry['password']))
                    self.show_password_btn.setText("👁️ Mostrar Contraseña")
    
    def on_generate_edit_password(self):
        """Generar contraseña aleatoria para el campo de edición"""
        length = self.edit_password_length.value()
        password = generate_random_password(length)
        self.edit_password.setText(password)
        
        self.edit_password.setEchoMode(QLineEdit.EchoMode.Normal)
        self.edit_reveal_btn.setChecked(True)
        
        QMessageBox.information(
            self,
            "Contraseña generada",
            f"Contraseña generada:\n{password}\n\nSe ha colocado en el campo de edición."
        )
    
    def authenticate(self, is_reauth=False):
        """Mostrar diálogo de autenticación"""
        print(f"DEBUG: Iniciando autenticación (reauth={is_reauth})")
        
        dialog = AuthenticationDialog(self)
        dialog_result = dialog.exec()
        
        print(f"DEBUG: Resultado del diálogo: {dialog_result}")
        
        if dialog_result == QDialog.DialogCode.Accepted:
            result = dialog.result
            
            if result:
                # Autenticación exitosa
                k_db, user_id, dnie_wrapping_key, password_key = result
                
                self.session = Session(k_db, user_id, dnie_wrapping_key, password_key, timeout_minutes=4)
                
                if self.expiry_stop and self.expiry_thread:
                    self.expiry_stop.set()
                    self.expiry_thread.join(timeout=2)
                
                self.expiry_stop, self.expiry_thread = auto_expire_session(self.session, check_interval=30)
                
                db_file = get_db_filename(self.session.user_id)
                self.encrypted_db = EncryptedDatabase(bytes(self.session.fernet_key), db_filename=db_file)
                
                self.authenticated = True
                
                if not is_reauth:
                    registry = load_dnie_registry()
                    user_desc = "Usuario"
                    for info in registry.get('dnies', {}).values():
                        if info.get('user_id') == user_id:
                            user_desc = info.get('description', 'Usuario')
                            break
                    
                    QMessageBox.information(
                        self,
                        "Autenticación exitosa",
                        f"✅ Autenticación exitosa\n\n"
                        f"Usuario: {user_id}\n"
                        f"Descripción: {user_desc}\n"
                        f"Sesión válida por: 4 minutos"
                    )
            else:
                # result es None - DNIe no registrado
                if not is_reauth and dialog.dnie_hash:
                    print(f"DEBUG: DNIe no registrado: {dialog.dnie_hash[:16]}...")
                    
                    reply = QMessageBox.question(
                        self,
                        "DNIe No Registrado",
                        "Este DNIe no está registrado en el sistema.\n\n"
                        "¿Desea registrarlo y crear una nueva base de datos?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.Yes
                    )
                    
                    if reply == QMessageBox.StandardButton.Yes:
                        # Iniciar proceso de inicialización
                        self.initialize_new_dnie(dialog.dnie_hash)
                    else:
                        print("DEBUG: Usuario canceló el registro, cerrando aplicación")
                        sys.exit(0)
                else:
                    if not is_reauth:
                        print("DEBUG: Autenticación falló, cerrando aplicación")
                        sys.exit(0)
        else:
            # Usuario canceló autenticación
            print("DEBUG: Usuario canceló autenticación, cerrando aplicación")
            if not is_reauth:
                sys.exit(0)

    def authenticate_and_load(self):
        """Autenticar y cargar la lista de entradas"""
        self.authenticate()
        
        # Si se autenticó correctamente, cargar la lista
        if self.authenticated:
            self.on_list_services()

    def initialize_new_dnie(self, dnie_hash):
        """Inicializar un nuevo DNIe y crear base de datos"""
        try:
            from PyQt6.QtWidgets import QInputDialog
            from cryptography.fernet import Fernet
            
            from crypto import derive_key_from_password, wrap_database_key
            import json
            import os
            
            # Generar user_id automáticamente siguiendo el patrón user001, user002, etc.
            registry = load_dnie_registry()
            existing_ids = []
            
            for dnie_info in registry.get('dnies', {}).values():
                user_id_temp = dnie_info.get('user_id', '')
                if user_id_temp.startswith('user'):
                    try:
                        num = int(user_id_temp.replace('user', ''))
                        existing_ids.append(num)
                    except:
                        pass
            
            next_id = max(existing_ids, default=0) + 1
            user_id = f"user{next_id:03d}"
            
            print(f"DEBUG: Generando user_id automático: {user_id}")
            
            # Solicitar descripción
            description, ok = QInputDialog.getText(
                self,
                "Descripción del Usuario",
                f"Se creará el usuario: {user_id}\n\n"
                "Introduzca una descripción para identificar este usuario\n"
                "(ejemplo: 'Mi cuenta personal', 'Trabajo', etc.):",
                QLineEdit.EchoMode.Normal,
                f"Usuario {next_id}"
            )
            
            if not ok or not description.strip():
                description = f"Usuario {next_id}"
            
            # Solicitar contraseña maestra
            while True:
                master_password, ok = QInputDialog.getText(
                    self,
                    "Contraseña Maestra",
                    "Introduzca una contraseña maestra segura\n"
                    "(16-60 caracteres con mayúsculas, minúsculas, dígitos y símbolos):",
                    QLineEdit.EchoMode.Password
                )
                
                if not ok:
                    QMessageBox.warning(self, "Cancelado", "Inicialización cancelada.")
                    sys.exit(0)
                
                if not is_valid_password(master_password):
                    QMessageBox.warning(
                        self,
                        "Contraseña Inválida",
                        "La contraseña debe tener 16-60 caracteres con mayúsculas, "
                        "minúsculas, dígitos y símbolos."
                    )
                    continue
                
                # Confirmar contraseña
                confirm_password, ok2 = QInputDialog.getText(
                    self,
                    "Confirmar Contraseña Maestra",
                    "Confirme la contraseña maestra:",
                    QLineEdit.EchoMode.Password
                )
                
                if not ok2:
                    QMessageBox.warning(self, "Cancelado", "Inicialización cancelada.")
                    sys.exit(0)
                
                if master_password != confirm_password:
                    QMessageBox.warning(self, "Error", "Las contraseñas no coinciden. Intente de nuevo.")
                    continue
                
                break
            
            # Solicitar PIN del DNIe
            pin, ok_pin = QInputDialog.getText(
                self,
                "PIN del DNIe",
                "Introduzca el PIN de su DNIe para completar el registro:",
                QLineEdit.EchoMode.Password
            )
            
            if not ok_pin:
                QMessageBox.warning(self, "Cancelado", "Inicialización cancelada.")
                sys.exit(0)
            
            # Mostrar progreso
            progress = QProgressDialog("Inicializando nuevo usuario...", None, 0, 0, self)
            progress.setWindowTitle("Inicializando")
            progress.setModal(True)
            progress.show()
            
            # Autenticar con DNIe
            try:
                card = DNIeCard()
                card.connect()
                dnie_wrapping_key = card.authenticate(pin)
                card.disconnect()
                del pin
            except Exception as e:
                progress.close()
                QMessageBox.critical(
                    self,
                    "Error de Autenticación DNIe",
                    f"No se pudo autenticar con el DNIe: {e}"
                )
                sys.exit(1)
            
            # Generar K_db
            k_db = Fernet.generate_key()
            
            # Generar salt
            salt = os.urandom(32)
            
            # Derivar clave de contraseña
            password_key = derive_key_from_password(master_password, salt)
            del master_password
            del confirm_password
            
            # Guardar archivos
            salt_file = get_salt_filename(user_id)
            with open(salt_file, 'wb') as f:
                f.write(salt)
            secure_file_permissions(salt_file)
            
            wrapped_key = wrap_database_key(k_db, dnie_wrapping_key, password_key)
            wrapped_key_file = get_wrapped_key_filename(user_id)
            with open(wrapped_key_file, 'wb') as f:
                f.write(wrapped_key)
            secure_file_permissions(wrapped_key_file)
            
            # Crear base de datos vacía
            db_file = get_db_filename(user_id)
            empty_db = {}
            save_database(empty_db, k_db, db_file)
            
            # Registrar DNIe
            registry = load_dnie_registry()
            if 'dnies' not in registry:
                registry['dnies'] = {}
            
            registry['dnies'][dnie_hash] = {
                'user_id': user_id,
                'description': description.strip(),
                'registered_at': datetime.now().isoformat(),
                'last_login': datetime.now().isoformat()
            }
            
            with open(DNIE_REGISTRY_FILE, 'w') as f:
                json.dump(registry, f, indent=2)
            
            progress.close()
            
            QMessageBox.information(
                self,
                "✅ Inicialización Exitosa",
                f"El DNIe ha sido registrado exitosamente.\n\n"
                f"Usuario: {user_id}\n"
                f"Descripción: {description}\n\n"
                f"Ahora puede iniciar sesión."
            )
            
            # Autenticar automáticamente
            self.authenticate()
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "❌ Error Crítico",
                f"Error durante la inicialización: {e}\n\n"
                "El programa se cerrará por seguridad."
            )
            import traceback
            traceback.print_exc()
            sys.exit(1)



    def update_session_status(self):
        """Actualizar estado de sesión en UI y re-autenticar si expira"""
        if self.session is None:
            self.session_label.setText("🔒 Sesión: No autenticado")
            self.session_label.setStyleSheet("color: red; padding: 10px; background-color: #f0f0f0;")
            return
        
        if self.session.expired():
            self.session_label.setText("⚠️ Sesión: EXPIRADA - Re-autenticación automática")
            self.session_label.setStyleSheet("color: red; padding: 10px; background-color: #ffe0e0;")
            
            self.session_timer.stop()
            
            QMessageBox.warning(
                self,
                "Sesión expirada",
                "Su sesión ha expirado por inactividad.\n\n"
                "Debe autenticarse nuevamente para continuar."
            )
            
            self.authenticate(is_reauth=True)
            
            self.session_timer.start(1000)
        else:
            remaining = self.session.timeout - (datetime.now() - self.session.last_auth)
            minutes = int(remaining.total_seconds() / 60)
            seconds = int(remaining.total_seconds() % 60)
            
            self.session_label.setText(
                f"✅ Sesión activa - Usuario: {self.session.user_id} - "
                f"Expira en: {minutes}m {seconds}s"
            )
            self.session_label.setStyleSheet("color: green; padding: 10px; background-color: #e0ffe0;")
    
    def check_session(self, show_message=True):
        """Verificar sesión antes de operaciones"""
        if self.session is None:
            if show_message:
                QMessageBox.warning(self, "Error", "No hay sesión activa")
            return False
        
        if self.session.expired():
            return False
        
        self.session.last_auth = datetime.now()
        return True
    
    def on_generate_password(self):
        """Generar contraseña aleatoria"""
        length = self.add_length.value()
        password = generate_random_password(length)
        self.add_password.setText(password)
        self.add_password.setEchoMode(QLineEdit.EchoMode.Normal)
        self.add_reveal_btn.setChecked(True)
        
        QMessageBox.information(
            self,
            "Contraseña generada",
            f"Contraseña generada:\n{password}\n\nSe ha colocado en el campo de contraseña."
        )
    
    def on_add_entry(self):
        """Añadir nueva entrada"""
        if not self.check_session():
            return
        
        service = self.add_service.text().strip()
        username = self.add_username.text().strip()
        password = self.add_password.text()
        
        if not service or not username or not password:
            QMessageBox.warning(self, "Error", "Todos los campos son obligatorios")
            return
        
        if self.encrypted_db.add_entry(service, username, password):
            QMessageBox.information(self, "Éxito", f"Entrada añadida: {service}")
            self.add_service.clear()
            self.add_username.clear()
            self.add_password.clear()
            
            self.tabs.setCurrentIndex(0)
            self.on_list_services()
        else:
            QMessageBox.critical(self, "Error", f"Error al añadir {service}")
    
    def on_list_services(self):
        """Listar servicios en la tabla con contraseñas enmascaradas"""
        # No mostrar mensaje si no hay sesión activa (puede ser al inicio)
        if not self.check_session(show_message=False):
            return
        
        self.show_password_btn.setText("👁️ Mostrar Contraseña")
        
        self.list_table.setRowCount(0)
        services = self.encrypted_db.list_services()
        
        for service in services:
            entry = self.encrypted_db.get_entry(service)
            if entry:
                row = self.list_table.rowCount()
                self.list_table.insertRow(row)
                
                service_item = QTableWidgetItem(service)
                self.list_table.setItem(row, 0, service_item)
                
                username_item = QTableWidgetItem(entry.get('username', ''))
                self.list_table.setItem(row, 1, username_item)
                
                password_masked = '•' * len(entry.get('password', ''))
                password_item = QTableWidgetItem(password_masked)
                self.list_table.setItem(row, 2, password_item)
    
    def on_entry_selected(self):
        """Cuando se selecciona una entrada en la tabla"""
        selected_rows = self.list_table.selectedItems()
        
        if not selected_rows:
            self.selected_service = None
            self.show_password_btn.setText("👁️ Mostrar Contraseña")
            return
        
        row = self.list_table.currentRow()
        service_item = self.list_table.item(row, 0)
        
        if service_item:
            self.selected_service = service_item.text()
            
            password_item = self.list_table.item(row, 2)
            if password_item and password_item.text().startswith('•'):
                self.show_password_btn.setText("👁️ Mostrar Contraseña")
            else:
                self.show_password_btn.setText("🔒 Ocultar Contraseña")
    
    def on_copy_username_from_table(self):
        """Copiar usuario al portapapeles"""
        if not self.check_session():
            return
        
        if not self.selected_service:
            QMessageBox.warning(self, "Error", "Selecciona una entrada de la tabla")
            return
        
        entry = self.encrypted_db.get_entry(self.selected_service)
        
        if entry:
            import pyperclip
            pyperclip.copy(entry['username'])
            QMessageBox.information(self, "Copiado", "Usuario copiado al portapapeles")
    
    def on_copy_password_from_table(self):
        """Copiar contraseña al portapapeles"""
        if not self.check_session():
            return
        
        if not self.selected_service:
            QMessageBox.warning(self, "Error", "Selecciona una entrada de la tabla")
            return
        
        entry = self.encrypted_db.get_entry(self.selected_service)
        
        if entry:
            import pyperclip
            pyperclip.copy(entry['password'])
            QMessageBox.information(self, "Copiado", "Contraseña copiada")
            
    
    def on_edit_entry_from_table(self):
        """Editar entrada seleccionada"""
        if not self.check_session():
            return
        
        if not self.selected_service:
            QMessageBox.warning(self, "Error", "Selecciona una entrada de la tabla")
            return
        
        new_username = self.edit_username.text().strip() or None
        new_password = self.edit_password.text() or None
        
        if not new_username and not new_password:
            QMessageBox.warning(self, "Error", "Especifica al menos un campo a cambiar")
            return
        
        if self.encrypted_db.edit_entry(self.selected_service, username=new_username, password=new_password):
            QMessageBox.information(self, "Éxito", f"Entrada actualizada: {self.selected_service}")
            self.edit_username.clear()
            self.edit_password.clear()
            
            self.on_list_services()
        else:
            QMessageBox.critical(self, "Error", f"Error al editar {self.selected_service}")
    
    def on_delete_entry_from_table(self):
        """Eliminar entrada seleccionada"""
        if not self.check_session():
            return
        
        if not self.selected_service:
            QMessageBox.warning(self, "Error", "Selecciona una entrada de la tabla")
            return
        
        reply = QMessageBox.question(
            self,
            "Confirmar eliminación",
            f"¿Eliminar '{self.selected_service}'?\n\nEsta acción no se puede deshacer.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.encrypted_db.delete_entry(self.selected_service):
                QMessageBox.information(self, "Éxito", f"Entrada eliminada: {self.selected_service}")
                
                self.selected_service = None
                self.edit_username.clear()
                self.edit_password.clear()
                
                self.on_list_services()
            else:
                QMessageBox.critical(self, "Error", f"Error al eliminar {self.selected_service}")
    
    def on_lock(self):
        """Bloquear sesión"""
        if self.session:
            self.session.clear_key()
            self.session.last_auth = None

    def on_change_master_password(self):
        """Cambiar la contraseña maestra"""
        if not self.check_session():
            return
        
        # RE-AUTENTICACIÓN: Pedir contraseña maestra actual y PIN del DNIe
        from PyQt6.QtWidgets import QInputDialog
        
        QMessageBox.information(
            self,
            "🔑 Cambiar Contraseña Maestra",
            "Para cambiar su contraseña maestra, primero debe re-autenticarse.\n\n"
            "Necesitará:\n"
            "• Su contraseña maestra actual\n"
            "• El PIN de su DNIe",
            QMessageBox.StandardButton.Ok
        )
        
        # Pedir contraseña maestra actual
        current_password, ok_pass = QInputDialog.getText(
            self,
            "Contraseña Maestra Actual",
            "Introduzca su contraseña maestra actual:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok_pass or not current_password:
            QMessageBox.information(self, "Cancelado", "Cambio de contraseña cancelado.")
            return
        
        # Pedir PIN del DNIe
        pin, ok_pin = QInputDialog.getText(
            self,
            "PIN del DNIe",
            "Introduzca el PIN de su DNIe:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok_pin or not pin:
            QMessageBox.information(self, "Cancelado", "Cambio de contraseña cancelado.")
            return
        
        # Mostrar progreso
        progress = QProgressDialog("Verificando credenciales...", None, 0, 0, self)
        progress.setWindowTitle("Verificando")
        progress.setModal(True)
        progress.show()
        
        try:
            # Autenticar con DNIe
            card = DNIeCard()
            card.connect()
            dnie_wrapping_key = card.authenticate(pin)
            card.disconnect()
            del pin
            
            # Verificar contraseña maestra actual
            from crypto import derive_key_from_password, unwrap_database_key, wrap_database_key
            from database import secure_file_permissions
            import os
            
            salt_file = get_salt_filename(self.session.user_id)
            with open(salt_file, 'rb') as f:
                salt = f.read()
            
            current_password_key = derive_key_from_password(current_password, salt)
            wrapped_key_file = get_wrapped_key_filename(self.session.user_id)
            with open(wrapped_key_file, 'rb') as f:
                wrapped_key = f.read()
            
            # Intentar desencriptar - si falla, la contraseña es incorrecta
            k_db = unwrap_database_key(wrapped_key, dnie_wrapping_key, current_password_key)
            
            del current_password
            del current_password_key
            
            progress.setLabelText("Credenciales verificadas. Esperando nueva contraseña...")
            
        except Exception as e:
            progress.close()
            QMessageBox.critical(
                self,
                "Error de Autenticación",
                f"La autenticación falló.\n\nVerifique su contraseña maestra y PIN del DNIe.\n\nError: {e}"
            )
            return
        
        # Pedir nueva contraseña maestra
        while True:
            new_password, ok_new = QInputDialog.getText(
                self,
                "Nueva Contraseña Maestra",
                "Introduzca la nueva contraseña maestra\n"
                "(16-60 caracteres con mayúsculas, minúsculas, dígitos y símbolos):",
                QLineEdit.EchoMode.Password
            )
            
            if not ok_new:
                progress.close()
                QMessageBox.information(self, "Cancelado", "Cambio de contraseña cancelado.")
                return
            
            if not is_valid_password(new_password):
                QMessageBox.warning(
                    self,
                    "Contraseña Inválida",
                    "La contraseña debe tener 16-60 caracteres con mayúsculas, "
                    "minúsculas, dígitos y símbolos."
                )
                continue
            
            # Confirmar nueva contraseña
            confirm_password, ok_confirm = QInputDialog.getText(
                self,
                "Confirmar Nueva Contraseña",
                "Confirme la nueva contraseña maestra:",
                QLineEdit.EchoMode.Password
            )
            
            if not ok_confirm:
                progress.close()
                QMessageBox.information(self, "Cancelado", "Cambio de contraseña cancelado.")
                return
            
            if new_password != confirm_password:
                QMessageBox.warning(self, "Error", "Las contraseñas no coinciden. Intente de nuevo.")
                continue
            
            break
        
        progress.setLabelText("Cambiando contraseña maestra...")
        
        try:
            # Generar nuevo salt
            new_salt = os.urandom(32)
            
            # Derivar nueva clave de contraseña
            new_password_key = derive_key_from_password(new_password, new_salt)
            del new_password
            del confirm_password
            
            # Re-encriptar K_db con la nueva contraseña
            new_wrapped_key = wrap_database_key(k_db, dnie_wrapping_key, new_password_key)
            
            # Guardar nueva clave envuelta
            with open(wrapped_key_file, 'wb') as f:
                f.write(new_wrapped_key)
            secure_file_permissions(wrapped_key_file)
            
            # Actualizar el salt en disco
            with open(salt_file, 'wb') as f:
                f.write(new_salt)
            secure_file_permissions(salt_file)

            # Actualizar sesión con la nueva clave de contraseña
            self.session.password_key = new_password_key
            
            # Limpiar datos sensibles
            del dnie_wrapping_key
            del new_password_key
            del k_db
            
            progress.close()
            
            QMessageBox.information(
                self,
                "✅ Contraseña Cambiada",
                "La contraseña maestra ha sido cambiada exitosamente.\n\n"
                "Asegúrese de recordar la nueva contraseña, ya que la necesitará "
                "para acceder a su base de datos en el futuro.\n\n"
                "El programa se cerrará ahora por seguridad."
            )
            
            # Cerrar sesión y limpiar
            if self.session:
                self.session.clear_key()
                if self.expiry_stop:
                    self.expiry_stop.set()
                    if self.expiry_thread:
                        self.expiry_thread.join(timeout=2)
            
            # Cerrar el programa
            sys.exit(0)

        except Exception as e:
            progress.close()
            QMessageBox.critical(
                self,
                "❌ Error Crítico",
                f"Error al cambiar la contraseña: {e}\n\n"
                "Por seguridad, reinicie la aplicación."
            )
            import traceback
            traceback.print_exc()


    def on_reinit_database(self):
        """Reinicializar la base de datos con nueva contraseña maestra"""
        if not self.check_session():
            return
        
        # RE-AUTENTICACIÓN: Pedir PIN del DNIe y contraseña maestra para confirmar identidad
        from PyQt6.QtWidgets import QInputDialog
        
        QMessageBox.warning(
            self,
            "🔐 Re-autenticación Requerida",
            "Por seguridad, debe re-autenticarse antes de reinicializar la base de datos.\n\n"
            "Introduzca su PIN del DNIe y contraseña maestra actual.",
            QMessageBox.StandardButton.Ok
        )
        
        # Pedir PIN del DNIe
        pin, ok_pin = QInputDialog.getText(
            self,
            "Re-autenticación - PIN del DNIe",
            "Introduzca el PIN de su DNIe:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok_pin or not pin:
            QMessageBox.information(self, "Cancelado", "Re-autenticación cancelada.")
            return
        
        # Pedir contraseña maestra
        master_password, ok_pass = QInputDialog.getText(
            self,
            "Re-autenticación - Contraseña Maestra",
            "Introduzca su contraseña maestra actual:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok_pass or not master_password:
            QMessageBox.information(self, "Cancelado", "Re-autenticación cancelada.")
            return
        
        # Verificar credenciales
        try:
            # Autenticar con DNIe
            card = DNIeCard()
            card.connect()
            dnie_hash = card.get_serial_hash()
            dnie_wrapping_key = card.authenticate(pin)
            card.disconnect()
            
            # Verificar que es el mismo DNIe de la sesión actual
            current_dnie_hash = None
            registry = load_dnie_registry()
            for dnie, info in registry.get('dnies', {}).items():
                if info.get('user_id') == self.session.user_id:
                    current_dnie_hash = dnie
                    break
            
            if current_dnie_hash != dnie_hash:
                QMessageBox.critical(
                    self,
                    "Error de Autenticación",
                    "El DNIe no corresponde al usuario actual."
                )
                return
            
            # Verificar contraseña maestra
            from crypto import derive_key_from_password, unwrap_database_key
            salt_file = get_salt_filename(self.session.user_id)
            with open(salt_file, 'rb') as f:
                salt = f.read()
            
            password_key = derive_key_from_password(master_password, salt)
            wrapped_key_file = get_wrapped_key_filename(self.session.user_id)
            with open(wrapped_key_file, 'rb') as f:
                wrapped_key = f.read()
            
            # Intentar desencriptar - si falla, la contraseña es incorrecta
            k_db = unwrap_database_key(wrapped_key, dnie_wrapping_key, password_key)
            
            # Limpiar datos sensibles
            del pin
            del master_password
            del dnie_wrapping_key
            del password_key
            del k_db
            
            print("✓ Re-autenticación exitosa")
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error de Re-autenticación",
                f"La re-autenticación falló.\n\nVerifique su PIN y contraseña maestra.\n\nError: {e}"
            )
            return
        
        # Triple confirmación
        reply = QMessageBox.warning(
            self,
            "⚠️ ADVERTENCIA: Reinicializar Base de Datos",
            "Esta acción destruirá TODOS los datos actuales y creará una nueva base de datos "
            "con una nueva contraseña maestra.\n\n"
            "¿Está COMPLETAMENTE SEGURO de que desea continuar?\n\n"
            "Esta acción NO SE PUEDE DESHACER.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Cancelado", "Reinicialización cancelada.")
            return
        
        # Solicitar confirmación escribiendo "REINICIAR"
        from PyQt6.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(
            self,
            "Confirmación Final",
            "Para confirmar, escriba exactamente: REINICIAR",
            QLineEdit.EchoMode.Normal,
            ""
        )
        
        if not ok or text.strip() != "REINICIAR":
            QMessageBox.information(self, "Cancelado", "Reinicialización cancelada: confirmación incorrecta.")
            return
        
        # Guardar user_id antes de cerrar sesión
        current_user_id = self.session.user_id
        
        # Cerrar sesión actual
        self.session.clear_key()
        if self.expiry_stop:
            self.expiry_stop.set()
            if self.expiry_thread:
                self.expiry_thread.join(timeout=2)
        
        self.session = None
        self.encrypted_db = None
        self.authenticated = False
        
        # Limpiar la lista
        self.list_table.setRowCount(0)
        
        try:
            # Importar funciones necesarias
            from database import destroy_database_files
            from crypto import derive_key_from_password, wrap_database_key
            
            # Destruir archivos actuales
            destroy_database_files(current_user_id)
            
            # Eliminar DNIe del registro
            import json
            if os.path.exists(DNIE_REGISTRY_FILE):
                registry = load_dnie_registry()
                dnie_hash_to_remove = None
                
                # Buscar el hash del DNIe asociado a este usuario
                for dnie_hash, info in registry.get('dnies', {}).items():
                    if info.get('user_id') == current_user_id:
                        dnie_hash_to_remove = dnie_hash
                        break
                
                # Eliminar el DNIe del registro
                if dnie_hash_to_remove and dnie_hash_to_remove in registry.get('dnies', {}):
                    del registry['dnies'][dnie_hash_to_remove]
                    
                    # Guardar el registro actualizado
                    with open(DNIE_REGISTRY_FILE, 'w') as f:
                        json.dump(registry, f, indent=2)
                    
                    print(f"DEBUG: DNIe {dnie_hash_to_remove[:16]}... eliminado del registro")
            
            QMessageBox.information(
                self,
                "✅ Base de Datos Destruida",
                "La base de datos ha sido destruida exitosamente.\n\n"
                "Ahora se iniciará el proceso de registro con nueva contraseña maestra."
            )
            
            # Detectar el DNIe y llamar a initialize_new_dnie
            try:
                card = DNIeCard()
                card.connect()
                dnie_hash_for_reinit = card.get_serial_hash()
                card.disconnect()
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"No se pudo detectar el DNIe: {e}\n\nDebe iniciar sesión manualmente."
                )
                sys.exit(1)
            
            # Inicializar el DNIe con la nueva base de datos
            self.initialize_new_dnie(dnie_hash_for_reinit)
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "❌ Error Crítico",
                f"Error durante la reinicialización: {e}\n\n"
                "El programa se cerrará por seguridad."
            )
            import traceback
            traceback.print_exc()
            sys.exit(1)

    def on_destroy_database(self):
        """Destruir permanentemente la base de datos del usuario"""
        if not self.check_session():
            return
        
        # RE-AUTENTICACIÓN: Pedir PIN del DNIe y contraseña maestra para confirmar identidad
        from PyQt6.QtWidgets import QInputDialog
        
        QMessageBox.warning(
            self,
            "🔐 Re-autenticación Requerida",
            "Por seguridad, debe re-autenticarse antes de destruir la base de datos.\n\n"
            "Introduzca su PIN del DNIe y contraseña maestra actual.",
            QMessageBox.StandardButton.Ok
        )
        
        # Pedir PIN del DNIe
        pin, ok_pin = QInputDialog.getText(
            self,
            "Re-autenticación - PIN del DNIe",
            "Introduzca el PIN de su DNIe:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok_pin or not pin:
            QMessageBox.information(self, "Cancelado", "Re-autenticación cancelada.")
            return
        
        # Pedir contraseña maestra
        master_password, ok_pass = QInputDialog.getText(
            self,
            "Re-autenticación - Contraseña Maestra",
            "Introduzca su contraseña maestra actual:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok_pass or not master_password:
            QMessageBox.information(self, "Cancelado", "Re-autenticación cancelada.")
            return
        
        # Verificar credenciales
        try:
            # Autenticar con DNIe
            card = DNIeCard()
            card.connect()
            dnie_hash = card.get_serial_hash()
            dnie_wrapping_key = card.authenticate(pin)
            card.disconnect()
            
            # Verificar que es el mismo DNIe de la sesión actual
            current_dnie_hash = None
            registry = load_dnie_registry()
            for dnie, info in registry.get('dnies', {}).items():
                if info.get('user_id') == self.session.user_id:
                    current_dnie_hash = dnie
                    break
            
            if current_dnie_hash != dnie_hash:
                QMessageBox.critical(
                    self,
                    "Error de Autenticación",
                    "El DNIe no corresponde al usuario actual."
                )
                return
            
            # Verificar contraseña maestra
            from crypto import derive_key_from_password, unwrap_database_key
            salt_file = get_salt_filename(self.session.user_id)
            with open(salt_file, 'rb') as f:
                salt = f.read()
            
            password_key = derive_key_from_password(master_password, salt)
            wrapped_key_file = get_wrapped_key_filename(self.session.user_id)
            with open(wrapped_key_file, 'rb') as f:
                wrapped_key = f.read()
            
            # Intentar desencriptar - si falla, la contraseña es incorrecta
            k_db = unwrap_database_key(wrapped_key, dnie_wrapping_key, password_key)
            
            # Limpiar datos sensibles
            del pin
            del master_password
            del dnie_wrapping_key
            del password_key
            del k_db
            
            print("✓ Re-autenticación exitosa")
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error de Re-autenticación",
                f"La re-autenticación falló.\n\nVerifique su PIN y contraseña maestra.\n\nError: {e}"
            )
            return
        
        # Primera advertencia
        reply = QMessageBox.critical(
            self,
            "💣 ADVERTENCIA CRÍTICA: Destruir Base de Datos",
            "Esta acción eliminará PERMANENTEMENTE:\n"
            "• La base de datos encriptada\n"
            "• Archivos de claves\n\n"
            "Esta acción es COMPLETAMENTE IRREVERSIBLE.\n"
            "NO HAY MANERA de recuperar los datos después.\n\n"
            "¿Está ABSOLUTAMENTE SEGURO?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            QMessageBox.information(self, "Cancelado", "Destrucción de base de datos cancelada.")
            return
        
        # Segunda confirmación escribiendo "DESTRUIR"
        from PyQt6.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(
            self,
            "Confirmación Final - Paso 1",
            "Para confirmar, escriba exactamente: DESTRUIR",
            QLineEdit.EchoMode.Normal,
            ""
        )
        
        if not ok or text.strip() != "DESTRUIR":
            QMessageBox.information(self, "Cancelado", "Destrucción cancelada: confirmación incorrecta.")
            return
        
        # Tercera confirmación escribiendo el user_id
        text2, ok2 = QInputDialog.getText(
            self,
            "Confirmación Final - Paso 2",
            f"Escriba su ID de usuario para confirmar: {self.session.user_id}",
            QLineEdit.EchoMode.Normal,
            ""
        )
        
        if not ok2 or text2.strip() != self.session.user_id:
            QMessageBox.information(self, "Cancelado", "Destrucción cancelada: ID de usuario incorrecto.")
            return
        
        # Mostrar progreso
        progress = QProgressDialog("Destruyendo base de datos permanentemente...", None, 0, 0, self)
        progress.setWindowTitle("Destruyendo")
        progress.setModal(True)
        progress.show()
        
        try:
            # Importar función de database.py
            from database import destroy_database_files
            
            current_user_id = self.session.user_id
            
            
            # Cerrar sesión
            self.session.clear_key()
            if self.expiry_stop:
                self.expiry_stop.set()
                if self.expiry_thread:
                    self.expiry_thread.join(timeout=2)
            
            self.session = None
            self.encrypted_db = None
            self.authenticated = False
            
            # Destruir archivos
            destroy_database_files(current_user_id)

            # Eliminar DNIe del registro
            import json
            if os.path.exists(DNIE_REGISTRY_FILE):
                registry = load_dnie_registry()
                dnie_hash_to_remove = None
                
                # Buscar el hash del DNIe asociado a este usuario
                for dnie_hash, info in registry.get('dnies', {}).items():
                    if info.get('user_id') == current_user_id:
                        dnie_hash_to_remove = dnie_hash
                        break
                
                # Eliminar el DNIe del registro
                if dnie_hash_to_remove and dnie_hash_to_remove in registry.get('dnies', {}):
                    del registry['dnies'][dnie_hash_to_remove]
                    
                    # Guardar el registro actualizado
                    with open(DNIE_REGISTRY_FILE, 'w') as f:
                        json.dump(registry, f, indent=2)
                    
                    print(f"DEBUG: DNIe {dnie_hash_to_remove[:16]}... eliminado del registro")

            progress.close()
            
            QMessageBox.information(
                self,
                "✅ Base de Datos Destruida",
                f"La base de datos del usuario '{current_user_id}' ha sido destruida permanentemente.\n\n"
                "El programa se cerrará ahora."
            )
            
            sys.exit(0)
            
        except Exception as e:
            progress.close()
            QMessageBox.critical(
                self,
                "❌ Error",
                f"Error durante la destrucción: {e}"
            )

    
    def closeEvent(self, event):
        """Manejar cierre de ventana con rotación automática de claves"""
        if not self.authenticated:
            event.accept()
            return
        
        if self.session:
            reply = QMessageBox.question(
                self,
                "Cerrar aplicación",
                "¿Desea cerrar el gestor de contraseñas?\n\n"
                "Las claves de la base de datos se rotarán automáticamente "
                "para garantizar forward secrecy.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
            
            progress = QProgressDialog("Rotando claves de seguridad...", None, 0, 0, self)
            progress.setWindowTitle("Cerrando sesión")
            progress.setModal(True)
            progress.show()
            
            from main import auto_rotate_on_logout
            auto_rotate_on_logout(self.session)
            
            progress.close()
            
            if self.expiry_stop:
                self.expiry_stop.set()
            if self.expiry_thread:
                self.expiry_thread.join(timeout=2)
            
            self.session.clear_key()
        
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = PasswordManagerWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
