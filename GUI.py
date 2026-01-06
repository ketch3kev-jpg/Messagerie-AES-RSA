"""
Application de messagerie sécurisée - Interface fusionnée
Combinaison du meilleur de GUI.py et main_window.py
"""

import sys
import os
from datetime import datetime
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
    QMessageBox, QProgressBar, QSplitter, QFrame, QScrollArea,
    QMenu, QAction, QDialog, QDialogButtonBox, QFormLayout
)
from PyQt5.QtCore import Qt, pyqtSignal as Signal, QTimer, QSize, QRect
from PyQt5.QtGui import QFont, QColor, QPixmap, QIcon, QPainter, QPainterPath, QBrush, QPen

# Imports des modules du projet
from server.client_socket import ClientSocket
from crypto.key_exchange import KeyExchangeProtocol
from crypto.rsa_manager import RSAManager
from server.MessageProtocole import MessageProtocol, MessageType

# ============================================================================
# Gestionnaire de thème (depuis main_window.py)
# ============================================================================

class ThemeManager:
    """Gère les thèmes clair et sombre"""
    
    LIGHT_THEME = {
        "primary": "#0084ff",
        "primary_hover": "#0073e0",
        "primary_pressed": "#0062c4",
        "background": "#ffffff",
        "background_secondary": "#f8f9fa",
        "background_tertiary": "#f0f0f0",
        "text_primary": "#000000",
        "text_secondary": "#666666",
        "text_tertiary": "#999999",
        "border": "#e5e5ea",
        "message_me": "#0084ff",
        "message_other": "#e5e5ea",
        "message_text_me": "#ffffff",
        "message_text_other": "#000000",
        "scrollbar": "#cccccc",
        "scrollbar_hover": "#aaaaaa",
        "search_background": "#ffffff",
        "search_icon": "#666666",
        "icon_color": "#666666",
        "input_background": "#ffffff",
        "input_border": "#e5e5ea"
    }
    
    DARK_THEME = {
        "primary": "#0084ff",
        "primary_hover": "#0073e0",
        "primary_pressed": "#0062c4",
        "background": "#1e1e1e",
        "background_secondary": "#2d2d2d",
        "background_tertiary": "#3d3d3d",
        "text_primary": "#ffffff",
        "text_secondary": "#cccccc",
        "text_tertiary": "#999999",
        "border": "#404040",
        "message_me": "#0084ff",
        "message_other": "#3d3d3d",
        "message_text_me": "#ffffff",
        "message_text_other": "#ffffff",
        "scrollbar": "#555555",
        "scrollbar_hover": "#777777",
        "search_background": "#2d2d2d",
        "search_icon": "#cccccc",
        "icon_color": "#cccccc",
        "input_background": "#2d2d2d",
        "input_border": "#404040"
    }
    
    @staticmethod
    def get_theme(is_dark=False):
        """Retourne le thème approprié"""
        return ThemeManager.DARK_THEME if is_dark else ThemeManager.LIGHT_THEME

# ============================================================================
# Composants d'interface 
# ============================================================================

class AvatarLabel(QLabel):
    """Crée un avatar circulaire avec une lettre"""
    
    def __init__(self, text, size=40, is_dark=False, parent=None):
        super().__init__(parent)
        self.text = text
        self.size = size
        self.is_dark = is_dark
        self.setFixedSize(size, size)
        self.setAlignment(Qt.AlignCenter)
        self.draw_avatar()
    
    def draw_avatar(self):
        """Dessine un avatar circulaire"""
        pixmap = QPixmap(self.size, self.size) #Crée une image en mémoire (bitmap), que Qt utilise pour dessiner.L’image créée a une largeur self.size et une hauteur self.size
        pixmap.fill(QColor(0, 0, 0, 0))  #Cette ligne remplit complètement le pixmap avec une couleur RGBA,Résultat Le pixmap devient un carré totalement transparent.
        """ Pourquoi remplir en transparent ?

        Pour partir d’une image vide afin d’y dessiner des formes, cercles, cadres, etc., sans laisser de pixels "sales
        """                                      
        painter = QPainter(pixmap) #Crée un objet QPainter qui permet de dessiner sur le pixmap.
        """
        Lorsque tu fais :
            painter = QPainter(pixmap)
            tu dis à Qt :
            "À partir de maintenant, tous les dessins (cercles, lignes, textes…) iront sur ce pixmap".
        """
        painter.setRenderHint(QPainter.Antialiasing) #Active l’antialiasing, c’est-à-dire le lissage des bords (anti-crénelage).
        
        # Couleur de fond (bleu Google Messages)
        brush = QBrush(QColor(0, 132, 255)) #
        """
        Ce que ça fait
            Crée un pinceau (brush).
            Un brush sert à remplir une forme.
            La couleur utilisée est QColor(0, 132, 255), un bleu (R=0, G=132, B=255).
            ✔ En résumé
            On prépare de quoi remplir l'ellipse avec un bleu.
        """
        painter.setBrush(brush)#On dit au QPainter :Quand tu dessineras une forme, remplis-la avec ce brush bleu
        painter.setPen(Qt.NoPen)#Désactive le stylo (pen).Un pen sert à dessiner les contours des formes
        painter.drawEllipse(0, 0, self.size, self.size)
        """
        Ce que ça fait
            Dessine une ellipse (ou ici un cercle, car largeur=hauteur).
            Paramètres :
            0, 0 → coin supérieur gauche du rectangle englobant
            self.size, self.size → largeur et hauteur du cercle
            Donc tu dessines un cercle bleu plein, parfaitement rond, occupant tout le pixmap.
        """
        # Texte
        painter.setPen(QColor(255, 255, 255))#Le pen est utilisé pour dessiner du texte et des contours.Ici, on met le pen à une couleur blanche (R=255, G=255, B=255).
        font = QFont("Arial", self.size // 2)#rée une police (QFont)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(0, 0, self.size, self.size, Qt.AlignCenter, self.text)#Dessine du texte au centre du cercle.
        
        painter.end()
        self.setPixmap(pixmap)

class MessageBubble(QFrame):
    """Crée une bulle de message arrondie comme Google Messages"""
    
    def __init__(self, text, is_me=False, is_dark=False, parent=None):
        super().__init__(parent)
        self.is_me = is_me
        self.text = text
        self.is_dark = is_dark
        self.theme = ThemeManager.get_theme(is_dark)
        self.setup_bubble()
    
    def setup_bubble(self):
        """Configure l'apparence de la bulle comme Google Messages"""
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 10, 15, 10)
        
        label = QLabel(self.text)
        label.setWordWrap(True)
        label.setFont(QFont("Arial", 11))
        
        if self.is_me:
            # Message envoyé : bleu avec texte blanc
            label.setStyleSheet(f"color: {self.theme['message_text_me']}; background: transparent;")
            self.setStyleSheet(f"""
                MessageBubble {{
                    background-color: {self.theme['message_me']};
                    border-radius: 18px;
                    border-bottom-right-radius: 4px;
                    margin-left: 80px;
                    margin-right: 10px;
                }}
            """)
        else:
            # Message reçu : gris avec texte adapté au thème
            label.setStyleSheet(f"color: {self.theme['message_text_other']}; background: transparent;")
            self.setStyleSheet(f"""
                MessageBubble {{
                    background-color: {self.theme['message_other']};
                    border-radius: 18px;
                    border-bottom-left-radius: 4px;
                    margin-left: 10px;
                    margin-right: 80px;
                }}
            """)
        
        layout.addWidget(label)
        self.setLayout(layout)

# ============================================================================
# Fenêtre de connexion (adaptée de GUI.py)
# ============================================================================

class LoginWindow(QWidget):
    """Fenêtre de connexion et d'inscription"""
    
    # Signal émis quand la connexion réussit
    login_successful = Signal(str, object, object, object)  # username, client, key_exchange, auth_data
    
    def __init__(self):
        super().__init__()
        self.client = None
        self.init_ui()
    
    def init_ui(self):
        """Initialise l'interface"""
        self.setWindowTitle("Connexion - Messagerie Sécurisée")
        self.setMinimumSize(400, 300)
        
        # Layout principal
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Titre
        title = QLabel(" Messagerie Sécurisée")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Sous-titre
        subtitle = QLabel("Chiffrement de bout en bout avec RSA + AES")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: gray;")
        layout.addWidget(subtitle)
        
        layout.addSpacing(20)
        
        # Champs de saisie
        # Serveur
        server_layout = QHBoxLayout()
        server_label = QLabel("Serveur:")
        server_label.setMinimumWidth(100)
        self.server_input = QLineEdit()
        self.server_input.setText("localhost")
        self.server_input.setPlaceholderText("localhost ou IP")
        server_layout.addWidget(server_label)
        server_layout.addWidget(self.server_input)
        layout.addLayout(server_layout)
        
        # Port
        port_layout = QHBoxLayout()
        port_label = QLabel("Port:")
        port_label.setMinimumWidth(100)
        self.port_input = QLineEdit()
        self.port_input.setText("5555")
        self.port_input.setPlaceholderText("5555")
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        layout.addLayout(port_layout)
        
        # Nom d'utilisateur
        username_layout = QHBoxLayout()
        username_label = QLabel("Utilisateur:")
        username_label.setMinimumWidth(100)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Nom d'utilisateur")
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        layout.addLayout(username_layout)
        
        # Mot de passe
        password_layout = QHBoxLayout()
        password_label = QLabel("Mot de passe:")
        password_label.setMinimumWidth(100)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Mot de passe")
        self.password_input.returnPressed.connect(self.on_enter_pressed)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        layout.addSpacing(10)
        
        # Barre de progression (cachée au début)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Label de statut
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: blue;")
        layout.addWidget(self.status_label)
        
        # Boutons
        button_layout = QHBoxLayout()
        
        self.login_btn = QPushButton("Se connecter")
        self.login_btn.setMinimumHeight(35)
        self.login_btn.clicked.connect(self.on_login_click)
        
        self.register_btn = QPushButton("S'inscrire")
        self.register_btn.setMinimumHeight(35)
        self.register_btn.clicked.connect(self.on_register_click)
        
        button_layout.addWidget(self.login_btn)
        button_layout.addWidget(self.register_btn)
        layout.addLayout(button_layout)
        
        layout.addStretch()
        
        self.setLayout(layout)
    
    def set_status(self, message, color="blue"):
        """Affiche un message de statut"""
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color};")

    def on_login_click(self):
        """Gère la connexion"""
        host = self.server_input.text().strip() or "localhost"
        port = int(self.port_input.text().strip() or "5555")
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        print(f" Tentative de connexion: {username}@{host}:{port}")
        
        if not username or not password:
            QMessageBox.warning(self, "Erreur", "Veuillez remplir tous les champs")
            return
        
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        self.set_status("Chargement des clés...", "blue")
        
        try:
            print(f" Chargement des clés pour '{username}'...")
            
            try:
                public_key, private_key = RSAManager.load_keypair(username, password)
                print(f"✓ Clés chargées avec succès")
                self.set_status("Clés chargées ✓", "green")
                
            except FileNotFoundError as e:
                print(f" Clés non trouvées: {e}")
                QMessageBox.critical(
                    self,
                    "Erreur",
                    f"Aucune clé trouvée pour '{username}'.\n"
                    "Veuillez d'abord vous inscrire."
                )
                self.login_btn.setEnabled(True)
                self.register_btn.setEnabled(True)
                self.set_status("", "blue")
                return
                
            except ValueError as e:
                print(f" Erreur de déchiffrement: {e}")
                QMessageBox.critical(
                    self,
                    "Erreur",
                    "Mot de passe incorrect pour le déchiffrement des clés."
                )
                self.login_btn.setEnabled(True)
                self.register_btn.setEnabled(True)
                self.set_status("", "blue")
                return
            
            print(f" Connexion au serveur {host}:{port}...")
            self.set_status("Connexion au serveur...", "blue")
            self.client = ClientSocket()
            
            auth_data = self.client.connect(host, port, username, password)
            print(f" Authentifié: {auth_data}")
            
            print(f" Initialisation KeyExchange...")
            key_exchange = KeyExchangeProtocol(private_key, public_key)
            
            self.set_status("Connecté ", "green")
            print(f" Connexion complète !")
            
            self.login_successful.emit(username, self.client, key_exchange, auth_data)
            self.close()
        
        except ConnectionError as e:
            print(f" Erreur de connexion: {e}")
            QMessageBox.critical(self, "Erreur de connexion", str(e))
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
            self.set_status("Échec de connexion", "red")
        
        except Exception as e:
            print(f" ERREUR INATTENDUE: {e}")
            import traceback
            traceback.print_exc()
            
            QMessageBox.critical(self, "Erreur", f"Erreur inattendue : {e}")
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
            self.set_status("Erreur", "red")

    def on_enter_pressed(self):
        """Handler lorsque l'utilisateur appuie sur Entrée dans le champ mot de passe"""
        reply = QMessageBox.question(
            self,
            "Action requise",
            "Voulez-vous vous connecter (Oui) ou créer un compte (Non) ?",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
        )

        if reply == QMessageBox.Yes:
            self.on_login_click()
        elif reply == QMessageBox.No:
            self.on_register_click()
        else:
            return

    def on_register_click(self):
        """Gère l'inscription"""
        host = self.server_input.text().strip() or "localhost"
        port = int(self.port_input.text().strip() or "5555")
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            QMessageBox.warning(self, "Erreur", "Veuillez remplir tous les champs")
            return
        
        if len(password) < 8:
            QMessageBox.warning(
                self,
                "Mot de passe faible",
                "Le mot de passe doit contenir au moins 8 caractères."
            )
            return
        
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Créer un compte pour '{username}' ?\n"
            "Cela va générer une paire de clés RSA (peut prendre quelques secondes).",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.set_status("Génération des clés RSA...", "blue")
        
        try:
            public_key, private_key = RSAManager.generate_keypair(bit_length=2048)
            self.set_status("Clés générées ", "green")
            
            RSAManager.save_keypair(username, public_key, private_key, password)
            self.set_status("Clés sauvegardées ", "green")
            
            self.set_status("Inscription sur le serveur...", "blue")
            temp_client = ClientSocket()
            temp_client.register(host, port, username, password, public_key)
            
            self.progress_bar.setVisible(False)
            self.set_status("Inscription réussie ", "green")
            
            QMessageBox.information(
                self,
                "Succès",
                f"Compte '{username}' créé avec succès !\n"
                "Vous pouvez maintenant vous connecter."
            )
            
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
        
        except Exception as e:
            self.progress_bar.setVisible(False)
            QMessageBox.critical(self, "Erreur d'inscription", str(e))
            self.login_btn.setEnabled(True)
            self.register_btn.setEnabled(True)
            self.set_status("Échec d'inscription", "red")

# ============================================================================
# Zone de chat moderne (depuis main_window.py)
# ============================================================================

class ChatArea(QWidget):
    """Zone d'affichage des messages moderne"""
    
    message_sent = Signal(str, str)  # (to_user, text)
    def __init__(self, is_dark=False, parent=None):
        super().__init__(parent)
        self.current_conversation = None
        self.is_dark = is_dark
        self.theme = ThemeManager.get_theme(is_dark)
        self.conversations = {}  # Stockage des conversations
        self.setup_ui()
    
    def setup_ui(self):
        """Configure l'interface"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        self.header = self.create_header()
        layout.addWidget(self.header)
        
        # Zone de messages scrollable
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet(f"""
            QScrollArea {{
                background-color: {self.theme['background']};
                border: none;
            }}
            QScrollBar:vertical {{
                width: 8px;
                background-color: {self.theme['background']};
            }}
            QScrollBar::handle:vertical {{
                background-color: {self.theme['scrollbar']};
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {self.theme['scrollbar_hover']};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                border: none;
                background: none;
            }}
        """)
        
        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout()
        self.messages_layout.setSpacing(8)
        self.messages_layout.setContentsMargins(10, 10, 10, 10)
        self.messages_layout.addStretch()
        self.messages_container.setLayout(self.messages_layout)
        self.messages_container.setStyleSheet(f"background-color: {self.theme['background']};")
        
        self.scroll_area.setWidget(self.messages_container)
        layout.addWidget(self.scroll_area, 1)
        
        # Zone de saisie
        self.input_area = self.create_input_area()
        layout.addWidget(self.input_area)
        
        self.setLayout(layout)
    
    def create_header(self):
        """Crée le header avec infos du contact"""
        header = QFrame()
        header.setStyleSheet(f"""
            QFrame {{
                background-color: {self.theme['background_secondary']};
                border-bottom: 1px solid {self.theme['border']};
            }}
        """)
        header.setFixedHeight(70)
        
        layout = QHBoxLayout()
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(15)
        
        # Avatar
        self.header_avatar = AvatarLabel("U", size=50, is_dark=self.is_dark)
        layout.addWidget(self.header_avatar)
        
        # Infos texte
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        
        self.header_name = QLabel("Sélectionnez une conversation")
        self.header_name.setFont(QFont("Arial", 14, QFont.Bold))
        self.header_name.setStyleSheet(f"color: {self.theme['text_primary']};")
        info_layout.addWidget(self.header_name)
        
        self.header_status = QLabel("Connecté")
        self.header_status.setFont(QFont("Arial", 11))
        self.header_status.setStyleSheet(f"color: {self.theme['text_secondary']};")
        info_layout.addWidget(self.header_status)
        
        layout.addLayout(info_layout, 1)
        layout.addStretch()
        
        header.setLayout(layout)
        return header
    
    def create_input_area(self):
        """Crée la zone de saisie avec bords arrondis"""
        input_frame = QFrame()
        input_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {self.theme['background_secondary']};
                border-top: 1px solid {self.theme['border']};
                border-radius: 0px;
            }}
        """)
        input_frame.setFixedHeight(90)
        
        layout = QHBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)
        
        # Champ de saisie avec bords arrondis
        self.input_container = QFrame()
        self.input_container.setStyleSheet(f"""
            QFrame {{
                background-color: {self.theme['input_background']};
                border: 2px solid {self.theme['input_border']};
                border-radius: 25px;
            }}
        """)
        self.input_container.setFixedHeight(50)
        
        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(20, 0, 20, 0)
        input_layout.setSpacing(10)
        
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Écrivez un message...")
        self.input_field.setStyleSheet(f"""
            QLineEdit {{
                background-color: transparent;
                color: {self.theme['text_primary']};
                border: none;
                font-size: 11pt;
                selection-background-color: {self.theme['primary']};
            }}
            QLineEdit:focus {{
                border: none;
                outline: none;
            }}
        """)
        self.input_field.setFont(QFont("Arial", 11))
        self.input_field.returnPressed.connect(self.send_message)
        self.input_field.setEnabled(False)
        
        input_layout.addWidget(self.input_field)
        self.input_container.setLayout(input_layout)
        layout.addWidget(self.input_container, 1)
        
        # Bouton envoyer avec bords arrondis
        self.send_btn = QPushButton("Envoyer")
        self.send_btn.setFixedSize(100, 50)
        self.send_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {self.theme['primary']};
                color: white;
                border: none;
                border-radius: 25px;
                font-weight: bold;
                font-size: 11pt;
            }}
            QPushButton:hover {{
                background-color: {self.theme['primary_hover']};
            }}
            QPushButton:pressed {{
                background-color: {self.theme['primary_pressed']};
            }}
            QPushButton:disabled {{
                background-color: {self.theme['border']};
                color: {self.theme['text_tertiary']};
            }}
        """)
        self.send_btn.setFont(QFont("Arial", 11, QFont.Bold))
        self.send_btn.clicked.connect(self.send_message)
        self.send_btn.setEnabled(False)
        layout.addWidget(self.send_btn)
        
        input_frame.setLayout(layout)
        return input_frame
    
    def load_conversation(self, user_id, user_data):
        """Charge une conversation avec un utilisateur"""
        self.current_conversation = user_id
        
        # Met à jour le header
        self.header_avatar.text = user_data.get("avatar", user_id[0].upper())
        self.header_avatar.draw_avatar()
        self.header_name.setText(user_data.get("name", user_id))
        
        # CORRECTION : Afficher le statut réel
        is_online = user_data.get("online", False)
        self.header_status.setText("En ligne" if is_online else "Hors ligne")
        
        # Efface les messages précédents
        while self.messages_layout.count() > 1:
            item = self.messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Charge les messages depuis les données réelles
        messages = user_data.get("messages", [])
        for msg in messages:
            bubble = MessageBubble(
                msg["content"], 
                is_me=msg.get("is_me", False),
                is_dark=self.is_dark
            )
            self.messages_layout.insertWidget(
                self.messages_layout.count() - 1, bubble
            )
        
        # Active la zone de saisie
        self.input_field.setEnabled(True)
        self.send_btn.setEnabled(True)
        self.input_field.setFocus()
        
        # Scroll vers le bas
        QTimer.singleShot(100, self.scroll_to_bottom)
        
        # NE PAS initier l'échange de clés ICI
        # C'est le rôle de MainWindow.load_conversation()
        
    def scroll_to_bottom(self):
        """Scroll vers le bas de la zone de messages"""
        scrollbar = self.scroll_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def send_message(self):
        """Envoie un message"""
        text = self.input_field.text().strip()
        if text and self.current_conversation is not None:
            # Créer la bulle de message
            bubble = MessageBubble(text, is_me=True, is_dark=self.is_dark)
            self.messages_layout.insertWidget(
                self.messages_layout.count() - 1, bubble
            )
            
            self.message_sent.emit(self.current_conversation, text)
            
            self.input_field.clear()
            self.scroll_to_bottom()
    
    def add_message(self, from_user, content, is_me=False):
        """Ajoute un message reçu"""
        bubble = MessageBubble(content, is_me=is_me, is_dark=self.is_dark)
        self.messages_layout.insertWidget(
            self.messages_layout.count() - 1, bubble
        )
        self.scroll_to_bottom()

# ============================================================================
# Barre latérale moderne (adaptée de main_window.py)
# ============================================================================

class Sidebar(QWidget):
    """Panneau latéral avec conversations"""
    
    def __init__(self, on_select_conversation, is_dark=False, parent=None):
        super().__init__(parent)
        self.on_select_conversation = on_select_conversation
        self.is_dark = is_dark
        self.theme = ThemeManager.get_theme(is_dark)
        self.conversations = {}
        self.setup_ui()
    
    def setup_ui(self):
        """Configure l'interface"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header avec titre
        self.header_frame = QFrame()
        self.header_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {self.theme['background_secondary']};
                border-bottom: 1px solid {self.theme['border']};
            }}
        """)
        self.header_frame.setFixedHeight(70)
        
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(20, 10, 20, 10)
        
        self.title_label = QLabel("Messages")
        self.title_label.setFont(QFont("Arial", 18, QFont.Bold))
        self.title_label.setStyleSheet(f"color: {self.theme['text_primary']};")
        header_layout.addWidget(self.title_label)
        
        header_layout.addStretch()
        
        self.header_frame.setLayout(header_layout)
        layout.addWidget(self.header_frame)
        
        # Liste des conversations
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet(f"""
            QScrollArea {{
                background-color: {self.theme['background']};
                border: none;
            }}
            QScrollBar:vertical {{
                width: 8px;
                background-color: {self.theme['background']};
            }}
            QScrollBar::handle:vertical {{
                background-color: {self.theme['scrollbar']};
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {self.theme['scrollbar_hover']};
            }}
        """)
        
        self.conv_list = QListWidget()
        self.conv_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {self.theme['background']};
                border: none;
                outline: none;
            }}
            QListWidget::item {{
                padding: 0px;
                border-radius: 0px;
                border: none;
            }}
            QListWidget::item:hover {{
                background-color: {self.theme['background_tertiary']};
            }}
            QListWidget::item:selected {{
                background-color: {self.theme['background_secondary']};
                border-left: 4px solid {self.theme['primary']};
            }}
        """)
        self.conv_list.itemClicked.connect(self.on_conversation_selected)
        
        self.scroll_area.setWidget(self.conv_list)
        layout.addWidget(self.scroll_area, 1)
        
        self.setLayout(layout)
    
    def load_conversations(self):
        """Charge les conversations dans la liste"""
        self.conv_list.clear()
        for user_id, conv in self.conversations.items():
            item = QListWidgetItem()
            item.setSizeHint(QSize(250, 80))
            self.conv_list.addItem(item)
            
            # Widget personnalisé pour l'item
            item_widget = self.create_conv_item(conv)
            self.conv_list.setItemWidget(item, item_widget)
    
    def create_conv_item(self, conv):
        """Crée un widget pour un item de conversation"""
        widget = QWidget()
        widget.setStyleSheet(f"background-color: transparent;")
        
        layout = QHBoxLayout()
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(15)
        
        # Avatar
        avatar = AvatarLabel(conv["avatar"], size=55, is_dark=self.is_dark)
        layout.addWidget(avatar)
        
        # Infos texte
        text_layout = QVBoxLayout()
        text_layout.setSpacing(4)
        
        name = QLabel(conv["name"])
        name.setFont(QFont("Arial", 12, QFont.Bold))
        name.setStyleSheet(f"color: {self.theme['text_primary']};")
        text_layout.addWidget(name)
        
        last_msg = QLabel(conv["last_msg"])
        last_msg.setFont(QFont("Arial", 10))
        last_msg.setStyleSheet(f"color: {self.theme['text_secondary']};")
        last_msg.setWordWrap(True)
        text_layout.addWidget(last_msg)
        
        layout.addLayout(text_layout, 1)
        
        # Badge de messages non lus
        if conv.get("unread", 0) > 0:
            badge = QLabel(str(conv["unread"]))
            badge.setFont(QFont("Arial", 9, QFont.Bold))
            badge.setFixedSize(20, 20)
            badge.setAlignment(Qt.AlignCenter)
            badge.setStyleSheet(f"""
                background-color: {self.theme['primary']};
                color: white;
                border-radius: 10px;
            """)
            layout.addWidget(badge)
        
        widget.setLayout(layout)
        return widget
    
    def on_conversation_selected(self, item):
        """Quand une conversation est sélectionnée"""
        index = self.conv_list.row(item)
        if 0 <= index < self.conv_list.count():
            user_id = list(self.conversations.keys())[index]
            self.on_select_conversation(user_id, self.conversations[user_id])
    
    def update_conversations(self, conversations_data):
        """Met à jour la liste des conversations"""
        self.conversations = conversations_data
        self.load_conversations()

# ============================================================================
# Fenêtre principale fusionnée
# ============================================================================

class MainWindow(QMainWindow):
    """Fenêtre principale de l'application de messagerie"""
    
    message_received_signal = Signal(dict)  
    
    def __init__(self, username, client, key_exchange, auth_data):
        super().__init__()
        
        self.username = username
        self.client = client
        self.key_exchange = key_exchange
        self.current_peer = None
        
        #  CONNECTER le signal au handler (dans le thread UI)
        self.message_received_signal.connect(self._process_message_safely)
        
        # Définir le callback pour les messages reçus
        self.client.set_callback(self.on_message_received)
        
        self.initUI(auth_data)
    
    def initUI(self, auth_data):
        """Initialise l'interface"""
        self.setWindowTitle(f"CryptoChat - {self.username}")
        self.setGeometry(100, 100, 1400, 800)
        self.setMinimumSize(1000, 600)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal horizontal
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Barre latérale (1/3 de la largeur)
        self.sidebar = Sidebar(self.load_conversation, is_dark=True)
        self.sidebar.setFixedWidth(350)
        
        # Zone de chat (2/3 de la largeur)
        self.chat_area = ChatArea(is_dark=True)
        
        # CRITIQUE : Connecter le signal message_sent
        self.chat_area.message_sent.connect(self.on_chat_area_message_sent)
        
        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.chat_area, 1)
        
        central_widget.setLayout(main_layout)
        
        # Initialiser les conversations avec les utilisateurs en ligne
        self.update_online_users(auth_data)
        
        self.show()

    def on_chat_area_message_sent(self, to_user, text):
        """Slot appelé quand ChatArea émet un message"""
        print(f"[GUI] on_chat_area_message_sent appelé: to={to_user}, text='{text}'")
        self.send_chat_message(to_user, text)
    def debug_sessions(self):
        """Affiche l'état des sessions pour debug"""
        print("=" * 60)
        print("DEBUG SESSIONS")
        print("=" * 60)
        sessions = self.key_exchange.list_active_sessions()
        print(f"Utilisateur: {self.username}")
        print(f"Sessions actives: {sessions}")
        for peer in sessions:
            info = self.key_exchange.get_session_info(peer)
            print(f"  - {peer}:")
            print(f"    Created: {info['age']:.1f}s ago")
            print(f"    Messages: {info['message_count']}")
            print(f"    Initiated by me: {info['initiated_by_me']}")
        print("=" * 60)     
         
    def update_online_users(self, auth_data):
        """Met à jour la liste des utilisateurs en ligne"""
        user_list = auth_data.get('user_list', [])
        print(f"DEBUG: Liste utilisateurs reçue: {user_list}")
        
        conversations = {}
        for user in user_list:
            if user != self.username:
                conversations[user] = {
                    "user_id": user,
                    "name": user,
                    "avatar": user[0].upper(),
                    "last_msg": "Nouveau contact",
                    "unread": 0,
                    "online": False,  #  OFFLINE par défaut
                    "messages": []
                }
        
        self.sidebar.update_conversations(conversations)
        #  NE PAS initier d'échange de clés ici !
    def load_conversation(self, user_id, conv_data):
        """Charge une conversation"""
        self.current_peer = user_id
        self.chat_area.load_conversation(user_id, conv_data)
        
        #  CORRECTION : TOUJOURS initier l'échange si pas de session
        if not self.key_exchange.has_session(user_id):
            print(f" Session manquante avec {user_id}, initiation automatique...")
            self.initiate_key_exchange(user_id)
    
    def initiate_key_exchange(self, username):
        """Initie l'échange de clés avec un utilisateur"""
        print(f" Initiation échange de clés avec {username}...")
        
        # Demander la clé publique au serveur
        self.client.send_key_request(username)
        
    def send_chat_message(self, to_user, text):
        """Envoie un message chiffré via le client"""
        print(f"[SEND] Tentative d'envoi à {to_user}: '{text}'")
        self.debug_sessions()
        # 1. Validation des conditions d'envoi
        if not text.strip():
            print("[SEND] Message vide")
            return
            
        if not self.client or not self.client.is_connected():
            print("[SEND] Pas connecté au serveur")
            QMessageBox.critical(self, "Erreur", "Non connecté au serveur")
            return
            
        if to_user not in self.sidebar.conversations:
            print(f"[SEND] Utilisateur {to_user} introuvable dans conversations")
            print(f"[SEND] Conversations disponibles: {list(self.sidebar.conversations.keys())}")
            QMessageBox.warning(self, "Erreur", f"Utilisateur {to_user} introuvable")
            return
        
        # 2. Gestion des sessions manquantes
        has_session = self.key_exchange.has_session(to_user)
        print(f"[SEND] Session avec {to_user}? {has_session}")
        
        if not has_session:
            print(f"[SEND] Pas de session avec {to_user}, initiation et mise en attente...")
            
            # Initier l'échange de clés
            self.initiate_key_exchange(to_user)
            
            # Stocker le message pour envoi ultérieur
            if not hasattr(self, 'pending_messages'):
                self.pending_messages = {}
            if to_user not in self.pending_messages:
                self.pending_messages[to_user] = []
            self.pending_messages[to_user].append(text)
            
            print(f"[SEND] Message mis en attente pour {to_user}")
            self.statusBar().showMessage(f"Echange de cles avec {to_user}...", 3000)
            return
        
        # 3. Chiffrement et envoi
        try:
            print(f"[SEND] Chiffrement du message pour {to_user}...")
            msg_data = self.key_exchange.encrypt_message(to_user, text)
            
            print(f"[SEND] Type de msg_data: {type(msg_data)}")
            print(f"[SEND] Clés de msg_data: {list(msg_data.keys()) if isinstance(msg_data, dict) else 'NOT A DICT'}")
            
            # Vérification du format
            if not isinstance(msg_data, dict):
                raise ValueError(f"encrypt_message() devrait retourner un dict, a retourné: {type(msg_data)}")
                
            required_keys = ['ciphertext', 'nonce', 'tag']
            missing_keys = [key for key in required_keys if key not in msg_data]
            if missing_keys:
                raise ValueError(f"Données de chiffrement manquantes: {missing_keys}")
            
            print(f"[SEND] Données chiffrées OK:")
            print(f"  - ciphertext: {len(msg_data['ciphertext'])} bytes")
            print(f"  - nonce: {len(msg_data['nonce'])} bytes")
            print(f"  - tag: {len(msg_data['tag'])} bytes")
            
            print(f"[SEND] Envoi au serveur...")
            self.client.send_chat_message(
                to_user,
                msg_data['ciphertext'],
                msg_data['nonce'],
                msg_data['tag']
            )
            
            print(f"[SEND] Message envoyé à {to_user}")
            
            # Mise à jour de l'historique local
            if to_user in self.sidebar.conversations:
                if "messages" not in self.sidebar.conversations[to_user]:
                    self.sidebar.conversations[to_user]["messages"] = []
                self.sidebar.conversations[to_user]["messages"].append({
                    "content": text,
                    "is_me": True,
                    "timestamp": datetime.now().isoformat()
                })
                self.sidebar.conversations[to_user]["last_msg"] = text
                
        except Exception as e:
            print(f"[SEND] Erreur d'envoi: {e}")
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Erreur d'envoi", f"Impossible d'envoyer le message:\n{e}")
    def _queue_message_for_session(self, to_user, text):
        """Met un message en attente pendant l'échange de clés (BONUS)"""
        if not hasattr(self, '_pending_messages'):
            self._pending_messages = {}
        
        if to_user not in self._pending_messages:
            self._pending_messages[to_user] = []
        
        self._pending_messages[to_user].append(text)
        print(f" Message mis en attente pour {to_user} (session en cours)")
        
        # Optionnel: envoyer automatiquement quand la session est prête
            # Vous pouvez connecter ça à un signal key_exchange_complete
    def on_message_received(self, message):
        """Appelé depuis le thread d'écoute - NE TOUCHE PAS l'UI !"""
        msg_type = message.get('type')
        #print(f"🎯 [DEBUG] on_message_received - Type: {msg_type}")
        #print(f"🎯 [DEBUG] Thread actuel: {threading.current_thread().name}")
        
        #  Émettre le signal (thread-safe automatiquement)
        try:
            self.message_received_signal.emit(message)
            #print(f"🎯 [DEBUG] Signal émis OK")
        except Exception as e:
            #print(f"❌ [DEBUG] Erreur émission signal: {e}")
            import traceback
            traceback.print_exc()
    
    def _process_message_safely(self, message):
        """SLOT connecté au signal - s'exécute dans le thread UI"""
        msg_type = message.get('type')
        
        #print(f"🎯 [DEBUG] ===== _process_message_safely APPELÉ =====")
        #print(f"🎯 [DEBUG] Thread actuel: {threading.current_thread().name}")
        #print(f"🎯 [DEBUG] Type reçu: '{msg_type}' (Python type: {type(msg_type).__name__})")
        #print(f"🎯 [DEBUG] Test égalité: '{msg_type}' == 'key_reply' ? {msg_type == 'key_reply'}")
        
        #  Utilisez les CHAÎNES DIRECTES (pas MessageType.*)
        if msg_type == "key_reply":
            #print(f"🎯 [DEBUG] ✅ MATCH key_reply !")
            #print(f"🎯 [DEBUG] → Appel handle_key_reply pour {message.get('username')}")
            self.handle_key_reply(message)
            
        elif msg_type == "user_online":
            #print(f"🎯 [DEBUG] ✅ MATCH user_online")
            self.handle_user_online(message)
            
        elif msg_type == "user_offline":
            #print(f"🎯 [DEBUG] ✅ MATCH user_offline")
            self.handle_user_offline(message)
            
        elif msg_type == "user_list":
            #print(f"🎯 [DEBUG] ✅ MATCH user_list")
            self.handle_user_list(message)
            
        elif msg_type == "key_exchange":
            #print(f"🎯 [DEBUG] ✅ MATCH key_exchange")
            self.handle_key_exchange(message)
            
        elif msg_type == "chat":
            #print(f"🎯 [DEBUG] ✅ MATCH chat")
            self.handle_chat_message(message)
            
        else:
            #print(f"🎯 [DEBUG] ❌ AUCUN MATCH pour '{msg_type}'")
            print(f"🎯 [DEBUG] Types disponibles: key_reply, user_online, user_offline, user_list, key_exchange, chat")
    
    def handle_key_reply(self, message):
        """Gère la réception d'une clé publique"""
        print(f" [HANDLE_KEY_REPLY] ===== FONCTION APPELÉE =====")
        
        username = message.get('username')
        public_key_data = message.get('public_key')
        
        print(f" [HANDLE_KEY_REPLY] Username: {username}")
        print(f" [HANDLE_KEY_REPLY] Public key présente: {public_key_data is not None}")
        
        if not username or not public_key_data:
            print(f" [HANDLE_KEY_REPLY] Données manquantes!")
            return
        
        try:
            public_key = tuple(public_key_data)
            print(f" [HANDLE_KEY_REPLY] Clé convertie en tuple OK")
        except Exception as e:
            print(f" [HANDLE_KEY_REPLY] Erreur conversion tuple: {e}")
            return
        
        #  Vérifier si session existe
        has_session = self.key_exchange.has_session(username)
        print(f" [HANDLE_KEY_REPLY] Session existe? {has_session}")
        
        if not has_session:
            try:
                print(f" [HANDLE_KEY_REPLY]  Initiation échange AES avec {username}...")
                
                # 1. Générer et chiffrer la clé AES
                encrypted_key = self.key_exchange.initiate_key_exchange(username, public_key)
                print(f" [HANDLE_KEY_REPLY]  Clé AES générée: {len(encrypted_key)} bytes")
                
                # 2. Envoyer au serveur
                self.client.send_key_exchange(username, encrypted_key)
                print(f"🔥 [HANDLE_KEY_REPLY]  Clé AES envoyée à {username}")
                
                self.statusBar().showMessage(f" Clé AES envoyée à {username}", 3000)
                
            except Exception as e:
                print(f" [HANDLE_KEY_REPLY]  ERREUR: {e}")
                import traceback
                traceback.print_exc()
                QMessageBox.critical(self, "Erreur", f"Échec échange de clés: {e}")
        else:
            print(f" [HANDLE_KEY_REPLY]  Session déjà existante")

    def handle_chat_message(self, message):
        """Gère la réception d'un message chiffré"""
        from_user = message['from']
        print(f"[CHAT] Message reçu de {from_user}")
        
        try:
            # Déchiffrer le message
            plaintext = self.key_exchange.decrypt_message(
                from_user,
                MessageProtocol.decode_bytes(message['ciphertext']),
                MessageProtocol.decode_bytes(message['nonce']),
                MessageProtocol.decode_bytes(message['tag'])
            )
            
            text = plaintext.decode('utf-8')
            print(f"[CHAT] Message déchiffré: '{text}'")
            
            # Mettre à jour l'interface
            if from_user in self.sidebar.conversations:
                # Ajouter à l'historique
                if "messages" not in self.sidebar.conversations[from_user]:
                    self.sidebar.conversations[from_user]["messages"] = []
                
                self.sidebar.conversations[from_user]["messages"].append({
                    "content": text,
                    "is_me": False,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Mettre à jour le dernier message
                self.sidebar.conversations[from_user]["last_msg"] = text
                self.sidebar.conversations[from_user]["unread"] = \
                    self.sidebar.conversations[from_user].get("unread", 0) + 1
            
            # Afficher le message si c'est la conversation active
            if self.current_peer == from_user:
                self.chat_area.add_message(from_user, text, is_me=False)
                # Réinitialiser le compteur de messages non lus
                self.sidebar.conversations[from_user]["unread"] = 0
            
            # Recharger la liste des conversations
            self.sidebar.load_conversations()
            
            # Notification
            self.statusBar().showMessage(f"Nouveau message de {from_user}", 3000)
            
        except Exception as e:
            print(f"[CHAT] Erreur déchiffrement: {e}")
            import traceback
            traceback.print_exc()
            QMessageBox.warning(self, "Erreur", f"Impossible de déchiffrer le message: {e}")

    def handle_key_exchange(self, message):
        """Gère la réception d'une clé AES chiffrée"""
        from_user = message['from']
        encrypted_key = MessageProtocol.decode_bytes(message['encrypted_key'])
        
        print(f"[KEY_EXCHANGE] Clé AES reçue de {from_user}")
        
        # Vérifier si on a DÉJÀ une session
        if self.key_exchange.has_session(from_user):
            print(f"[KEY_EXCHANGE] Session déjà établie avec {from_user}, clé ignorée")
            return
        
        try:
            # Recevoir et déchiffrer la clé AES
            self.key_exchange.receive_key_exchange(from_user, encrypted_key)
            
            print(f"[KEY_EXCHANGE] Session sécurisée établie avec {from_user}")
            
            # Envoyer les messages en attente
            if hasattr(self, 'pending_messages') and from_user in self.pending_messages:
                pending = self.pending_messages[from_user]
                print(f"[KEY_EXCHANGE] Envoi de {len(pending)} message(s) en attente à {from_user}")
                for msg_text in pending:
                    self.send_chat_message(from_user, msg_text)
                del self.pending_messages[from_user]
            
            self.statusBar().showMessage(f"Session securisee avec {from_user}", 3000)
            
        except Exception as e:
            print(f"[KEY_EXCHANGE] Erreur établissement session: {e}")
            import traceback
            traceback.print_exc()

    def handle_user_online(self, message):
        """Gère la notification d'un utilisateur en ligne"""
        username = message['username']
        print(f" {username} est en ligne")
        
        #  Ajouter ou mettre à jour l'utilisateur
        if username not in self.sidebar.conversations:
            self.sidebar.conversations[username] = {
                "user_id": username,
                "name": username,
                "avatar": username[0].upper(),
                "last_msg": "Nouveau contact",
                "unread": 0,
                "online": True,  #  En ligne
                "messages": []
            }
        else:
            self.sidebar.conversations[username]["online"] = True
            self.sidebar.conversations[username]["last_msg"] = "En ligne"
        
        self.sidebar.load_conversations()
        self.statusBar().showMessage(f" {username} est en ligne", 2000)
    def handle_user_offline(self, message):
        """Gère la notification d'un utilisateur hors ligne"""
        username = message['username']
        print(f" {username} est hors ligne")
        
        if username in self.sidebar.conversations:
            self.sidebar.conversations[username]["online"] = False
            self.sidebar.conversations[username]["last_msg"] = "Hors ligne"
            self.sidebar.load_conversations()
            self.statusBar().showMessage(f" {username} est hors ligne", 2000)
    def handle_user_list(self, message):
        """Gère la réception de la liste des utilisateurs"""
        users = message.get('users', [])
        print(f" Liste utilisateurs mise à jour: {users}")
        
        conversations = {}
        
        #  CORRECTION : Les utilisateurs dans la liste sont juste des noms
        # Par défaut, ils sont OFFLINE sauf s'ils sont déjà dans self.sidebar.conversations
        for username in users:
            if username != self.username:
                if username in self.sidebar.conversations:
                    #  Conserver le statut existant
                    conversations[username] = self.sidebar.conversations[username]
                else:
                    #  Nouveau contact : OFFLINE par défaut
                    conversations[username] = {
                        "user_id": username,
                        "name": username,
                        "avatar": username[0].upper(),
                        "last_msg": "Nouveau contact",
                        "unread": 0,
                        "online": False,  #  OFFLINE par défaut
                        "messages": []
                    }
        
        self.sidebar.update_conversations(conversations)
    def handle_error(self, message):
        """Gère les erreurs du serveur"""
        error_msg = message.get('message', 'Erreur inconnue')
        print(f" Erreur serveur: {error_msg}")
        QMessageBox.warning(self, "Erreur serveur", error_msg)

    def closeEvent(self, event):
        """Appelé à la fermeture de la fenêtre"""
        reply = QMessageBox.question(
            self,
            "Confirmation",
            "Voulez-vous vraiment vous déconnecter ?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            #  Déconnexion propre UNE SEULE FOIS
            if self.client and self.client.is_connected():
                try:
                    print(f" Déconnexion de {self.username}...")
                    self.client.disconnect()
                    self.client = None  #  Empêcher les doubles déconnexions
                except Exception as e:
                    print(f" Erreur lors de la déconnexion : {e}")
            event.accept()
        else:
            event.ignore()

# ============================================================================
# Application principale
# ============================================================================

class MessagingApp(QApplication):
    """Application principale de messagerie sécurisée"""
    
    def __init__(self, argv):
        super().__init__(argv)
        
        # Définir le style
        self.setStyle("Fusion")
        
        # Fenêtres
        self.login_window = None
        self.main_window = None
        
        # Démarrer avec la fenêtre de login
        self.show_login()
    
    def show_login(self):
        """Affiche la fenêtre de connexion"""
        self.login_window = LoginWindow()
        self.login_window.login_successful.connect(self.on_login_successful)
        self.login_window.show()
    
    def on_login_successful(self, username, client, key_exchange, auth_data):
        """Appelé quand la connexion réussit"""
        print(f" Connexion réussie pour {username}, ouverture de la fenêtre principale...")
        
        # Créer la fenêtre principale
        self.main_window = MainWindow(username, client, key_exchange, auth_data)
        self.main_window.show()
        
        # Fermer la fenêtre de login
        self.login_window.close()
        self.login_window = None

# ============================================================================
# Point d'entrée
# ============================================================================

def main():
    """Point d'entrée de l'application"""
    app = MessagingApp(sys.argv)
    
    try:
        sys.exit(app.exec_())
    except Exception as e:
        print(f" Erreur critique: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()