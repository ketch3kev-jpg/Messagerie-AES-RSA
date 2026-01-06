"""
Serveur de messagerie sécurisée avec chiffrement de bout en bout.
Le serveur agit comme un routeur de message :
-Il ne voit jamais les messages en clair
-Il route les messages chiffrés
-Il stocke les clés publiques
- Il gère les messages offline

Architecture :
- Thread principal : accepte les connexions
- Un thread par client : gère la communication
- Stockage JSON simple (pas de vraie base de données)
"""

import socket
import threading
import json
import os
import hashlib
from datetime import datetime

from server.MessageProtocole import MessageProtocol, MessageType

#===================================USER MANAGER=================================
class UserManager:
    """Gestion des utilisateurs (pseudo-base de données)"""

    def __init__(self, filepath='data/users.json'):
        self.filepath = filepath
        self.users = {}
        self.load()
    
    def load(self):
        """Charge les utilisateurs depuis le fichier"""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    self.users = json.load(f)
                print(f"{len(self.users)} utilisateurs chargés")
            except Exception as e:
                print(f"Erreur chargement users.json: {e}")
                self.users = {}
        else:
            print("Aucun fichier users.json, creation d'un nouveau")
            self.users = {}
            os.makedirs(os.path.dirname(self.filepath) or '.', exist_ok=True)
            try:
                self.save()
            except Exception as e:
                print(f"Impossible de créer users.json : {e}")
    
    def save(self):
        """Sauvegarde les utilisateurs dans le fichier"""
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            print(f"Erreur sauvegarde users.json :{e}")
    
    def register(self, username, password, public_key):
        """Enregistre un nouvel utilisateur"""
        if username in self.users:
            return False
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        self.users[username] = {
            'password_hash': password_hash,
            'public_key': public_key,
            'register_at': datetime.now().isoformat()
        }
        self.save()
        print(f"Utilisateur '{username}' enregistré")
        return True
    
    def authenticate(self, username, password):
        """Verifie les credentials"""
        if username not in self.users:
            return False
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return self.users[username]['password_hash'] == password_hash
    
    def get_public_key(self, username):
        """Récupère la clé publique d'un utilisateur"""
        if username not in self.users:
            return None
        return self.users[username]['public_key']
    
    def user_exists(self, username):
        """Vérifie si un utilisateur existe"""
        return username in self.users
    
    def list_users(self):
        """Liste tous les utilisateurs"""
        return list(self.users.keys())

#==================================OFFLINE_MESSAGE=======================================
class OfflineMessageManager:
    """Gestion des messages en attente (pour utilisateurs déconnectés)"""

    def __init__(self, filepath='data/offline_message.json'):
        self.filepath = filepath
        self.messages = {}
        self.load()

    def load(self):
        """Charge les messages offline"""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    self.messages = json.load(f)
                total = sum(len(msgs) for msgs in self.messages.values())
                print(f"{total} messages offline chargés")
            except Exception as e:
                print(f"Erreur chargement offline_messages.json :{e}")
                self.messages = {}
        else:
            self.messages = {}
            os.makedirs(os.path.dirname(self.filepath) or '.', exist_ok=True)
    
    def save(self):
        """Sauvegarde les messages offline"""
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.messages, f, indent=2)
        except Exception as e:
            print(f"Erreur sauvegarde offline_messages.json : {e}")
    
    def add_message(self, to_user, message):
        """Ajouter un message en attente pour un utilisateur"""
        if to_user not in self.messages:
            self.messages[to_user] = []
        message['stored_at'] = datetime.now().isoformat()
        self.messages[to_user].append(message)
        self.save()
        print(f" Message offline stocké pour '{to_user}'")

    def get_messages(self, username):
        """Récupère et supprime les messages d'un utilisateur"""
        if username not in self.messages:
            return []
        messages = self.messages[username]
        del self.messages[username]
        self.save()
        print(f" {len(messages)} message(s) offline récupéré(s) pour '{username}'")
        return messages
    
    def has_messages(self, username):
        """Vérifie si un utilisateur a des messages en attente"""
        return username in self.messages and len(self.messages[username]) > 0

#===================================SERVER=================================

class server:
    """Serveur principal de messagerie"""
    
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False

        self.user_manager = UserManager()
        self.offline_manager = OfflineMessageManager()

        self.clients = {}
        self.clients_lock = threading.Lock()

    def start(self):
        """Lancer le serveur"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)

            self.running = True

            print(f"✓ Serveur démarré sur {self.host}:{self.port}")
        except Exception as e:
            print(f"✗ Erreur démarrage serveur : {e}")
            self.running = False
    
    def accept_connections(self):
        """Accepte les connexions entrantes (boucle principale)"""
        print("En attente de connexions")
        print()
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"🔌 Nouvelle connexion de {address}")

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"✗ Erreur acceptation connexion :{e}")
    
    def handle_client(self, client_socket, address):
        """Gère un client connecté (thread dédié)"""
        username = None
        authenticated = False

        try:
            # Attendre l'authentification
            while not authenticated and self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                message = MessageProtocol.parse(data.decode('utf-8'))
                
                if message['type'] == MessageType.AUTH:
                    username, authenticated = self.handle_auth(client_socket, message)
                elif message['type'] == MessageType.REGISTER:
                    self.handle_register(client_socket, message)
                    client_socket.close()
                    return
                else:
                    error = MessageProtocol.create_error("Authentification requise")
                    client_socket.send(error.encode('utf-8'))

            if not authenticated:
                client_socket.close()
                return
            
            # CORRECTION 1 : Enregistrer l'utilisateur AVANT d'envoyer les listes
            with self.clients_lock:
                self.clients[username] = client_socket
            
            print(f"'{username}' ajouté à la liste des clients connectés")
            print(f"Clients actuels : {list(self.clients.keys())}")

            # CORRECTION 2 : Envoyer la liste COMPLÈTE des utilisateurs enregistrés
            all_users = self.user_manager.list_users()
            all_users_except_me = [u for u in all_users if u != username]
            
            user_list_msg = MessageProtocol.create_user_list(all_users_except_me)
            client_socket.send(user_list_msg.encode('utf-8'))
            print(f"Liste complète envoyée à '{username}' : {all_users_except_me}")
            
            # CORRECTION 3 : Notifier TOUS les autres utilisateurs connectés
            # IMPORTANT : Envoyer USER_ONLINE avant USER_LIST
            self.broadcast_user_status(username, MessageType.USER_ONLINE)

            # Envoyer les messages offline
            self.send_offline_messages(client_socket, username)

            # Boucle de réception des messages
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                message = MessageProtocol.parse(data.decode('utf-8'))
                self.route_message(username, message)

        except Exception as e:
            print(f"Erreur avec client {username or address} : {e}")
            import traceback
            traceback.print_exc()
        finally:
            if username:
                self.disconnect_client(username)
            client_socket.close()


    def broadcast_user_status(self, username, status):
        """
        Notifie tous les clients qu'un utilisateur est online/offline
        """
        if status == MessageType.USER_ONLINE:
            msg = MessageProtocol.create_user_online(username)
            print(f"Broadcast : '{username}' est en ligne")
        else:
            msg = MessageProtocol.create_user_offline(username)
            print(f"Broadcast : '{username}' est hors ligne")

        with self.clients_lock:
            # CORRECTION : Envoyer la notification à TOUS sauf l'utilisateur concerné
            for user, client_socket in self.clients.items():
                if user != username:
                    try:
                        client_socket.send(msg.encode('utf-8'))
                        print(f"  -> Notification envoyée à '{user}'")
                    except Exception as e:
                        print(f"Erreur broadcast à '{user}' : {e}")
            
            # Envoyer la liste mise à jour à TOUS les clients
            all_users = self.user_manager.list_users()
            
            for user, client_socket in self.clients.items():
                users_for_this_client = [u for u in all_users if u != user]
                
                try:
                    user_list_msg = MessageProtocol.create_user_list(users_for_this_client)
                    client_socket.send(user_list_msg.encode('utf-8'))
                    print(f"Liste mise à jour envoyée à '{user}' : {users_for_this_client}")
                except Exception as e:
                    print(f"Erreur envoi user_list à '{user}' : {e}")

    def handle_register(self, client_socket, message):
        """Gère l'inscription d'un nouvel utilisateur"""
        username = message.get('username')
        password = message.get('password')
        public_key = message.get('public_key')
        
        print(f" Inscription : username='{username}', has_password={bool(password)}, has_key={bool(public_key)}")
        
        # Validation
        if not username or not password or not public_key:
            response = MessageProtocol.create_register_fail("Données manquantes")
            client_socket.send(response.encode('utf-8'))
            print(f"✗ Inscription échouée : données manquantes")
            return
        
        # Vérifier le format de la clé publique
        if not isinstance(public_key, list) or len(public_key) != 2:
            response = MessageProtocol.create_register_fail("Format de clé publique invalide")
            client_socket.send(response.encode('utf-8'))
            print(f"✗ Inscription échouée : clé invalide")
            return
        
        # Tenter l'inscription
        try:
            success = self.user_manager.register(username, password, public_key)
            
            if success:
                response = MessageProtocol.create_register_ok(username)
                print(f"✓ Utilisateur '{username}' enregistré avec succès")
            else:
                response = MessageProtocol.create_register_fail("Nom d'utilisateur déjà pris")
                print(f"✗ Échec enregistrement '{username}' (existe déjà)")
        except Exception as e:
            response = MessageProtocol.create_register_fail(f"Erreur serveur : {e}")
            print(f"✗ Erreur lors de l'inscription de '{username}' : {e}")
        
        client_socket.send(response.encode('utf-8'))

    def handle_auth(self, client_socket, message):
        """Gère l'authentification"""
        username = message['username']
        password = message['password']

        if self.user_manager.authenticate(username, password):
            # Authentification réussie
            print(f"✓ '{username}' authentifié")
            
            #  CORRECTION 4 : Envoyer TOUS les utilisateurs enregistrés (pas seulement les connectés)
            all_users = self.user_manager.list_users()
            all_users_except_me = [u for u in all_users if u != username]
            
            print(f" Envoi de la liste à '{username}' : {all_users_except_me}")
            
            response = MessageProtocol.create_auth_ok(username, all_users_except_me)
            client_socket.send(response.encode('utf-8'))

            return username, True
        else:
            # Authentification échouée
            print(f"✗ Échec authentification pour '{username}'")
            response = MessageProtocol.create_auth_fail(
                "Nom d'utilisateur ou mot de passe incorrect"
            )
            client_socket.send(response.encode('utf-8'))
            
            return None, False
    
    def route_message(self, from_user, message):
        """Route un message vers le bon destinataire"""
        msg_type = message.get('type')
        try:
            if msg_type == MessageType.KEY_REQUEST:
                self.handle_key_request(from_user, message)
            elif msg_type == MessageType.KEY_EXCHANGE:
                self.handle_key_exchange(from_user, message)
            elif msg_type == MessageType.CHAT:
                self.handle_chat_message(from_user, message)
            elif msg_type == MessageType.DISCONNECT:
                self.disconnect_client(from_user)
            else:
                print(f"⚠ Type de message non géré :{msg_type}")
        except Exception as e:
            print(f"✗ Erreur routage message de '{from_user}' : {e}")

    def handle_key_request(self, from_user, message):
        """Gère une demande de clé publique"""
        to_user = message['to']

        # Récupère la clé publique
        public_key = self.user_manager.get_public_key(to_user)

        if public_key:
            # Envoyer la clé au demandeur
            response = MessageProtocol.create_key_reply(to_user, tuple(public_key))
            
            with self.clients_lock:
                if from_user in self.clients:
                    self.clients[from_user].send(response.encode('utf-8'))
                    print(f" Clé publique de '{to_user}' envoyée à '{from_user}'")
        else:
            # Utilisateur n'existe pas
            error = MessageProtocol.create_error(f"Utilisateur '{to_user}' introuvable")
            with self.clients_lock:
                if from_user in self.clients:
                    self.clients[from_user].send(error.encode('utf-8'))
    
    def handle_key_exchange(self, from_user, message):
        """Gère l'échange de clé AES chiffrée"""
        to_user = message['to']

        # Transférer le message au destinataire
        msg_str = MessageProtocol.create_key_exchange(
            from_user,
            to_user,
            MessageProtocol.decode_bytes(message['encrypted_key'])
        )
        
        with self.clients_lock:
            if to_user in self.clients:
                # Destinataire en ligne
                self.clients[to_user].send(msg_str.encode('utf-8'))
                print(f" Clé AES transférée de '{from_user}' à '{to_user}'")
            else:
                # Destinataire hors ligne, stocker
                self.offline_manager.add_message(to_user, message)

    def handle_chat_message(self, from_user, message):
        """Gère un message chiffré"""
        to_user = message['to']

        # Reconstruire le message
        msg_str = MessageProtocol.create_chat_message(
            from_user,
            to_user,
            MessageProtocol.decode_bytes(message['ciphertext']),
            MessageProtocol.decode_bytes(message['nonce']),
            MessageProtocol.decode_bytes(message['tag'])
        )
        
        with self.clients_lock:
            if to_user in self.clients:
                # Destinataire en ligne
                self.clients[to_user].send(msg_str.encode('utf-8'))
                print(f"✓ Message de '{from_user}' → '{to_user}'")
            else:
                # Destinataire hors ligne, stocker
                self.offline_manager.add_message(to_user, message)
                print(f" Message de '{from_user}' → '{to_user}' (offline)")
    
    def send_offline_messages(self, client_socket, username):
        """Envoie les messages en attente à un utilisateur qui se connecte"""
        messages = self.offline_manager.get_messages(username)
        
        if not messages:
            return
        
        print(f" Envoi de {len(messages)} message(s) offline à '{username}'")
        
        for message in messages:
            msg_type = message['type']
            
            if msg_type == MessageType.KEY_EXCHANGE:
                msg_str = MessageProtocol.create_key_exchange(
                    message['from'],
                    message['to'],
                    MessageProtocol.decode_bytes(message['encrypted_key'])
                )
            
            elif msg_type == MessageType.CHAT:
                msg_str = MessageProtocol.create_chat_message(
                    message['from'],
                    message['to'],
                    MessageProtocol.decode_bytes(message['ciphertext']),
                    MessageProtocol.decode_bytes(message['nonce']),
                    MessageProtocol.decode_bytes(message['tag'])
                )
            
            else:
                continue
            
            try:
                client_socket.send(msg_str.encode('utf-8'))
            except Exception as e:
                print(f"✗ Erreur envoi message offline : {e}")
    
    def disconnect_client(self, username):
        """Déconnexion propre d'un client"""
        with self.clients_lock:
            if username in self.clients:
                del self.clients[username]
                print(f"✓ '{username}' déconnecté")
        
        # Notifier les autres utilisateurs
        self.broadcast_user_status(username, MessageType.USER_OFFLINE)
    
    def stop(self):
        """Arrête le serveur proprement"""
        print("\n Arrêt du serveur...")
        self.running = False
        
        # Fermer toutes les connexions clients
        with self.clients_lock:
            for username, client_socket in self.clients.items():
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
        
        # Fermer le socket serveur
        if self.server_socket:
            self.server_socket.close()
        
        print(" Serveur arrêté")


# ══════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import signal
    import sys
    
    print("=" * 60)
    print("    SERVEUR DE MESSAGERIE SÉCURISÉE")
    print("=" * 60)
    print()
    
    # Créer le serveur
    serveur = server(host='0.0.0.0', port=5555)
    
    # Gérer Ctrl+C proprement
    def signal_handler(sig, frame):
        print("\n\n⚠ Signal d'interruption reçu (Ctrl+C)")
        serveur.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Démarrer le serveur
    try:
        serveur.start()
        
        print(" Appuyez sur Ctrl+C pour arrêter le serveur")
        print()
        
        # LIGNE CRUCIALE : Lancer la boucle d'acceptation
        serveur.accept_connections()
        
    except KeyboardInterrupt:
        print("\n⚠ Interruption clavier détectée")
        serveur.stop()
    except Exception as e:
        print(f"\n✗ Erreur fatale : {e}")
        import traceback
        traceback.print_exc()
        serveur.stop()
        sys.exit(1)