""" Client Socket pour la messagerie sécurisée 

Gère la connexion TCP avec le serveir et la communication bidirectionnelle

Architecture :
- Thread principal : envoi des messages
- Thread d'écoute : réception des messages du serveur
- Callback pour notifier l'interface utilisateur

Utilisation :
    client = ClientSocket()
    client.set_callback(on_message_received)
    client.connect('localhost', 5555, 'alice', 'password')
    client.send({'type': 'chat', ...})
"""
import socket
import threading
import queue
from .MessageProtocole import MessageProtocol,MessageType

class ClientSocket :
    """
    Gère la connexion socket avec le serveur

    Responsabilités :
    -connexion au serveur
    -Envoi de messages
    -Reception de messages (thread separé)
    -Notification de l'interface via callback

    """
    def  __init__(self):
        self.socket=None
        self.connected=False
        self.username= None
        
        #Thread d'écoute
        self.listen_thread=None
        self.running=False

        #Callback pour notifier l'interface
        self.callback=None

        #File d'attente pour message à envoyer
        self.send_queue=queue.Queue()
    def set_callback(self,callback_function):
        """ Definit la fonction appelée à reception de message"""
        self.callback=callback_function
    def connect(self, host, port, username, password):
        """Connexion au serveur et authentification"""
        
        try:
            # Créer le socket TCP
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(None)
            self.socket.connect((host, port))
            print(f"Connecté au serveur {host}:{port}")

            # Envoyer message d'authentification
            auth_message = MessageProtocol.create_auth(username, password)
            self.socket.send(auth_message.encode('utf-8'))

            #  CORRECTION : Lire ligne par ligne au lieu de tout d'un coup
            buffer = ""
            auth_response = None
            
            # Lire la première ligne (AUTH_OK ou AUTH_FAIL)
            while '\n' not in buffer:
                data = self.socket.recv(4096)
                if not data:
                    raise ConnectionError("Connexion fermée par le serveur")
                buffer += data.decode('utf-8')
            
            # Extraire la première ligne
            line, buffer = buffer.split('\n', 1)
            auth_response = MessageProtocol.parse(line)

            if auth_response['type'] == MessageType.AUTH_OK:
                # Authentification réussie
                self.connected = True
                self.username = username
                self.running = True
                print(f"Authentifié en tant que '{username}'")
                
                # Lancer le thread d'écoute AVEC le buffer restant
                self.listen_thread = threading.Thread(
                    target=self._listen_with_buffer,
                    args=(buffer,),
                    daemon=True
                )
                self.listen_thread.start()

                return auth_response
                
            elif auth_response['type'] == MessageType.AUTH_FAIL:
                # Authentification échouée
                self.socket.close()
                raise ValueError(
                    f"Authentification échouée : {auth_response.get('reason', 'Erreur inconnue')}"
                )
            else:
                # Réponse inattendue
                self.socket.close()
                raise ValueError(f"Réponse inattendue du serveur : {auth_response['type']}")

        except socket.error as e:
            raise ConnectionError(f"Impossible de se connecter au serveur : {e}")
        except Exception as e:
            if self.socket:
                self.socket.close()
            raise

    def register(self, host, port, username, password, public_key):
        """Inscription d'un nouvel utilisateur"""
        try:
            # Créer une connexion temporaire
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect((host, port))

            # Envoyer demande d'inscription
            register_msg = MessageProtocol.create_register(username, password, public_key)
            temp_socket.send(register_msg.encode('utf-8'))

            # Attendre la réponse
            response = temp_socket.recv(4096).decode('utf-8')
            register_response = MessageProtocol.parse(response)

            temp_socket.close()
            
            if register_response['type'] == MessageType.REGISTER_OK:
                print(f" Inscription réussie pour '{username}'")
                return True
            elif register_response['type'] == MessageType.REGISTER_FAIL:
                reason = register_response.get('reason', 'Erreur inconnue')
                raise ValueError(f"Inscription échouée : {reason}")
            else:
                raise ValueError(f"Réponse inattendue : {register_response['type']}")
        
        except socket.error as e:
            raise ConnectionError(f"Impossible de se connecter au serveur : {e}")
        except Exception as e:
            raise Exception(f"Erreur lors de l'inscription : {e}")

    def send(self,message_dict):        
        """ Envoi un message au serveur """
        if not self.connected :
            raise ConnectionError("Pas connecté au serveur")
        try :
            #Convertir le dictionnaire en json et ajouter \n
            import json
            json_str=json.dumps(message_dict)+ '\n'

            #Envoyer
            self.socket.send(json_str.encode('utf-8'))
        except Exception as e :
            print(f"Erreur de connexion : {e}")
            self.connected=False
            raise
    def send_key_request(self,to_user):
        """ Demande la clé publique d'un utilisteur """
        # Utiliser le helper du protocole pour construire le message
        if not self.connected:
            raise ConnectionError("Pas connecté au serveur")
        msg = MessageProtocol.create_key_request(self.username, to_user)
        self.socket.send(msg.encode('utf-8'))
        print(f"Demande de clé publique envoyée à '{to_user}'")

    def send_chat_message(self,to_user,ciphertext,nonce,tag)   : 
        """ Envoie un message chiffré """
        msg= MessageProtocol.create_chat_message(self.username,to_user,ciphertext,nonce,tag)
        self.socket.send(msg.encode('utf-8'))
        print(f" Message envoyé à '{to_user}' ")

    def send_key_exchange(self, to_user, encrypted_key):
        """Envoie une clé AES chiffrée"""
        msg = MessageProtocol.create_key_exchange(self.username, to_user, encrypted_key)
        self.socket.send(msg.encode('utf-8'))
        print(f"✓ Clé AES envoyée à '{to_user}'")

    def _listen_with_buffer(self, initial_buffer=""):
        """Thread d'écoute avec buffer initial (pour éviter de perdre les messages déjà reçus)"""
        print(" Thread d'écoute démarré")

        buffer = initial_buffer  # Commence avec le buffer de connexion

        while self.running and self.connected:
            try:
                # Recevoir des données
                data = self.socket.recv(4096)

                if not data:
                    # Connexion fermée par le serveur
                    print(" Connexion fermée par le serveur")
                    self.connected = False
                    break
                
                buffer += data.decode('utf-8')

                # Traiter toutes les lignes complètes (terminées par \n)
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)

                    if not line.strip():
                        continue
                    
                    try:
                        # Parser le message
                        message = MessageProtocol.parse(line)

                        # Log selon type
                        self._log_received_message(message)
                        
                        # Appeler le callback si défini
                        if self.callback:
                            self.callback(message)

                    except Exception as e:
                        print(f" Erreur parsing message : {e}")
                        print(f"    Ligne problématique : {line[:100]}")

            except socket.timeout:
                # Ignore timeout and continue listening
                continue
            except Exception as e:
                if self.running:
                    print(f" Erreur réception : {e}")
                    import traceback
                    traceback.print_exc()
                    self.connected = False
                break
        
        print(" Thread d'écoute terminé")
    def _listen(self):
        """Thread d'écoute des messages du serveur (version sans buffer initial)"""
        self._listen_with_buffer("")

    def _log_received_message(self, message):
        """ Log les messages recus (pour debug)"""
        msg_type = message.get('type', 'unknown')
        
        if msg_type == MessageType.CHAT:
            print(f"← Message de '{message.get('from', '?')}'")
        
        elif msg_type == MessageType.KEY_REPLY:
            print(f"← Clé publique de '{message.get('username', '?')}' reçue")
        
        elif msg_type == MessageType.KEY_EXCHANGE:
            print(f"← Clé AES de '{message.get('from', '?')}' reçue")
        
        elif msg_type == MessageType.USER_ONLINE:
            print(f"← '{message.get('username', '?')}' est en ligne")
        
        elif msg_type == MessageType.USER_OFFLINE:
            print(f"← '{message.get('username', '?')}' s'est déconnecté")
        
        elif msg_type == MessageType.USER_LIST:
            users = message.get('users', [])
            print(f"← Liste utilisateurs reçue : {users}")
        
        elif msg_type == MessageType.ERROR:
            print(f"← Erreur serveur : {message.get('message', '?')}")
        
        else:
            print(f"← Message reçu : {msg_type}")    

    def disconnect(self):
        """Ferme proprement la connexion au serveur."""
        # Arrêter la boucle d'écoute
        self.running = False

        # Tenter d'envoyer un message de déconnexion
        try:
            if self.connected and self.socket:
                msg = MessageProtocol.create_disconnect(self.username or "")
                self.socket.send(msg.encode('utf-8'))
        except Exception:
            # Ignorer les erreurs lors de l'envoi du disconnect
            pass

        # Fermer la socket
        try:
            if self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self.socket.close()
        except Exception:
            pass

        self.connected = False

        # Joindre le thread d'écoute si nécessaire
        try:
            if self.listen_thread and self.listen_thread.is_alive():
                self.listen_thread.join(timeout=1)
        except Exception:
            pass

        print("Déconnecté du serveur")
    def is_connected(self):
        """Vérifie si le client est connecté"""
        return self.connected
    
    def get_username(self):
        """Retourne le nom d'utilisateur"""
        return self.username


# ═══════════════════════════════════════════════════════════════
# EXEMPLE D'UTILISATION EN LIGNE DE COMMANDE
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    
    print("=" * 60)
    print("    CLIENT DE MESSAGERIE - TEST EN LIGNE DE COMMANDE")
    print("=" * 60)
    print()
    
    # Callback pour afficher les messages reçus
    def on_message_received(message):
        msg_type = message.get('type')
        
        if msg_type == MessageType.CHAT:
            print(f"\n Message de {message['from']} :")
            print(f"   (chiffré, besoin de KeyExchange pour déchiffrer)")
            print()
        
        elif msg_type == MessageType.USER_ONLINE:
            print(f"\n {message['username']} est maintenant en ligne")
            print()
        
        elif msg_type == MessageType.USER_OFFLINE:
            print(f"\n {message['username']} s'est déconnecté")
            print()
        
        elif msg_type == MessageType.KEY_REPLY:
            print(f"\n Clé publique de {message['username']} reçue")
            print(f"   n = {str(message['public_key'][0])[:50]}...")
            print(f"   e = {message['public_key'][1]}")
            print()
    
    # Créer le client
    client = ClientSocket()
    client.set_callback(on_message_received)
    
    # Demander les informations de connexion
    host = input("Adresse du serveur [localhost] : ").strip() or "localhost"
    port = input("Port [5555] : ").strip() or "5555"
    port = int(port)
    
    print()
    print("1. Se connecter")
    print("2. S'inscrire")
    choice = input("Choix : ").strip()
    
    username = input("Nom d'utilisateur : ").strip()
    password = input("Mot de passe : ").strip()
    
    try:
        if choice == "2":
            # Inscription
            print("\nInscription...")
            print("Génération de clés RSA (peut prendre quelques secondes)...")
            
            from crypto.rsa_manager import RSAManager
            public_key, private_key = RSAManager.generate_keypair()
            
            client.register(host, port, username, password, public_key)
            print("\n✓ Inscription réussie ! Vous pouvez maintenant vous connecter.")
            sys.exit(0)
        
        else:
            # Connexion
            print("\nConnexion...")
            auth_data = client.connect(host, port, username, password)
            
            print(f"\n✓ Connecté en tant que '{username}'")
            print(f"Utilisateurs en ligne : {auth_data.get('user_list', [])}")
            print()
            print("Commandes disponibles :")
            print("  /list          - Liste des utilisateurs")
            print("  /key <user>    - Demander clé publique d'un utilisateur")
            print("  /quit          - Se déconnecter")
            print()
            
            # Boucle de commandes
            while client.is_connected():
                try:
                    cmd = input(f"{username}> ").strip()
                    
                    if not cmd:
                        continue
                    
                    if cmd == "/quit":
                        break
                    
                    elif cmd == "/list":
                        client.send({'type': MessageType.USER_LIST})
                    
                    elif cmd.startswith("/key "):
                        target_user = cmd[5:].strip()
                        client.send_key_request(target_user)
                    
                    else:
                        print("Commande inconnue. Utilisez /quit pour quitter.")
                
                except KeyboardInterrupt:
                    print("\n")
                    break
                except EOFError:
                    break
            
            # Déconnexion
            client.disconnect()
    
    except ConnectionError as e:
        print(f"\n✗ Erreur de connexion : {e}")
    except ValueError as e:
        print(f"\n✗ Erreur : {e}")
    except Exception as e:
        print(f"\n✗ Erreur inattendue : {e}")
        import traceback
        traceback.print_exc()
    
    print("\nAu revoir !")
