import json
import base64
from enum import Enum

class MessageType:
    """Énumération des types de messages du protocole"""
    
    # Authentification
    AUTH = "auth"
    AUTH_OK = "auth_ok"
    AUTH_FAIL = "auth_fail"
    REGISTER = "register"
    REGISTER_OK = "register_ok"
    REGISTER_FAIL = "register_fail"
    
    # Gestion des clés
    KEY_REQUEST = "key_request"
    KEY_REPLY = "key_reply"
    KEY_EXCHANGE = "key_exchange"
    KEY_EXCHANGE_ACK = "key_exchange_ack"
    
    # Messages
    CHAT = "chat"
    CHAT_ACK = "chat_ack"
    
    # Gestion des utilisateurs
    USER_LIST = "user_list"
    USER_ONLINE = "user_online"
    USER_OFFLINE = "user_offline"
    
    # Erreurs
    ERROR = "error"
    
    # Divers
    DISCONNECT = "disconnect"
    PING = "ping"
    PONG = "pong"

class MessageProtocol:
    """creation et parsing des messages JSON du protocole 
    Format générale:
    {"type":"...",...autreschamps...}\n
    """
    @staticmethod
    def create_auth(username,password):
        """
        Crée un message d'authentification
        """
        return json.dumps({
                'type':MessageType.AUTH,
                'username':username,
                'password':password
            }
        )+ '\n'
    @staticmethod
    def create_auth_ok(username,userlist):
        """
        Crée une reponse d'authentification réussi
        """
        return json.dumps( {
                 'type':MessageType.AUTH_OK,
                'username':username,
                # Provide both 'user_list' (used by the GUI/client) and
                # 'userlist' (historical) for backward compatibility.
                'user_list': userlist,
            }
        )+ '\n'
    @staticmethod
    def create_auth_fail(reason):
        """
        Crée une reponse d'authentication échouée
        """
        return json.dumps( {
                 'type':MessageType.AUTH_FAIL,
                'reason':reason
            }
        )+ '\n'
    @staticmethod
    def create_register(username,password,public_key):
        """
        Crée un message d'inscription
        """
        n,e=public_key
        return json.dumps({
            'type': MessageType.REGISTER,
            'username': username,
            'password': password,
            'public_key': [n, e]
        }) + '\n'
    @staticmethod
    def create_register_ok(username):
        """
        Inscription réussi
        """
        return json.dumps( {
                 'type':MessageType.REGISTER_OK,
                'username':username
            }
        )+ '\n'
    @staticmethod
    def create_register_fail(reason):
        """
        Inscription échouée
        """
        return json.dumps( {
                 'type':MessageType.REGISTER_FAIL,
                'reason':reason
            }
        )+ '\n'
    
    #=========================GESTION DES CLÉS=====================================

    @staticmethod
    def create_key_request(from_user,to_user):
        """
        Crée une demande de clés publique
        """
        return json.dumps(
            {
                'type':MessageType.KEY_REQUEST,
                'from':from_user,
                'to':to_user
            }
        )+ '\n'
    @staticmethod
    def create_key_reply(username,public_key):
        """
        Crée une reponse avec la clé publique
        """
        return json.dumps(
            {
                'type':MessageType.KEY_REPLY,
                'username':username,
                'public_key':public_key
            }
        )+ '\n'
    @staticmethod
    def create_key_exchange(from_user,to_user,encrypted_key):
        """
        Crée un message déchange de clé AES chiffrée
        """
        # Accepter bytes ou listes/tuples d'octets (par ex. [int, ...])
        if isinstance(encrypted_key, (list, tuple)):
            try:
                encrypted_key = bytes(encrypted_key)
            except Exception:
                raise ValueError("encrypted_key invalide : attendu bytes ou sequence d'octets")
        if not isinstance(encrypted_key, (bytes, bytearray)):
            raise ValueError("encrypted_key must be bytes-like")

        return json.dumps(
            {
                'type':MessageType.KEY_EXCHANGE,
                'from':from_user,
                'to':to_user,
                'encrypted_key':base64.b64encode(encrypted_key).decode('UTF-8')
            }
        )+ '\n'
    @staticmethod
    def create_key_ack(from_user,to_user):
        """
        Accusé de reception de l'échange de clés
        """
        return json.dumps(
            {
                'type':MessageType.KEY_EXCHANGE_ACK,
                'from':from_user,
                'to':to_user
            }
        )+ '\n'
    #===========================MÉSSAGES CHIFFRÉS=========================================
    @staticmethod
    def create_chat_message(from_user,to_user,ciphertext,nonce,tag):
        """
        Crée un message chiffré
        """
        # Accepter bytes ou listes/tuples d'octets
        def _ensure_bytes(x, name):
            if isinstance(x, (list, tuple)):
                try:
                    return bytes(x)
                except Exception:
                    raise ValueError(f"{name} invalide : attendu bytes ou sequence d'octets")
            if isinstance(x, (bytes, bytearray)):
                return bytes(x)
            raise ValueError(f"{name} must be bytes-like")

        ciphertext = _ensure_bytes(ciphertext, 'ciphertext')
        nonce = _ensure_bytes(nonce, 'nonce')
        tag = _ensure_bytes(tag, 'tag')

        return json.dumps({
            'type': MessageType.CHAT,
            'from':from_user,
            'to':to_user,
            'ciphertext':base64.b64encode(ciphertext).decode('utf-8'),
            'nonce':base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        })+ '\n'
    @staticmethod
    def create_chat_ack(from_user, to_user, message_id=None):
        """Accusé de réception d'un message"""
        msg = {
            'type': MessageType.CHAT_ACK,
            'from': from_user,
            'to': to_user
        }
        if message_id:
            msg['message_id'] = message_id
        return json.dumps(msg) + '\n'
    #============================GESTION DES UTILISATEURS========================
    @staticmethod
    def create_user_list(users):
        """ 
        Crée un message avec la liste des utilisateurs
        """
        return json.dumps({
            'type':MessageType.USER_LIST,
            'users':users
        })+ '\n'
    @staticmethod
    def create_user_online(username):
        """
        Notification qu'un utilisateur est en ligne
        """
        return json.dumps({
            'type': MessageType.USER_ONLINE,
            'username': username
        }) + '\n'
    
    @staticmethod
    def create_user_offline(username):
        """
        Notification qu'un utilisateur est hors ligne

        """
        return json.dumps({
            'type': MessageType.USER_OFFLINE,
            'username': username
        }) + '\n'
    @staticmethod
    def create_error(message, error_code=None):
        """
        Crée un message d'erreur

        """
        msg = {
            'type': MessageType.ERROR,
            'message': message
        }
        if error_code:
            msg['error_code'] = error_code
        return json.dumps(msg) + '\n'
    
    @staticmethod
    def create_disconnect(username):
        """Message de déconnexion"""
        return json.dumps({
            'type': MessageType.DISCONNECT,
            'username': username
        }) + '\n'
    
    @staticmethod
    def create_ping():
        """Message ping (keep-alive)"""
        return json.dumps({'type': MessageType.PING}) + '\n'
    
    @staticmethod
    def create_pong():
        """Message pong (réponse au ping)"""
        return json.dumps({'type': MessageType.PONG}) + '\n'
    @staticmethod
    def create_user_list_with_status(users_status):
        """users_status = [{'username': 'alice', 'online': True}, ...]"""
        return json.dumps({
            'type': MessageType.USER_LIST,
            'users': users_status
        }) + '\n'
    #=========================PARSING===========================
    @staticmethod
    def parse(json_line) :
        """
        Parse une ligne JSON recue
        """
        json_line=json_line.strip()
        if not json_line :
            raise ValueError("Ligne vide")
        try :
            message=json.loads(json_line)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON invalide :{e}")

        if 'type' not in message :
            raise ValueError("Message sanns champs 'type' ")
        return message    
    # ═══════════════════════════════════════════════════════════
    # HELPERS : CONVERSION BYTES ↔ BASE64
    # ═══════════════════════════════════════════════════════════
    
    @staticmethod
    def encode_bytes(data):
        """
        Convertit des bytes en string base64
        
        Args:
            data: Données binaires
            
        Returns:
            str: String base64
            
        Example:
            >>> MessageProtocol.encode_bytes(b'hello')
            'aGVsbG8='
        """
        if not isinstance(data, bytes):
            raise ValueError("Les données doivent être de type bytes")
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode_bytes(base64_str):
        """
        Convertit une string base64 en bytes
        
        Args:
            base64_str: String base64
            
        Returns:
            bytes: Données binaires
            
        Raises:
            ValueError: Si le base64 est invalide
            
        Example:
            >>> MessageProtocol.decode_bytes('aGVsbG8=')
            b'hello'
        """
        if not isinstance(base64_str, str):
            raise ValueError("L'entrée doit être une string")
        
        try:
            return base64.b64decode(base64_str)
        except Exception as e:
            raise ValueError(f"Base64 invalide : {e}")
    
    # ═══════════════════════════════════════════════════════════
    # VALIDATION
    # ═══════════════════════════════════════════════════════════
    
    @staticmethod
    def validate_message(message):
        """
        Valide qu'un message a la structure correcte
        
        Args:
            message: Dictionnaire du message
            
        Returns:
            bool: True si valide
            
        Raises:
            ValueError: Si le message est invalide
        """
        if not isinstance(message, dict):
            raise ValueError("Le message doit être un dictionnaire")
        
        if 'type' not in message:
            raise ValueError("Champ 'type' manquant")
        
        msg_type = message['type']
        
        # Validation selon le type
        if msg_type == MessageType.AUTH:
            required = ['username', 'password']
        elif msg_type == MessageType.KEY_REQUEST:
            required = ['from', 'to']
        elif msg_type == MessageType.KEY_REPLY:
            required = ['username', 'public_key']
        elif msg_type == MessageType.KEY_EXCHANGE:
            required = ['from', 'to', 'encrypted_key']
        elif msg_type == MessageType.CHAT:
            required = ['from', 'to', 'ciphertext', 'nonce', 'tag']
        else:
            # Types qui n'ont pas de champs requis spécifiques
            return True
        
        # Vérifier que tous les champs requis sont présents
        for field in required:
            if field not in message:
                raise ValueError(f"Champ '{field}' manquant pour type '{msg_type}'")
        
        return True
    @staticmethod
    def create_user_list(users):
        """ 
        Crée un message avec la liste des utilisateurs
        """
        return json.dumps({
            'type': MessageType.USER_LIST,
            'users': users
        }) + '\n'


# ═══════════════════════════════════════════════════════════════
# TESTS ET EXEMPLES
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("    TEST DU MESSAGE PROTOCOL")
    print("=" * 60)
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 1 : Messages d'authentification
    # ═══════════════════════════════════════════════════════════
    print("TEST 1 : Messages d'authentification")
    print("-" * 60)
    
    auth_msg = MessageProtocol.create_auth("alice", "password123")
    print(f"Auth : {auth_msg.strip()}")
    
    parsed = MessageProtocol.parse(auth_msg)
    print(f"Parsé : {parsed}")
    
    MessageProtocol.validate_message(parsed)
    print("✓ Validation OK")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 2 : Échange de clés
    # ═══════════════════════════════════════════════════════════
    print("TEST 2 : Échange de clés")
    print("-" * 60)
    
    # Demande de clé
    key_req = MessageProtocol.create_key_request("alice", "bob")
    print(f"Key request : {key_req.strip()}")
    
    # Réponse avec clé publique
    public_key = (123456789, 65537)
    key_reply = MessageProtocol.create_key_reply("bob", public_key)
    print(f"Key reply : {key_reply.strip()}")
    
    # Vérifier qu'on peut retrouver la clé
    parsed_reply = MessageProtocol.parse(key_reply)
    retrieved_key = tuple(parsed_reply['public_key'])
    assert retrieved_key == public_key
    print("✓ Clé publique correctement encodée/décodée")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 3 : Message chiffré
    # ═══════════════════════════════════════════════════════════
    print("TEST 3 : Message chiffré")
    print("-" * 60)
    
    # Simuler des données chiffrées
    ciphertext = b'\x8f\x2a\x91\xc3\x45\x67\x89\xab' * 5
    nonce = b'\x3d\x7f\x92\x8a\xb1\xc4\xe5\xf6\x12\x34\x56\x78'
    tag = b'\xa1\xb2\xc3\xd4\xe5\xf6\x07\x18\x29\x3a\x4b\x5c\x6d\x7e\x8f\x90'
    
    chat_msg = MessageProtocol.create_chat_message(
        "alice", "bob",
        ciphertext, nonce, tag
    )
    print(f"Chat message : {chat_msg[:80]}...")
    
    # Parser et reconstruire
    parsed_chat = MessageProtocol.parse(chat_msg)
    
    recovered_ciphertext = MessageProtocol.decode_bytes(parsed_chat['ciphertext'])
    recovered_nonce = MessageProtocol.decode_bytes(parsed_chat['nonce'])
    recovered_tag = MessageProtocol.decode_bytes(parsed_chat['tag'])
    
    assert recovered_ciphertext == ciphertext
    assert recovered_nonce == nonce
    assert recovered_tag == tag
    print("✓ Données binaires correctement encodées/décodées")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 4 : Notifications utilisateurs
    # ═══════════════════════════════════════════════════════════
    print("TEST 4 : Notifications utilisateurs")
    print("-" * 60)
    
    user_list = MessageProtocol.create_user_list(["alice", "bob", "carol"])
    print(f"User list : {user_list.strip()}")
    
    user_online = MessageProtocol.create_user_online("bob")
    print(f"User online : {user_online.strip()}")
    
    user_offline = MessageProtocol.create_user_offline("carol")
    print(f"User offline : {user_offline.strip()}")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 5 : Erreurs
    # ═══════════════════════════════════════════════════════════
    print("TEST 5 : Gestion d'erreurs")
    print("-" * 60)
    
    error_msg = MessageProtocol.create_error("Utilisateur introuvable", 404)
    print(f"Error : {error_msg.strip()}")
    
    # Test parsing JSON invalide
    try:
        MessageProtocol.parse("invalid json{{{")
        print("✗ ERREUR : devrait lever une exception")
    except ValueError as e:
        print(f"✓ Exception levée correctement : {e}")
    
    # Test message sans type
    try:
        MessageProtocol.validate_message({'username': 'alice'})
        print("✗ ERREUR : devrait lever une exception")
    except ValueError as e:
        print(f"✓ Validation échoue correctement : {e}")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 6 : Workflow complet Alice → Bob
    # ═══════════════════════════════════════════════════════════
    print("TEST 6 : Workflow complet simulé")
    print("-" * 60)
    
    print("1. Alice s'authentifie")
    msg1 = MessageProtocol.create_auth("alice", "pass123")
    print(f"   → {msg1.strip()}")
    
    print("2. Serveur répond OK avec liste users")
    msg2 = MessageProtocol.create_auth_ok("alice", ["bob", "carol"])
    print(f"   → {msg2.strip()}")
    
    print("3. Alice demande la clé de Bob")
    msg3 = MessageProtocol.create_key_request("alice", "bob")
    print(f"   → {msg3.strip()}")
    
    print("4. Serveur répond avec clé publique de Bob")
    msg4 = MessageProtocol.create_key_reply("bob", (987654321, 65537))
    print(f"   → {msg4.strip()}")
    
    print("5. Alice envoie sa clé AES chiffrée à Bob")
    encrypted_key = b'\xaa\xbb\xcc\xdd' * 64  # Simuler clé RSA chiffrée
    msg5 = MessageProtocol.create_key_exchange("alice", "bob", encrypted_key)
    print(f"   → {msg5[:80]}...")
    
    print("6. Alice envoie un message chiffré à Bob")
    msg6 = MessageProtocol.create_chat_message(
        "alice", "bob",
        b'encrypted_message',
        b'nonce_123456',
        b'tag_1234567890ab'
    )
    print(f"   → {msg6[:80]}...")
    
    print("\n✓ Workflow complet testé")
    print()
    
    print("=" * 60)
    print("    TOUS LES TESTS RÉUSSIS !")
    print("=" * 60)
    print()
    print("Le protocole MessageProtocol est prêt à l'emploi !")
    print()
    print("UTILISATION :")
    print("1. Créer des messages avec create_*() côté émetteur")
    print("2. Envoyer via socket")
    print("3. Parser avec parse() côté récepteur")
    print("4. Valider avec validate_message() (optionnel)")
    print("5. Traiter selon le type de message")

    
    

    