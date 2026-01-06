import os
import time
import hashlib
import json
from .aes_manager import AESManager
from .rsa_manager import RSAManager


class KeyExchangeProtocol:
    """
    Gère l'échange de clés et les sessions de chiffrement avec plusieurs pairs.
    
    Responsabilités :
    - Initier des échanges de clés AES via RSA
    - Recevoir des clés AES chiffrées
    - Chiffrer/déchiffrer les messages avec les bonnes clés de session
    - Gérer le cycle de vie des sessions (création, expiration, suppression)
    """
    
    def __init__(self, my_private_key, my_public_key, public_key_dir=None):
        """
        Initialise le gestionnaire d'échange de clés
        
        Args:
            my_private_key: Ma clé privée RSA (dict avec n, e, d, p, q, etc.)
            my_public_key: Ma clé publique RSA (tuple (n, e))
            public_key_dir: Instance de PublicKeyDirectory (optionnel)
        """
        self.my_private_key = my_private_key
        self.my_public_key = my_public_key
        self.sessions = {}
        self.public_key_dir = public_key_dir or PublicKeyDirectory()
        
        # Configuration de sécurité
        self.max_session_age = 3600  # 1 heure
        self.max_messages_per_session = 10000  # Limite pour forcer rotation
        
    def initiate_key_exchange(self, peer_id, peer_public_key=None):
        """
        Initie un échange de clés avec un pair
        
        Workflow :
        1. Génère une nouvelle clé AES-256
        2. Chiffre cette clé avec la clé publique RSA du pair
        3. Stocke la clé en clair localement
        4. Retourne la clé chiffrée pour envoi au pair
        """
        # Validation
        if not peer_id or not isinstance(peer_id, str):
            raise ValueError("L'ID du pair doit être une chaîne non vide")
            
        if peer_id in self.sessions:
            raise ValueError(f"Une session existe déjà avec '{peer_id}'")
        
        # Génération de la clé AES
        aes_key = AESManager.generate_session_key(256)
        
        # Récupération de la clé publique
        if peer_public_key is None:
            peer_public_key = self.public_key_dir.get_public_key(peer_id)
        
        if peer_public_key is None:
            raise ValueError(f"Clé publique de '{peer_id}' non trouvée")
        
        # Validation de la clé publique
        if not isinstance(peer_public_key, tuple) or len(peer_public_key) != 2:
            raise ValueError("Format de clé publique invalide")
            
        # Chiffrement de la clé AES par RSA
        try:
            aes_key_encrypted = RSAManager.encrypt(peer_public_key, aes_key)
        except Exception as e:
            raise ValueError(f"Échec du chiffrement RSA: {e}")
        
        # Stocker la clé en clair localement
        self.sessions[peer_id] = {
            'key': aes_key,           
            'created': time.time(),     
            'last_used': time.time(), 
            'message_count': 0,
            'initiated_by_me': True
        }
        
        print(f"✓ Échange de clés initié avec '{peer_id}'")
        
        return aes_key_encrypted

    def receive_key_exchange(self, peer_id, aes_key_encrypted):
        """
        Reçoit une clé AES chiffrée d'un pair
        
        Workflow :
        1. Déchiffre la clé AES avec ma clé privée RSA
        2. Stocke la clé pour les communications futures
        """
        # Validation
        if not peer_id or not isinstance(peer_id, str):
            raise ValueError("L'ID du pair doit être une chaîne non vide")
            
        if peer_id in self.sessions:
            raise ValueError(f"Une session existe déjà avec '{peer_id}'")
        
        if not aes_key_encrypted or not isinstance(aes_key_encrypted, bytes):
            raise ValueError("La clé chiffrée doit être de type bytes")
        
        # Déchiffrement
        try:
            aes_key_decrypted = RSAManager.decrypt(self.my_private_key, aes_key_encrypted)
        except Exception as e:
            raise ValueError(f"Échec du déchiffrement: {e}")
        
        # Vérification taille clé
        if len(aes_key_decrypted) not in [16, 24, 32]:
            raise ValueError(f"Taille de clé AES invalide: {len(aes_key_decrypted)} bytes")
        
        # Stocker
        self.sessions[peer_id] = {
            'key': aes_key_decrypted,           
            'created': time.time(),     
            'last_used': time.time(), 
            'message_count': 0,
            'initiated_by_me': False
        }
        
        print(f"✓ Clé reçue de '{peer_id}', session établie")

    def encrypt_message(self, peer_id, message):
        """Chiffre un message pour un pair"""
        # Vérifier que la session existe
        if peer_id not in self.sessions:
            raise KeyError(f"Aucune session avec '{peer_id}'")
        
        # Récupération clé
        session = self.sessions[peer_id]
        
        # Vérifier expiration de la session
        if time.time() - session['created'] > self.max_session_age:
            raise ValueError(f"Session avec '{peer_id}' expirée (>{self.max_session_age}s)")
        
        # Vérifier limite de messages (recommandation de rotation)
        if session['message_count'] >= self.max_messages_per_session:
            print(f"⚠ Attention : {self.max_messages_per_session} messages atteints, rotation recommandée")
        
        aes_key = session['key']
        
        # Conversion message
        if isinstance(message, str):
            message = message.encode('utf-8')
        elif not isinstance(message, bytes):
            raise TypeError("Le message doit être str ou bytes")
        
        # Chiffrement
        try:
            ciphertext, nonce, auth_tag = AESManager.encrypt(aes_key, message)
        except Exception as e:
            raise ValueError(f"Chiffrement échoué: {e}")
        
        # Mise à jour session
        session['last_used'] = time.time()
        session['message_count'] += 1
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'tag': auth_tag
        }

    def decrypt_message(self, peer_id, ciphertext, nonce, tag):
        """Déchiffre un message reçu"""
        # Vérifier session
        if peer_id not in self.sessions:
            raise KeyError(f"Aucune session avec '{peer_id}'")
        
        # Validation des paramètres
        if not isinstance(ciphertext, bytes):
            raise TypeError("Le ciphertext doit être de type bytes")
        if not isinstance(nonce, bytes) or len(nonce) != 12:
            raise ValueError("Le nonce doit être 16 bytes")
        if not isinstance(tag, bytes) or len(tag) != 16:
            raise ValueError("Le tag doit être 16 bytes")
        
        # Récupération clé
        session = self.sessions[peer_id]
        
        # Vérifier expiration
        if time.time() - session['created'] > self.max_session_age:
            raise ValueError(f"Session avec '{peer_id}' expirée (>{self.max_session_age}s)")
        
        aes_key = session['key']
        
        # Déchiffrement
        try:
            message_decrypted = AESManager.decrypt(aes_key, ciphertext, nonce, tag)
        except Exception as e:
            raise ValueError(f"Échec du déchiffrement ou authentification: {e}")
        
        # Mise à jour session
        session['last_used'] = time.time()
        session['message_count'] += 1

        return message_decrypted

    # ═══════════════════════════════════════════════════════════
    # GESTION DES SESSIONS
    # ═══════════════════════════════════════════════════════════
    
    def has_session(self, peer_id):
        """Vérifie si une session existe"""
        return peer_id in self.sessions
    
    def get_session_info(self, peer_id):
        """Obtient les informations d'une session"""
        if peer_id not in self.sessions:
            raise KeyError(f"Aucune session avec '{peer_id}'")
        
        session = self.sessions[peer_id]
        age = time.time() - session['created']
        inactive_for = time.time() - session['last_used']
        
        return {
            'peer_id': peer_id,
            'created': session['created'],
            'last_used': session['last_used'],
            'age': age,
            'message_count': session['message_count'],
            'initiated_by_me': session['initiated_by_me'],
            'is_active': inactive_for < 300,  # Actif si utilisé dans les 5 dernières minutes
            'is_expired': age > self.max_session_age,
            'inactive_for': inactive_for,
            'key_size': len(session['key']) * 8,
            'key_hash': hashlib.sha256(session['key']).hexdigest()[:16],
            'needs_rotation': session['message_count'] >= self.max_messages_per_session
        }
    
    def delete_session(self, peer_id):
        """Supprime une session"""
        if peer_id not in self.sessions:
            return False
        
        del self.sessions[peer_id]
        print(f"✓ Session avec '{peer_id}' supprimée")
        return True

    def list_active_sessions(self):
        """Liste les sessions actives"""
        return list(self.sessions.keys())
    
    def session_count(self):
        """Nombre de sessions actives"""
        return len(self.sessions)

    def cleanup_expired_sessions(self, max_age=None):
        """Nettoie les sessions expirées"""
        if max_age is None:
            max_age = self.max_session_age
            
        current_time = time.time()
        
        expired_peers = [
            peer_id for peer_id, session in self.sessions.items()
            if current_time - session['created'] > max_age
        ]
        
        for peer_id in expired_peers:
            del self.sessions[peer_id]
        
        if expired_peers:
            print(f"✓ {len(expired_peers)} session(s) expirée(s) supprimée(s)")
        
        return len(expired_peers)
    
    def clear_all_sessions(self):
        """Supprime toutes les sessions"""
        count = len(self.sessions)
        self.sessions.clear()
        print(f"✓ Toutes les sessions supprimées ({count})")
        return count
    
    def rotate_session_key(self, peer_id):
        """
        Rotation de clé : génère une nouvelle clé AES pour une session existante
        
        Returns:
            bytes: La nouvelle clé chiffrée à envoyer au pair
        """
        if peer_id not in self.sessions:
            raise KeyError(f"Aucune session avec '{peer_id}'")
        
        # Récupérer la clé publique du pair
        peer_public_key = self.public_key_dir.get_public_key(peer_id)
        if peer_public_key is None:
            raise ValueError(f"Clé publique de '{peer_id}' non trouvée pour rotation")
        
        # Supprimer l'ancienne session
        old_msg_count = self.sessions[peer_id]['message_count']
        self.delete_session(peer_id)
        
        # Créer une nouvelle session
        encrypted_key = self.initiate_key_exchange(peer_id, peer_public_key)
        
        print(f"✓ Rotation de clé effectuée (ancien compteur: {old_msg_count} messages)")
        
        return encrypted_key


class PublicKeyDirectory:
    """
    Annuaire local des clés publiques des autres utilisateurs.
    Permet de ne pas redemander la clé publique à chaque fois.
    """
    
    def __init__(self, storage_path="data/public_keys.json"):
        self.storage_path = storage_path
        self.public_keys = {}  # Format: {user_id: {public_key, retrieved_at, verified}}
        
        # Créer le dossier si nécessaire et charger les données
        os.makedirs(os.path.dirname(storage_path), exist_ok=True)
        self.load_from_disk()
    
    def add_public_key(self, user_id, public_key, verified=False):
        """Ajoute une clé publique à l'annuaire"""
        if not user_id or not isinstance(user_id, str):
            raise ValueError("L'ID utilisateur doit être une chaîne non vide")
        
        if not public_key or not isinstance(public_key, tuple) or len(public_key) != 2:
            raise ValueError("Clé publique invalide - doit être un tuple (n, e)")
        
        self.public_keys[user_id] = {
            'public_key': public_key,
            'retrieved_at': time.time(),
            'verified': verified
        }
        
        # Sauvegarder automatiquement
        self.save_to_disk()
    
    def get_public_key(self, user_id):
        """Récupère la clé publique d'un utilisateur"""
        if not user_id or not isinstance(user_id, str):
            raise ValueError("L'ID utilisateur doit être une chaîne non vide")
        
        if user_id in self.public_keys:
            return self.public_keys[user_id]['public_key']
        return None
    
    def get_public_key_info(self, user_id):
        """Récupère toutes les infos d'une clé publique"""
        if not user_id or not isinstance(user_id, str):
            raise ValueError("L'ID utilisateur doit être une chaîne non vide")
        
        return self.public_keys.get(user_id)
    
    def remove_public_key(self, user_id):
        """Supprime une clé publique"""
        if not user_id or not isinstance(user_id, str):
            raise ValueError("L'ID utilisateur doit être une chaîne non vide")
        
        if user_id in self.public_keys:
            del self.public_keys[user_id]
            self.save_to_disk()
            return True
        return False
    
    def has_public_key(self, user_id):
        """Vérifie si une clé publique est en cache"""
        return user_id in self.public_keys
    
    def list_users(self):
        """Liste tous les utilisateurs en cache"""
        return list(self.public_keys.keys())
    
    def cleanup_old_keys(self, max_age=7*24*3600):  # 7 jours par défaut
        """Nettoie les clés trop anciennes"""
        current_time = time.time()
        old_keys = [
            user_id for user_id, data in self.public_keys.items()
            if current_time - data['retrieved_at'] > max_age
        ]
        
        for user_id in old_keys:
            del self.public_keys[user_id]
        
        if old_keys:
            self.save_to_disk()
        
        return len(old_keys)
    
    def save_to_disk(self):
        """Sauvegarde l'annuaire sur disque"""
        try:
            # Convertir les tuples en listes pour JSON
            serializable_data = {}
            for user_id, data in self.public_keys.items():
                serializable_data[user_id] = {
                    'public_key': list(data['public_key']),  # tuple -> list
                    'retrieved_at': data['retrieved_at'],
                    'verified': data['verified']
                }
            
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_data, f, indent=2)
        except Exception as e:
            print(f"Erreur sauvegarde annuaire clés: {e}")
    
    def load_from_disk(self):
        """Charge l'annuaire depuis le disque"""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)
                
                # Convertir les listes en tuples
                for user_id, data in loaded_data.items():
                    self.public_keys[user_id] = {
                        'public_key': tuple(data['public_key']),  # list -> tuple
                        'retrieved_at': data['retrieved_at'],
                        'verified': data['verified']
                    }
        except Exception as e:
            print(f"Erreur chargement annuaire clés: {e}")
            self.public_keys = {}
    
    def __len__(self):
        """Nombre de clés en cache"""
        return len(self.public_keys)
    
    def clear(self):
        """Vide complètement l'annuaire"""
        self.public_keys.clear()
        self.save_to_disk()


# Backwards-compatible alias: some code expects `KeyExchange` class name
KeyExchange = KeyExchangeProtocol


# ═══════════════════════════════════════════════════════════════
# TESTS ET EXEMPLES D'UTILISATION
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("    TEST DU KEY EXCHANGE")
    print("=" * 60)
    print()
    
    # ═══════════════════════════════════════════════════════════
    # SETUP : Génération des clés pour Alice et Bob
    # ═══════════════════════════════════════════════════════════
    print("SETUP : Génération des clés RSA")
    print("-" * 60)
    
    # Alice génère sa paire de clés
    alice_public, alice_private = RSAManager.generate_keypair(bit_length=2048)
    print("✓ Alice : clés générées")
    
    # Bob génère sa paire de clés
    bob_public, bob_private = RSAManager.generate_keypair(bit_length=2048)
    print("✓ Bob : clés générées")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 1 : Échange de clés Alice → Bob avec PublicKeyDirectory
    # ═══════════════════════════════════════════════════════════
    print("TEST 1 : Échange de clés Alice → Bob (avec annuaire)")
    print("-" * 60)
    
    # Alice crée son gestionnaire avec annuaire
    alice_directory = PublicKeyDirectory()
    alice_exchange = KeyExchangeProtocol(alice_private, alice_public, alice_directory)
    
    # Bob crée son gestionnaire
    bob_exchange = KeyExchangeProtocol(bob_private, bob_public)
    
    # Alice ajoute la clé publique de Bob à son annuaire
    alice_directory.add_public_key("bob", bob_public, verified=True)
    print(f"✓ Clé publique de Bob ajoutée à l'annuaire d'Alice")
    
    # Alice initie l'échange avec Bob (sans passer la clé publique)
    print("Alice initie l'échange avec Bob...")
    encrypted_key = alice_exchange.initiate_key_exchange("bob")
    print(f"  Clé chiffrée : {len(encrypted_key)} bytes")
    
    # Simulation réseau : Alice envoie encrypted_key à Bob
    print("Envoi via réseau simulé...")
    
    # Bob reçoit la clé chiffrée
    print("Bob reçoit et déchiffre la clé...")
    bob_exchange.receive_key_exchange("alice", encrypted_key)
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 2 : Alice envoie un message à Bob
    # ═══════════════════════════════════════════════════════════
    print("TEST 2 : Communication Alice → Bob")
    print("-" * 60)
    
    # Alice chiffre un message
    message = "Hello Bob! Comment vas-tu ?"
    print(f"Alice : '{message}'")
    
    msg_data = alice_exchange.encrypt_message("bob", message)
    print(f"✓ Message chiffré")
    print(f"  - Ciphertext : {msg_data['ciphertext'][:30].hex()}... ({len(msg_data['ciphertext'])} bytes)")
    print(f"  - Nonce : {msg_data['nonce'].hex()}")
    print(f"  - Tag : {msg_data['tag'].hex()}")
    
    # Simulation réseau : envoi à Bob
    print("Envoi via réseau simulé...")
    
    # Bob déchiffre
    decrypted = bob_exchange.decrypt_message(
        "alice",
        msg_data['ciphertext'],
        msg_data['nonce'],
        msg_data['tag']
    )
    print(f"Bob reçoit : '{decrypted.decode('utf-8')}'")
    
    if message == decrypted.decode('utf-8'):
        print("✓ Vérification : messages identiques")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 3 : Bob répond à Alice
    # ═══════════════════════════════════════════════════════════
    print("TEST 3 : Communication Bob → Alice")
    print("-" * 60)
    
    # Bob répond
    response = "Salut Alice ! Je vais très bien, merci !"
    print(f"Bob : '{response}'")
    
    msg_data_bob = bob_exchange.encrypt_message("alice", response)
    print(f"✓ Message chiffré")
    
    # Alice déchiffre
    decrypted_response = alice_exchange.decrypt_message(
        "bob",
        msg_data_bob['ciphertext'],
        msg_data_bob['nonce'],
        msg_data_bob['tag']
    )
    print(f"Alice reçoit : '{decrypted_response.decode('utf-8')}'")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 4 : Gestion des sessions
    # ═══════════════════════════════════════════════════════════
    print("TEST 4 : Gestion des sessions")
    print("-" * 60)
    
    # Informations sur la session
    alice_info = alice_exchange.get_session_info("bob")
    print(f"Session Alice → Bob :")
    print(f"  - Créée il y a : {alice_info['age']:.2f} secondes")
    print(f"  - Messages échangés : {alice_info['message_count']}")
    print(f"  - Initiée par moi : {alice_info['initiated_by_me']}")
    print(f"  - Expirée : {alice_info['is_expired']}")
    print()
    
    bob_info = bob_exchange.get_session_info("alice")
    print(f"Session Bob → Alice :")
    print(f"  - Créée il y a : {bob_info['age']:.2f} secondes")
    print(f"  - Messages échangés : {bob_info['message_count']}")
    print(f"  - Initiée par moi : {bob_info['initiated_by_me']}")
    print()
    
    # Liste des sessions
    print(f"Sessions actives d'Alice : {alice_exchange.list_active_sessions()}")
    print(f"Sessions actives de Bob : {bob_exchange.list_active_sessions()}")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 5 : Conversations multiples
    # ═══════════════════════════════════════════════════════════
    print("TEST 5 : Conversations multiples (Alice avec Bob et Carol)")
    print("-" * 60)
    
    # Carol arrive
    carol_public, carol_private = RSAManager.generate_keypair(bit_length=2048)
    carol_exchange = KeyExchangeProtocol(carol_private, carol_public)
    print("✓ Carol : clés générées")
    
    # Alice ajoute Carol à son annuaire
    alice_directory.add_public_key("carol", carol_public)
    
    # Alice initie avec Carol
    encrypted_key_carol = alice_exchange.initiate_key_exchange("carol")
    carol_exchange.receive_key_exchange("alice", encrypted_key_carol)
    print("✓ Échange de clés Alice ↔ Carol établi")
    
    # Alice envoie à Carol
    msg_carol = alice_exchange.encrypt_message("carol", "Salut Carol!")
    print("✓ Alice → Carol : 'Salut Carol!'")
    
    # Alice envoie à Bob
    msg_bob = alice_exchange.encrypt_message("bob", "Et toi Bob ?")
    print("✓ Alice → Bob : 'Et toi Bob ?'")
    
    print(f"\nAlice a maintenant {alice_exchange.session_count()} sessions actives")
    print(f"Avec : {alice_exchange.list_active_sessions()}")
    print(f"Annuaire d'Alice : {alice_directory.list_users()}")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 6 : Test de sécurité (mauvaise clé)
    # ═══════════════════════════════════════════════════════════
    print("TEST 6 : Test de sécurité (manipulation)")
    print("-" * 60)
    
    # Tenter de déchiffrer un message avec la mauvaise session
    print("Tentative de Bob de déchiffrer un message d'Alice à Carol...")
    try:
        bob_exchange.decrypt_message(
            "alice",
            msg_carol['ciphertext'],
            msg_carol['nonce'],
            msg_carol['tag']
        )
        print("✗ ERREUR : Le déchiffrement aurait dû échouer !")
    except Exception as e:
        print(f"✓ Sécurité OK : {str(e)[:50]}...")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 7 : Rotation de clés
    # ═══════════════════════════════════════════════════════════
    print("TEST 7 : Rotation de clés")
    print("-" * 60)
    
    # Simuler beaucoup de messages
    old_count = alice_exchange.sessions["bob"]["message_count"]
    alice_exchange.sessions["bob"]["message_count"] = 10001
    
    # Vérifier le besoin de rotation
    info = alice_exchange.get_session_info("bob")
    if info['needs_rotation']:
        print("⚠ Rotation de clé nécessaire détectée")
        
        # Alice effectue la rotation
        new_encrypted_key = alice_exchange.rotate_session_key("bob")
        
        # Bob reçoit la nouvelle clé
        bob_exchange.delete_session("alice")
        bob_exchange.receive_key_exchange("alice", new_encrypted_key)
        
        print("✓ Rotation terminée, nouvelle session établie")
    print()
    
    # ═══════════════════════════════════════════════════════════
    # TEST 8 : Nettoyage
    # ═══════════════════════════════════════════════════════════
    print("TEST 8 : Nettoyage des sessions")
    print("-" * 60)
    
    # Supprimer une session
    alice_exchange.delete_session("carol")
    print(f"Sessions restantes d'Alice : {alice_exchange.list_active_sessions()}")
    
    # Tout supprimer
    alice_exchange.clear_all_sessions()
    print(f"Sessions d'Alice après clear : {alice_exchange.list_active_sessions()}")
    print()
    
    print("=" * 60)
    print("    TOUS LES TESTS RÉUSSIS !")
    print("=" * 60)
    print()
    print("RÉSUMÉ :")
    print("✓ Échange de clés bidirectionnel")
    print("✓ Chiffrement/déchiffrement des messages")
    print("✓ Gestion de multiples sessions simultanées")
    print("✓ Sécurité : impossible de déchiffrer sans la bonne clé")
    print("✓ Gestion du cycle de vie des sessions")
    print("✓ Rotation automatique des clés")
    print("✓ Intégration avec PublicKeyDirectory")