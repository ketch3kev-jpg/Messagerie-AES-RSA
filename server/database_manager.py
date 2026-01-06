class DatabaseManager:
    """
    Gère la base de données SQLite.
    Stocke utilisateurs, clés publiques, messages en attente.
    """
    
    def __init__(self, db_path="data/messagerie.db"):
        """
        Tables:
            - users (user_id, password_hash, public_key_n, public_key_e, created_at)
            - pending_messages (id, from_user, to_user, encrypted_data, timestamp)
            - contacts (user_id, contact_user_id, added_at)
        """
        
    def init_database(self):
        """Crée les tables si elles n'existent pas"""
        
    # ─────────────────────────────────────────────────────────
    # GESTION DES UTILISATEURS
    # ─────────────────────────────────────────────────────────
    
    def create_user(self, user_id, password_hash, public_key):
        """Crée un nouvel utilisateur"""
        
    def authenticate_user(self, user_id, password_hash):
        """Vérifie les identifiants"""
        
    def get_public_key(self, user_id):
        """Récupère la clé publique d'un utilisateur"""
        
    def user_exists(self, user_id):
        """Vérifie si un utilisateur existe"""
        
    # ─────────────────────────────────────────────────────────
    # GESTION DES MESSAGES EN ATTENTE
    # ─────────────────────────────────────────────────────────
    
    def store_pending_message(self, from_user, to_user, encrypted_data):
        """Stocke un message pour un utilisateur hors ligne"""
        
    def get_pending_messages(self, user_id):
        """Récupère tous les messages en attente pour un utilisateur"""
        
    def delete_pending_message(self, message_id):
        """Supprime un message après livraison"""
        
    # ─────────────────────────────────────────────────────────
    # GESTION DES CONTACTS
    # ─────────────────────────────────────────────────────────
    
    def add_contact(self, user_id, contact_user_id):
        """Ajoute un contact"""
        
    def get_contacts(self, user_id):
        """Liste les contacts d'un utilisateur"""
        
    def remove_contact(self, user_id, contact_user_id):
        """Supprime un contact"""