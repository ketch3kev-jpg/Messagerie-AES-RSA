from . import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import os
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import padding as sym_padding
class RSAManager:
    @staticmethod
    def generate_keypair(bit_length=2048, e=65537, max_attempts=10):
            print(f"🔧 Génération clés RSA {bit_length} bits...")
            
            for attempt in range(max_attempts):
                print(f"   Tentative {attempt + 1}/{max_attempts}...")
                
                try:
                    p = utils.generate_large_prime(bit_length // 2, 10) 
                    print(f"    Premier nombre premier p généré")
                    
                    q = utils.generate_large_prime(bit_length // 2, 10)  
                    while p == q:
                        q = utils.generate_large_prime(bit_length // 2, 10)
                    print(f"    Deuxième nombre premier q généré")
                    
                    n = p * q
                    phi = (p - 1) * (q - 1)
                    
                    d = utils.mod_inverse(e, phi)
                    
                    dmp1 = d % (p - 1)
                    dmq1 = d % (q - 1)
                    iqmp = utils.mod_inverse(q, p)
                    
                    public_key = (n, e)
                    private_key = {
                        'n': n, 'e': e, 'd': d, 'p': p, 'q': q,
                        'dmp1': dmp1, 'dmq1': dmq1, 'iqmp': iqmp
                    }
                    
                    print(f"    Clés générées avec succès !")
                    return (public_key, private_key)
                    
                except ValueError as ve:
                    print(f"    Tentative {attempt + 1} échouée: {ve}")
                    if attempt == max_attempts - 1:
                        raise ValueError(f"Impossible de générer une paire de clés valide après {max_attempts} tentatives")
                    continue
                except Exception as e:
                    print(f"   Erreur inattendue: {e}")
                    raise
            
            raise ValueError("Échec de la génération de clés")

    @staticmethod
    def encrypt(public_key, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('UTF-8')
        n, e = public_key
        # création d'une clé publique compatible
        public_key_crypto = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        # chiffrement avec OAEP pré-implémenté
        ciphertext = public_key_crypto.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def decrypt(private_key, ciphertext):
        # private_key est maintenant un dictionnaire avec tous les paramètres
        n = private_key['n']
        d = private_key['d']
        p = private_key['p']
        q = private_key['q']
        e = private_key['e']
        dmp1 = private_key['dmp1']
        dmq1 = private_key['dmq1']
        iqmp = private_key['iqmp']
        
        # RECONSTRUCTION DE LA CLÉ PRIVÉE CRYPTOGRAPHY
        private_key_crypto = rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=dmp1,
            dmq1=dmq1,
            iqmp=iqmp,
            public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
        ).private_key(default_backend())
        
        # DÉCHIFFREMENT AVEC OAEP AUTOMATIQUE
        # Plus besoin de convertir en int/to_bytes, la librairie gère tout
        plaintext = private_key_crypto.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext
    
    @staticmethod
    def validate_password(password): #Valide la force du mot de passe
        if len(password)<8:
            raise ValueError("Le mot de passe doit contenir au moins 8 caractères")
            
    @staticmethod  
    def save_keypair(user_id, public_key, private_key, password):
        """Sauvegarde la paire de clés en chiffrant la clé privée"""
        
        # validation du mot de passe
        # appeler la méthode statique via la classe pour être sûr que le nom est résolu
        RSAManager.validate_password(password)
        # Créer le dossier data/keys s'il n'existe pas
        os.makedirs("data/keys", exist_ok=True)
        
        # Étape 1: Sérialisation de la clé publique
        n, e = public_key
        public_key_obj = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        public_pem = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Sauvegarde de la clé publique
        public_key_path = f"data/keys/{user_id}_public.pem"
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        # Étape 2: Préparation de la clé privée pour le chiffrement
        private_key_json = json.dumps({
            'n': private_key['n'],
            'e': private_key['e'], 
            'd': private_key['d'],
            'p': private_key['p'],
            'q': private_key['q'],
            'dmp1': private_key['dmp1'],
            'dmq1': private_key['dmq1'],
            'iqmp': private_key['iqmp']
        })
        private_key_bytes = private_key_json.encode('utf-8')
        
        # Étape 3: Chiffrement de la clé privée
        # Génération salt et IV
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        # Dérivation de la clé AES depuis le password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        
        # Chiffrement AES-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Padding des données
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(private_key_bytes) + padder.finalize()
        
        # Chiffrement
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Structure des données à sauvegarder
        private_key_data = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8')
        }
        
        # Sauvegarde de la clé privée chiffrée
        private_key_path = f"data/keys/{user_id}_private.enc"
        with open(private_key_path, 'w') as f:
            json.dump(private_key_data, f)
        
        return public_key_path, private_key_path

    @staticmethod
    def load_keypair(user_id, password):
        """Charge et déchiffre la paire de clés"""
        
        # Étape 1: Chargement de la clé publique
        public_key_path = f"data/keys/{user_id}_public.pem"
        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"Clé publique non trouvée: {public_key_path}")
        
        with open(public_key_path, 'rb') as f:
            public_pem = f.read()
        
        public_key_obj = serialization.load_pem_public_key(public_pem, backend=default_backend())
        public_numbers = public_key_obj.public_numbers()
        public_key = (public_numbers.n, public_numbers.e)
        
        # Étape 2: Chargement de la clé privée chiffrée
        private_key_path = f"data/keys/{user_id}_private.enc"
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Clé privée non trouvée: {private_key_path}")
        
        with open(private_key_path, 'r') as f:
            private_key_data = json.load(f)
        
        # Décodage des données base64
        salt = base64.b64decode(private_key_data['salt'])
        iv = base64.b64decode(private_key_data['iv'])
        encrypted_data = base64.b64decode(private_key_data['encrypted_data'])
        
        # Étape 3: Déchiffrement de la clé privée
        # Régénération de la clé AES
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        try:
            key = kdf.derive(password.encode('utf-8'))
        except Exception:
            raise ValueError("Mot de passe incorrect")
        
        # Déchiffrement AES-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        try:
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Dépadding
            unpadder = sym_padding.PKCS7(128).unpadder()
            private_key_bytes = unpadder.update(padded_data) + unpadder.finalize()
            
            # Reconstruction de la clé privée
            private_key_json = private_key_bytes.decode('utf-8')
            private_key_dict = json.loads(private_key_json)
            
        except Exception as e:
            raise ValueError(f"Échec du déchiffrement: {e}")
        
        return public_key, private_key_dict  




if __name__ == "__main__":
    print("=== Test du RSA Manager Amélioré ===\n")
    
    # 1. Génération de clés
    print("1. Génération d'une paire de clés...")
    public_key, private_key = RSAManager.generate_keypair(bit_length=2048)
    print("✓ Paire de clés générée\n")
    
    # 2. Sauvegarde sécurisée
    print("2. Sauvegarde des clés...")
    user_id = "alice"
    password = "MonMotDePasseSecurise123!"
    save_keypair(user_id, public_key, private_key, password)
    print()
    
    # 3. Chargement des clés
    print("3. Chargement des clés...")
    loaded_public, loaded_private = load_keypair(user_id, password)
    print()
    
    # 4. Test de chiffrement/déchiffrement
    print("4. Test de chiffrement/déchiffrement...")
    message = "Message secret pour le projet RSA!"
    print(f"Message original : {message}")
    
    ciphertext = RSAManager.encrypt(loaded_public, message)
    print(f"Message chiffré : {ciphertext[:50]}... ({len(ciphertext)} bytes)")
    
    decrypted = RSAManager.decrypt(loaded_private, ciphertext)
    print(f"Message déchiffré : {decrypted.decode('utf-8')}")
    
    if message == decrypted.decode('utf-8'):
        print("✓ Test réussi !")
    
    print("\n=== Fin des tests ===")
