import os
import time
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AESManager:
    @staticmethod
    def generate_session_key(key_size=256):
        size_bytes = key_size // 8
        key = os.urandom(size_bytes)
        return key
    
    @staticmethod
    def encrypt(key, plaintext):
        # Validation des entrées
        if not isinstance(key, bytes):
            raise ValueError("La clé doit être de type bytes")
        
        if len(key) not in [16, 24, 32]:
            raise ValueError(
                f"Taille de clé invalide : {len(key)} bytes. "
                "Valeurs acceptées : 16 (AES-128), 24 (AES-192), 32 (AES-256)"
            )
        
        if not isinstance(plaintext, bytes):
            raise ValueError("Le plaintext doit être de type bytes")
        
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        auth_tag = encryptor.tag
        return ciphertext, nonce, auth_tag
    
    @staticmethod
    def decrypt(key, ciphertext, nonce, auth_tag):
        # Validation des entrées
        if not isinstance(key, bytes):
            raise ValueError("La clé doit être de type bytes")
        
        if len(key) not in [16, 24, 32]:
            raise ValueError(
                f"Taille de clé invalide : {len(key)} bytes. "
                "Valeurs acceptées : 16, 24, 32"
            )
        
        if not isinstance(ciphertext, bytes):
            raise ValueError("Le ciphertext doit être de type bytes")
        
        if not isinstance(nonce, bytes) or len(nonce) != 12:
            raise ValueError("Le nonce doit être de 12 bytes")
        
        if not isinstance(auth_tag, bytes) or len(auth_tag) != 16:
            raise ValueError("Le tag d'authentification doit être de 16 bytes")
        
        try:
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            # Gestion des différentes erreurs possibles
            if "Authentication" in str(e) or "tag" in str(e).lower():
                raise ValueError("Échec de l'authentification : données corrompues ou clé incorrecte")
            elif "padding" in str(e).lower():
                raise ValueError("Erreur de padding : données mal formattées")
            else:
                raise ValueError(f"Échec du déchiffrement : {e}")


if __name__ == "__main__":
    print("Test 1: Génération des clés AES")
    key_128 = AESManager.generate_session_key(128)
    key_192 = AESManager.generate_session_key(192)
    key_256 = AESManager.generate_session_key(256)

    print(f" Clé AES-128 : {len(key_128)} bytes")
    print(f" Clé AES-192 : {len(key_192)} bytes")
    print(f" Clé AES-256 : {len(key_256)} bytes")

    print("\nTest 2: Chiffrement/déchiffrement")
    msg = "message à chiffrer".encode("utf-8")

    print(f"Message original : {msg.decode('utf-8')}")
    print(f"Taille : {len(msg)} bytes")
    print()
    
    # Chiffrement
    ciphertext, nonce, auth_tag = AESManager.encrypt(key_256, msg)
    print(f" Message chiffré")
    print(f"  - Ciphertext : {ciphertext.hex()[:60]}... ({len(ciphertext)} bytes)")
    print(f"  - Nonce : {nonce.hex()} ({len(nonce)} bytes)")
    print(f"  - Auth tag : {auth_tag.hex()} ({len(auth_tag)} bytes)")
    print()
    
    # Déchiffrement
    decrypted_message = AESManager.decrypt(key_256, ciphertext, nonce, auth_tag)
    print(f"✓ Message déchiffré : {decrypted_message.decode('utf-8')}")
    
    if msg == decrypted_message:
        print("✓ Vérification réussie : messages identiques")
    print()
 
