
"""

Ce programme simule un attaquant qui tente d'envoyer un message
au serveur en se faisant passer pour un client légitime.
L'attaquant génère ses propres clés mais tente d'usurper l'identité
d'un autre client. Le serveur détectera la signature invalide.
"""

import socket
import pickle
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AttaquantPGP:
    def __init__(self, host='localhost', port=8888):
        """
        Initialisation de l'attaquant
        
        Args:
            host (str): Adresse IP du serveur
            port (int): Port du serveur
        """
        self.host = "172.20.10.3"
        self.port = 8888
        self.cle_privee_attaquant = None
        self.cle_publique_attaquant = None
        self.cle_publique_serveur = None
        # L'attaquant n'a PAS accès à la vraie clé privée du client légitime
        self.cle_publique_client_legitime = None  # Il pourrait avoir la clé publique
        
    def _generer_cles_rsa_attaquant(self):
        """Génération des propres clés RSA de l'attaquant"""
       
        # L'attaquant génère SES PROPRES clés
        self.cle_privee_attaquant = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        self.cle_publique_attaquant = self.cle_privee_attaquant.public_key()
        
    
    def _simuler_cle_publique_legitime(self):
        """
        Simulation d'une clé publique d'un client légitime
        (L'attaquant pourrait avoir récupéré cette clé publique d'une façon ou d'une autre)
        """
        
        # Génération d'une fausse clé "légitime" pour la démonstration
        cle_privee_fictive = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.cle_publique_client_legitime = cle_privee_fictive.public_key()
        
        print("Clé publique récupérée")
    
    def _generer_cle_aes(self):
        """Génération d'une clé AES aléatoire"""
        cle_aes = os.urandom(32)  # Clé AES-256
        iv = os.urandom(16)       # Vecteur d'initialisation
        return cle_aes, iv
    
    def _chiffrer_aes(self, message, cle_aes, iv):
        """
        Chiffrement AES du message
        """
        
        cipher = Cipher(
            algorithms.AES(cle_aes),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        def _pad_message(message):
            pad_length = 16 - (len(message) % 16)
            return message + bytes([pad_length] * pad_length)
        
        message_padded = _pad_message(message)
        encryptor = cipher.encryptor()
        message_chiffre = encryptor.update(message_padded) + encryptor.finalize()
        
        return message_chiffre
    
    def _chiffrer_cle_aes_rsa(self, cle_aes):
        """
        Chiffrement de la clé AES avec RSA
        """
        cle_aes_chiffree = self.cle_publique_serveur.encrypt(
            cle_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return cle_aes_chiffree
    
    def _connecter_au_serveur(self):
        """
        Connexion au serveur et récupération de sa clé publique
        """
        try:
            print(f"Connexion au serveur {self.host}:{self.port}...")
            
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.connect((self.host, self.port))
            
            print("Réception de la clé publique du serveur...")
            cle_publique_serveur_pem = socket_client.recv(1024)
            
            self.cle_publique_serveur = serialization.load_pem_public_key(
                cle_publique_serveur_pem,
                backend=default_backend()
            )
             
            return socket_client
            
        except Exception as e:
            print(f"Erreur de connexion: {e}")
            return None
    
    def _signer_message_avec_mauvaise_cle(self, message):
        """
        Tentative de signature avec la MAUVAISE clé privée
        (L'attaquant utilise SA propre clé au lieu de celle du client légitime)
        """
      
        # L'attaquant signe avec SA propre clé privée
        # (Il n'a pas accès à la vraie clé privée du client)
        signature = self.cle_privee_attaquant.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def _serialiser_fausse_cle_publique(self):
        """
        Envoi d'une fausse clé publique pour tenter l'usurpation
        """
        
        # L'attaquant peut soit:
        # 1. Envoyer sa propre clé publique (incohérent avec la signature)
        # 2. Envoyer une clé publique d'un client légitime qu'il aurait récupérée
        
        # Ici, on simule le cas 2: il a la clé publique légitime mais pas la clé privée
        if self.cle_publique_client_legitime:
            return self.cle_publique_client_legitime.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            return self.cle_publique_attaquant.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
    def tenter_attaque(self, message_malveillant):
        """
        Tentative d'attaque par usurpation d'identité
        
        Args:
            message_malveillant (str): Message malveillant à envoyer
        """
        print("=" * 50)
        print("DÉBUT DE L'ATTAQUE")
        print("=" * 50)
        print(f"Message: {message_malveillant}")
        print("-" * 50)
        
        message_bytes = message_malveillant.encode('utf-8')
        
        # Connexion au serveur
        socket_client = self._connecter_au_serveur()
        if not socket_client:
            return False
        
        try:
            # Génération de la clé AES
            cle_aes, iv = self._generer_cle_aes()
            
            # PROBLÈME: L'attaquant signe avec SA propre clé privée
            signature = self._signer_message_avec_mauvaise_cle(message_bytes)
            
            # Chiffrement hybride (cette partie fonctionne normalement)
            message_chiffre_aes = self._chiffrer_aes(message_bytes, cle_aes, iv)
            cle_aes_chiffree_rsa = self._chiffrer_cle_aes_rsa(cle_aes)
            
            # Préparation du paquet d'attaque
            print("Préparation du paquet...")
            paquet_attaque = {
                'message_chiffre_aes': message_chiffre_aes,
                'cle_aes_chiffree': cle_aes_chiffree_rsa,
                'iv': iv,
                'signature': signature,  # Signature avec la mauvaise clé
                'cle_publique_client': self._serialiser_fausse_cle_publique()  # Fausse identité
            }
            
            # Envoi du paquet d'attaque

            
            donnees_a_envoyer = pickle.dumps(paquet_attaque)
            socket_client.send(donnees_a_envoyer)
            
            print("Paquet envoyé")
            
            return True
            
        except Exception as e:
            print(f"Erreur lors de l'attaque: {e}")
            return False
        
        finally:
            socket_client.close()
            print("Connexion fermée")
    
    def interface_attaquant(self):
        """Interface de l'attaquant"""
    
    
       
        print()
        
        # Génération des clés de l'attaquant
        self._generer_cles_rsa_attaquant()
        
        # Simulation d'une clé publique légitime récupérée
        self._simuler_cle_publique_legitime()
        
        print("\nOptions:")
        print("1. Lancer une attaque")
        print("2. Quitter")
        
        while True:
            choix = input("Choix (1-2): ").strip()
            
            if choix == '1':
                message = input("Message à envoyer: ").strip()
                
                if message:
                    print(f"\nLancement de l'attaque...")
                    succes = self.tenter_attaque(message)
                    
                    if succes:
                        print("\nRésultat:")
                        print("- Signature invalide (clé incorrecte)")
                        print("- Le serveur détecte l'usurpation")
                    else:
                        print("Échec de l'attaque")
                else:
                    print("Message vide")
                
                print("-" * 40)
                
            elif choix == '2':
                print("Fin de la démonstration")
                break
            else:
                print("Choix invalide")

if __name__ == "__main__":
  
    # Création et démarrage de l'attaquant
    attaquant = AttaquantPGP()
    attaquant.interface_attaquant()