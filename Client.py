
"""
 Communication sécurisée avec chiffrement hybride
============================================================
Ce programme implémente un client basé sur le modèle de sécurité PGP
avec chiffrement hybride (RSA + AES).
Il génère ses propres clés RSA, utilise AES pour chiffrer les messages
et RSA pour chiffrer la clé AES, puis signe et envoie les messages
de manière sécurisée au serveur.
"""

import socket
import pickle
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class ClientPGP:
    def __init__(self, host='localhost', port=8888):
        """
        Initialisation du client PGP
        
        Args:
            host (str): Adresse IP du serveur
            port (int): Port du serveur
        """
        self.host = "172.20.10.3"
        self.port = 8888
        self.cle_privee = None
        self.cle_publique = None
        self.cle_publique_serveur = None
        
    def _generer_cles_rsa(self):
        """🔐 Génération des clés RSA du client"""
        print("🔐 Génération des clés RSA du client...")
        
        # Génération de la clé privée RSA
        self.cle_privee = rsa.generate_private_key(
            public_exponent=65537,  # Exposant public standard
            key_size=2048,          # Taille de clé sécurisée
            backend=default_backend()
        )
        
        # Extraction de la clé publique depuis la clé privée
        self.cle_publique = self.cle_privee.public_key()
        
       # print("✅ Clés RSA du client générées avec succès")
    
    def _generer_cle_aes(self):
        """🔑 Génération d'une clé AES aléatoire"""
        print("🔑 Génération de la clé AES...")
        cle_aes = os.urandom(32)  # Clé AES-256 (32 bytes)
        iv = os.urandom(16)       # Vecteur d'initialisation (16 bytes pour AES)
       # print("✅ Clé AES générée avec succès")
        return cle_aes, iv
    
    def _chiffrer_aes(self, message, cle_aes, iv):
        """
        🔒 Chiffrement AES du message
        
        Args:
            message (bytes): Message à chiffrer
            cle_aes (bytes): Clé AES
            iv (bytes): Vecteur d'initialisation
            
        Returns:
            bytes: Message chiffré avec AES
        """
       # print("🔒 Chiffrement AES du message...")
        
        # Création du cipher AES en mode CBC
        cipher = Cipher(
            algorithms.AES(cle_aes),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        # Padding PKCS7 pour AES
        def _pad_message(message):
            pad_length = 16 - (len(message) % 16)
            return message + bytes([pad_length] * pad_length)
        
        # Application du padding et chiffrement
        message_padded = _pad_message(message)
        encryptor = cipher.encryptor()
        message_chiffre = encryptor.update(message_padded) + encryptor.finalize()
        
       # print("✅ Message chiffré avec AES avec succès")
        return message_chiffre
    
    def _chiffrer_cle_aes_rsa(self, cle_aes):
        """
        🔐 Chiffrement de la clé AES avec RSA
        
        Args:
            cle_aes (bytes): Clé AES à chiffrer
            
        Returns:
            bytes: Clé AES chiffrée avec RSA
        """
       # print("🔐 Chiffrement de la clé AES avec RSA...")
        
        cle_aes_chiffree = self.cle_publique_serveur.encrypt(
            cle_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
       # print("✅ Clé AES chiffrée avec RSA avec succès")
        return cle_aes_chiffree
    
    def _serialiser_cle_publique(self):
        """📤 Sérialisation de la clé publique pour l'envoi"""
        return self.cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def _connecter_au_serveur(self):
        """
        🌐 Connexion au serveur et récupération de sa clé publique
        
        Returns:
            socket: Socket connecté au serveur ou None en cas d'erreur
        """
        try:
            print(f"🔗 Connexion au serveur {self.host}:{self.port}...")
            
            # Création du socket client
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.connect((self.host, self.port))
            
            print("✅ Connexion établie avec le serveur")
            
            # Réception de la clé publique du serveur
          #  print("📥 Réception de la clé publique du serveur...")
            cle_publique_serveur_pem = socket_client.recv(1024)
            
            # Reconstruction de la clé publique du serveur
            self.cle_publique_serveur = serialization.load_pem_public_key(
                cle_publique_serveur_pem,
                backend=default_backend()
            )
            
          #  print("✅ Clé publique du serveur reçue et chargée")
            
            return socket_client
            
        except Exception as e:
            print(f"❌ Erreur de connexion: {e}")
            return None
    
    def _signer_message(self, message):
        """
        ✍️ Signature numérique du message
        
        Args:
            message (bytes): Message à signer
            
        Returns:
            bytes: Signature numérique
        """
        #print("✍️ Signature numérique du message...")
        
        signature = self.cle_privee.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
       #{} print("✅ Message signé avec succès")
        return signature
    
    def envoyer_message(self, message_texte):
        """
        📤 Envoi d'un message sécurisé au serveur avec chiffrement hybride
        
        Args:
            message_texte (str): Message à envoyer
        """
        print(f" Préparation de l'envoi du message: '{message_texte}'")
       # print("🔄 Utilisation du chiffrement hybride (RSA + AES)")
        print("-" * 60)
        
        # Conversion du message en bytes
        message_bytes = message_texte.encode('utf-8')
        
        # Connexion au serveur
        socket_client = self._connecter_au_serveur()
        if not socket_client:
            return False
        
        try:
            # Génération de la clé AES et du vecteur d'initialisation
            cle_aes, iv = self._generer_cle_aes()
            
            # Signature numérique du message original
            signature = self._signer_message(message_bytes)
            
            # Chiffrement hybride
            message_chiffre_aes = self._chiffrer_aes(message_bytes, cle_aes, iv)
            cle_aes_chiffree_rsa = self._chiffrer_cle_aes_rsa(cle_aes)
            
            # Préparation du paquet sécurisé hybride
           # print("📦 Préparation du paquet sécurisé hybride...")
            paquet_securise = {
                'message_chiffre_aes': message_chiffre_aes,
                'cle_aes_chiffree': cle_aes_chiffree_rsa,
                'iv': iv,
                'signature': signature,
                'cle_publique_client': self._serialiser_cle_publique()
            }
            
            # Envoi du paquet sécurisé au serveur
            print("📡 Envoi du paquet au serveur...")
            donnees_a_envoyer = pickle.dumps(paquet_securise)
            socket_client.send(donnees_a_envoyer)
            
            print("✅ Message envoyé avec succès!")
           # print("🔒 Le message a été:")
           # print("   ✅ Signé numériquement (authenticité)")
           # print("   ✅ Chiffré avec AES (confidentialité - efficace)")
           # print("   ✅ Clé AES chiffrée avec RSA (sécurité des clés)")
           # print("   ✅ Transmis de manière sécurisée")
           # print("🔄 Chiffrement hybride utilisé avec succès!")
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur lors de l'envoi: {e}")
            return False
        
        finally:
            socket_client.close()
           # print("🔌 Connexion fermée")
    
    def interface_utilisateur(self):
        """🎯 Interface utilisateur du client"""
       # print("🔐 Client PGP - Communication Sécurisée Hybride")
       # print("=" * 55)
        #print("🔄 Chiffrement hybride: RSA + AES")
       # print("   • AES pour chiffrer le message (rapide)")
        #print("   • RSA pour chiffrer la clé AES (sécurisé)")
        
        # Génération des clés du client
        self._generer_cles_rsa()
        
        #print("\n⚡ Mode test rapide disponible!")
       # print("Tapez 'test' pour envoyer un message de démonstration\n")
        
        while True:
            print("🌟 Que souhaitez-vous faire ?")
            print("1. Envoyer un message sécurisé (chiffrement hybride)")
            print("2. Quitter")
            
            choix = input(" Votre choix (1-2): ").strip()
            
            if choix == '1':
                message = input(" Entrez votre message: ").strip()
                if message:
                    if message.lower() == 'test':
                        message = "Hello, ceci est un message de test sécurisé avec chiffrement hybride RSA+AES!"
                        print(f" Envoi du message de test: '{message}'")
                    
                    succes = self.envoyer_message(message)
                    if succes:
                        print(" Opération terminée avec succès!")
                    else:
                        print("❌ Échec de l'envoi du message")
                else:
                    print("⚠️  Message vide, veuillez réessayer")
                
                print("-" * 60)
                
            elif choix == '2':
                print("Au revoir!👋")
                break
            else:
                print("❌ Choix invalide, veuillez réessayer")

if __name__ == "__main__":
    # Création et démarrage du client PGP
    client = ClientPGP()
    client.interface_utilisateur()