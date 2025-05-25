
"""
Communication sécurisée avec chiffrement hybride
=============================================================
Ce programme implémente un serveur basé sur le modèle de sécurité PGP
avec chiffrement hybride (RSA + AES).
Il génère ses propres clés RSA, écoute les connexions clients,
déchiffre d'abord la clé AES avec RSA, puis déchiffre le message avec AES,
et vérifie les signatures numériques.
"""

import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import threading

class ServeurPGP:
    def __init__(self, host='localhost', port=8888):
        """
        Initialisation du serveur 
        
        Args:
            host (str): Adresse IP d'écoute
            port (int): Port d'écoute
        """
        self.host = "172.20.10.3"
        self.port = 8888
        self.cle_privee = None
        self.cle_publique = None
        self.socket_serveur = None
        
    def _generer_cles_rsa(self):
        """🔐 Génération des clés RSA du serveur"""
        print("🔐 Génération des clés RSA du serveur...")
        
        # Génération de la clé privée RSA
        self.cle_privee = rsa.generate_private_key(
            public_exponent=65537,  # Exposant public standard
            key_size=2048,          # Taille de clé sécurisée
            backend=default_backend()
        )
        
        # Extraction de la clé publique depuis la clé privée
        self.cle_publique = self.cle_privee.public_key()
        
       # print("✅ Clés RSA du serveur générées avec succès")
    
    def _dechiffrer_cle_aes_rsa(self, cle_aes_chiffree):
        """
        🔓 Déchiffrement de la clé AES avec RSA
        
        Args:
            cle_aes_chiffree (bytes): Clé AES chiffrée avec RSA
            
        Returns:
            bytes: Clé AES déchiffrée
        """
       # print("🔓 Déchiffrement de la clé AES avec RSA...")
        
        cle_aes = self.cle_privee.decrypt(
            cle_aes_chiffree,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print("✅ Clé AES déchiffrée avec RSA avec succès")
        return cle_aes
    
    def _dechiffrer_aes(self, message_chiffre, cle_aes, iv):
        """
        🔓 Déchiffrement AES du message
        
        Args:
            message_chiffre (bytes): Message chiffré avec AES
            cle_aes (bytes): Clé AES
            iv (bytes): Vecteur d'initialisation
            
        Returns:
            bytes: Message déchiffré
        """
       # print("🔓 Déchiffrement AES du message...")
        
        # Création du cipher AES en mode CBC
        cipher = Cipher(
            algorithms.AES(cle_aes),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        # Déchiffrement
        decryptor = cipher.decryptor()
        message_padded = decryptor.update(message_chiffre) + decryptor.finalize()
        
        # Suppression du padding PKCS7
        def _unpad_message(message):
            pad_length = message[-1]
            return message[:-pad_length]
        
        message_dechiffre = _unpad_message(message_padded)
        
        print("✅ Message déchiffré avec AES avec succès")
        return message_dechiffre
    
    def _serialiser_cle_publique(self):
        """📤 Sérialisation de la clé publique pour l'envoi"""
        return self.cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def _demarrer_serveur(self):
        """🚀 Démarrage du serveur socket"""
        try:
            self.socket_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket_serveur.bind((self.host, self.port))
            self.socket_serveur.listen(5)
            
            print(f"🌐 Serveur initialisé sur {self.host}:{self.port}")
            print("📡 Serveur en écoute...")
           # print("🔄 Support du chiffrement hybride (RSA + AES)")
            print(" En attente de connexions clients...")
            print("-" * 60)
            
        except Exception as e:
            print(f"❌ Erreur lors du démarrage du serveur: {e}")
            return False
        return True
    
    def _traiter_client(self, socket_client, adresse_client):
        """
        🔄 Traitement d'un client connecté avec déchiffrement hybride
        
        Args:
            socket_client: Socket du client connecté
            adresse_client: Adresse du client
        """
        try:
            print(f"🔗 Nouvelle connexion de {adresse_client[0]}:{adresse_client[1]}")
            
            # Envoi de la clé publique du serveur au client
            cle_publique_serialisee = self._serialiser_cle_publique()
            socket_client.send(cle_publique_serialisee)
           # print("📤 Clé publique envoyée au client")
            
            # Réception du paquet sécurisé hybride du client
            #print("📥 Réception du message chiffré hybride...")
            donnees_recues = socket_client.recv(8192)  # Taille augmentée pour le paquet hybride
            
            if donnees_recues:
                # Désérialisation du paquet hybride
                paquet = pickle.loads(donnees_recues)
                message_chiffre_aes = paquet['message_chiffre_aes']
                cle_aes_chiffree = paquet['cle_aes_chiffree']
                iv = paquet['iv']
                signature = paquet['signature']
                cle_publique_client_pem = paquet['cle_publique_client']
                
                print("🔄 Déchiffrement  en cours...")
                
                # Étape 1: Déchiffrement de la clé AES avec RSA
                cle_aes = self._dechiffrer_cle_aes_rsa(cle_aes_chiffree)
                
                # Étape 2: Déchiffrement du message avec AES
                message_dechiffre = self._dechiffrer_aes(message_chiffre_aes, cle_aes, iv)
                
                # Reconstruction de la clé publique du client
                cle_publique_client = serialization.load_pem_public_key(
                    cle_publique_client_pem,
                    backend=default_backend()
                )
                
               # print("✅ Message déchiffré avec succès (hybride)")
                print("Vérification de la signature numérique...")
                
                # Vérification de la signature
                try:
                    cle_publique_client.verify(
                        signature,
                        message_dechiffre,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    # Si la signature est valide, on affiche le message déchiffré
                    print("MESSAGE REÇU ET VÉRIFIÉ  !🎉 ")
                    print("=" * 70)
                    print(f"📨 Message déchiffré: {message_dechiffre.decode('utf-8')}")
                    print("✅ Signature numérique VALIDE✅")
               
                    
                except InvalidSignature:
                    print("❌ ERREUR: Signature numérique invalide!")
                    print("⚠️  Le message pourrait avoir été altéré")
            
        except Exception as e:
            print(f"❌ Erreur lors du traitement du client: {e}")
        
        finally:
            socket_client.close()
            print(f"🔌 Connexion fermée avec {adresse_client[0]}:{adresse_client[1]}")
            print("-" * 60)
    
    def demarrer(self):
        """🎯 Démarrage principal du serveur"""
        print("🔐 Système de Communication Sécurisée ")
        print("=" * 60)
        print("Démarrage du serveur...")
        
        # Génération des clés RSA
        self._generer_cles_rsa()
        
        # Démarrage du serveur
        if not self._demarrer_serveur():
            return
        
        try:
            # Boucle principale d'écoute
            while True:
                socket_client, adresse_client = self.socket_serveur.accept()
                
                # Traitement du client dans un thread séparé
                thread_client = threading.Thread(
                    target=self._traiter_client,
                    args=(socket_client, adresse_client)
                )
                thread_client.daemon = True
                thread_client.start()
                
        except KeyboardInterrupt:
            print("\n🛑 Arrêt du serveur demandé...")
        except Exception as e:
            print(f"❌ Erreur serveur: {e}")
        finally:
            if self.socket_serveur:
                self.socket_serveur.close()
            print(" Serveur arrêté")

if __name__ == "__main__":
    # Création et démarrage du serveur PGP
    serveur = ServeurPGP()
    serveur.demarrer()