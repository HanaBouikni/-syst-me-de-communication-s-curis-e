#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client PGP - Communication sécurisée
====================================
Ce programme implémente un client basé sur le modèle de sécurité PGP.
Il génère ses propres clés RSA, chiffre et signe les messages,
puis les envoie de manière sécurisée au serveur.
"""

import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
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
        
        print("✅ Clés RSA du client générées avec succès")
    
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
            print("📥 Réception de la clé publique du serveur...")
            cle_publique_serveur_pem = socket_client.recv(1024)
            
            # Reconstruction de la clé publique du serveur
            self.cle_publique_serveur = serialization.load_pem_public_key(
                cle_publique_serveur_pem,
                backend=default_backend()
            )
            
            print("✅ Clé publique du serveur reçue et chargée")
            
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
        print("✍️ Signature numérique du message...")
        
        signature = self.cle_privee.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print("✅ Message signé avec succès")
        return signature
    
    def _chiffrer_message(self, message):
        """
        🔒 Chiffrement du message avec la clé publique du serveur
        
        Args:
            message (bytes): Message à chiffrer
            
        Returns:
            bytes: Message chiffré
        """
        print("🔒 Chiffrement du message...")
        
        message_chiffre = self.cle_publique_serveur.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print("✅ Message chiffré avec succès")
        return message_chiffre
    
    def envoyer_message(self, message_texte):
        """
        📤 Envoi d'un message sécurisé au serveur
        
        Args:
            message_texte (str): Message à envoyer
        """
        print(f"📝 Préparation de l'envoi du message: '{message_texte}'")
        print("-" * 60)
        
        # Conversion du message en bytes
        message_bytes = message_texte.encode('utf-8')
        
        # Connexion au serveur
        socket_client = self._connecter_au_serveur()
        if not socket_client:
            return False
        
        try:
            # Signature numérique du message
            signature = self._signer_message(message_bytes)
            
            # Chiffrement du message
            message_chiffre = self._chiffrer_message(message_bytes)
            
            # Préparation du paquet sécurisé
            print("📦 Préparation du paquet sécurisé...")
            paquet_securise = {
                'message_chiffre': message_chiffre,
                'signature': signature,
                'cle_publique_client': self._serialiser_cle_publique()
            }
            
            # Envoi du paquet sécurisé au serveur
            print("📡 Envoi du paquet sécurisé au serveur...")
            donnees_a_envoyer = pickle.dumps(paquet_securise)
            socket_client.send(donnees_a_envoyer)
            
            print("✅ Message envoyé avec succès!")
            print("🔒 Le message a été:")
            print("   ✅ Signé numériquement (authenticité)")
            print("   ✅ Chiffré (confidentialité)")
            print("   ✅ Transmis de manière sécurisée")
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur lors de l'envoi: {e}")
            return False
        
        finally:
            socket_client.close()
            print("🔌 Connexion fermée")
    
    def interface_utilisateur(self):
        """🎯 Interface utilisateur du client"""
        print("🔐 Client PGP - Communication Sécurisée")
        print("=" * 50)
        
        # Génération des clés du client
        self._generer_cles_rsa()
        
        print("\n⚡ Mode test rapide disponible!")
        print("Tapez 'test' pour envoyer un message de démonstration\n")
        
        while True:
            print("🌟 Que souhaitez-vous faire ?")
            print("1. Envoyer un message sécurisé")
            print("2. Quitter")
            
            choix = input("👉 Votre choix (1-2): ").strip()
            
            if choix == '1':
                message = input("📝 Entrez votre message: ").strip()
                if message:
                    if message.lower() == 'test':
                        message = "Hello, ceci est un message de test sécurisé!"
                        print(f"🚀 Envoi du message de test: '{message}'")
                    
                    succes = self.envoyer_message(message)
                    if succes:
                        print("🎉 Opération terminée avec succès!")
                    else:
                        print("❌ Échec de l'envoi du message")
                else:
                    print("⚠️  Message vide, veuillez réessayer")
                
                print("-" * 60)
                
            elif choix == '2':
                print("👋 Au revoir!")
                break
            else:
                print("❌ Choix invalide, veuillez réessayer")

if __name__ == "__main__":
    # Création et démarrage du client PGP
    client = ClientPGP()
    client.interface_utilisateur()