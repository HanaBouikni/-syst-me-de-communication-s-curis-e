#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur PGP - Communication sécurisée
=====================================
Ce programme implémente un serveur basé sur le modèle de sécurité PGP.
Il génère ses propres clés RSA, écoute les connexions clients,
déchiffre les messages et vérifie les signatures numériques.
"""

import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import threading

class ServeurPGP:
    def __init__(self, host='localhost', port=8888):
        """
        Initialisation du serveur PGP
        
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
        
        print("✅ Clés RSA du serveur générées avec succès")
    
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
            
            print(f"🌐 Serveur PGP initialisé sur {self.host}:{self.port}")
            print("📡 Serveur PGP en écoute...")
            print("⏳ En attente de connexions clients...")
            print("-" * 60)
            
        except Exception as e:
            print(f"❌ Erreur lors du démarrage du serveur: {e}")
            return False
        return True
    
    def _traiter_client(self, socket_client, adresse_client):
        """
        🔄 Traitement d'un client connecté
        
        Args:
            socket_client: Socket du client connecté
            adresse_client: Adresse du client
        """
        try:
            print(f"🔗 Nouvelle connexion de {adresse_client[0]}:{adresse_client[1]}")
            
            # Envoi de la clé publique du serveur au client
            cle_publique_serialisee = self._serialiser_cle_publique()
            socket_client.send(cle_publique_serialisee)
            print("📤 Clé publique envoyée au client")
            
            # Réception du paquet sécurisé du client
            print("📥 Réception du message chiffré...")
            donnees_recues = socket_client.recv(4096)
            
            if donnees_recues:
                # Désérialisation du paquet
                paquet = pickle.loads(donnees_recues)
                message_chiffre = paquet['message_chiffre']
                signature = paquet['signature']
                cle_publique_client_pem = paquet['cle_publique_client']
                
                print("🔓 Déchiffrement du message...")
                
                # Déchiffrement du message avec la clé privée du serveur
                message_dechiffre = self.cle_privee.decrypt(
                    message_chiffre,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Reconstruction de la clé publique du client
                cle_publique_client = serialization.load_pem_public_key(
                    cle_publique_client_pem,
                    backend=default_backend()
                )
                
                print("✅ Message déchiffré avec succès")
                print("🔍 Vérification de la signature numérique...")
                
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
                    
                    # ✅ AFFICHAGE DU MESSAGE ET CONFIRMATION DANS LE SERVEUR
                    print("=" * 60)
                    print("🎉 MESSAGE REÇU ET VÉRIFIÉ !")
                    print("=" * 60)
                    print(f"📨 Message déchiffré: {message_dechiffre.decode('utf-8')}")
                    print("✅ Signature numérique VALIDE")
                    print("🔒 Message authentifié avec succès")
                    print("=" * 60)
                    
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
        print("🔐 Système de Communication Sécurisée PGP")
        print("=" * 50)
        print("🖥️  Démarrage du serveur...")
        
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
            print("👋 Serveur arrêté")

if __name__ == "__main__":
    # Création et démarrage du serveur PGP
    serveur = ServeurPGP()
    serveur.demarrer()