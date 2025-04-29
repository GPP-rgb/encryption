# 🔐 Projet de Cryptographie Hybride : AES, RSA, SHA

Ce projet illustre des combinaisons de techniques de cryptographie symétrique, asymétrique et de hachage pour renforcer la sécurité des données. Il se base sur trois grandes familles d’algorithmes :  
- **AES (Advanced Encryption Standard)**  
- **RSA (Rivest–Shamir–Adleman)**  
- **SHA (Secure Hash Algorithm)**

## 📌 Objectif

Le but est de démontrer comment sécuriser un fichier ou des données sensibles en combinant :
- Le **chiffrement symétrique AES** pour l'efficacité sur les grandes données
- Le **chiffrement asymétrique RSA** pour sécuriser la transmission de la clé AES
- Le **hachage SHA** pour dériver des clés fiables à partir de mots de passe

---

## 📁 Contenu du dépôt

| Fichier                  | Description                                                            |
|--------------------------|------------------------------------------------------------------------|
| `aes_rsa.py`             | Implémente la combinaison AES + RSA                                    |
| `aes_sha.py`             | Implémente la combinaison AES + SHA                                    |
| `aes_rsa_sha.py`         | Implémente la combinaison complète AES + RSA + SHA                     |
| `example.txt`            | Exemple de fichier texte à chiffrer                                    |
| `README.md`              | Ce fichier de documentation                                            |

---

## 🔧 Prérequis

- Python 3.6+
- Bibliothèque `cryptography`

Installation :
```bash
pip install cryptography
