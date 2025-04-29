import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# === 1. Génération de la clé AES ===

def generate_aes_key(length=32):
    return os.urandom(length)

# === 2. Chiffrement AES d'un fichier ===

def encrypt_file_with_aes(input_file, output_file, aes_key):
    iv = os.urandom(16)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)  # On stocke IV + ciphertext ensemble

# === 3. Génération et sauvegarde des clés RSA ===

def generate_and_save_rsa_keypair(private_key_file, public_key_file):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Sauvegarder la clé privée
    with open(private_key_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Sauvegarder la clé publique
    with open(public_key_file, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# === 4. Chiffrement de la clé AES avec RSA ===

def encrypt_aes_key_with_rsa(aes_key, public_key_file, output_file):
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, 'wb') as f:
        f.write(encrypted_key)

# === 5. Déchiffrement de la clé AES avec RSA ===

def decrypt_aes_key_with_rsa(encrypted_key_file, private_key_file):
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    with open(encrypted_key_file, 'rb') as f:
        encrypted_key = f.read()

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# === 6. Déchiffrement du fichier AES ===

def decrypt_file_with_aes(encrypted_file, output_file, aes_key):
    with open(encrypted_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]

    with open(output_file, 'wb') as f:
        f.write(plaintext)

# === 7. Scénario complet ===

def main():
    # Fichiers
    original_file = 'example.txt'
    encrypted_file = 'data_encrypted.bin'
    decrypted_file = 'data_decrypted.txt'
    private_key_file = 'private_key.pem'
    public_key_file = 'public_key.pem'
    encrypted_key_file = 'aes_key_encrypted.bin'

    # 1. Générer la clé AES
    aes_key = generate_aes_key()

    # 2. Chiffrer le fichier original
    encrypt_file_with_aes(original_file, encrypted_file, aes_key)

    # 3. Générer et sauvegarder les clés RSA
    generate_and_save_rsa_keypair(private_key_file, public_key_file)

    # 4. Chiffrer la clé AES et sauvegarder
    encrypt_aes_key_with_rsa(aes_key, public_key_file, encrypted_key_file)

    print("[Info] Fichier chiffré et clé AES chiffrée sauvegardés.")

    # 5. Simulation réception : déchiffrer la clé AES
    recovered_aes_key = decrypt_aes_key_with_rsa(encrypted_key_file, private_key_file)

    # 6. Déchiffrer le fichier
    decrypt_file_with_aes(encrypted_file, decrypted_file, recovered_aes_key)

    # Vérification
    with open(original_file, 'rb') as f:
        original_data = f.read()
    with open(decrypted_file, 'rb') as f:
        decrypted_data = f.read()

    if original_data == decrypted_data:
        print("[Succès] Déchiffrement parfait : les données sont intactes.")
    else:
        print("[Erreur] Les données ne correspondent pas !")

if __name__ == "__main__":
    main()
