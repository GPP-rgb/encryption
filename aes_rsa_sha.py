import os, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def hash_password(password):
    return hashlib.sha256(password.encode()).digest()

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_aes_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_file(data, aes_key):
    iv = os.urandom(16)
    padding_length = 16 - len(data) % 16
    data += bytes([padding_length]) * padding_length
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def decrypt_file(encrypted_data, aes_key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

# Exemple
password = "monMotDePasseComplexe"
data = b"Contenu confidentiel à chiffrer"

aes_key = hash_password(password)
private_key, public_key = generate_rsa_keypair()
encrypted_key = encrypt_aes_key(aes_key, public_key)
encrypted_data = encrypt_file(data, aes_key)

recovered_key = decrypt_aes_key(encrypted_key, private_key)
decrypted_data = decrypt_file(encrypted_data, recovered_key)
print(decrypted_data)
