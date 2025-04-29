import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def hash_password_sha256(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_file_with_password(password, input_file, output_file):
    key = hash_password_sha256(password)
    iv = os.urandom(16)

    with open(input_file, 'rb') as f:
        plaintext = f.read()
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_file_with_password(password, input_file, output_file):
    key = hash_password_sha256(password)

    with open(input_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]

    with open(output_file, 'wb') as f:
        f.write(plaintext)
