import os
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import base64

# Define constants
SALT_SIZE = 16
IV_SIZE = 16
TAG_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 16
MAC_SIZE = 16

# Derive the key from the password and salt
def derive_key(password, salt):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, KEY_SIZE)
    return dk

# Encrypt the message using AES-GCM mode
def encrypt(key, message):
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return [cipher.nonce, tag, ciphertext]


# Decrypt the message using AES-GCM mode
def decrypt(encrypted_data, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=encrypted_data[:IV_SIZE])
    plaintext = cipher.decrypt_and_verify(encrypted_data[IV_SIZE+TAG_SIZE:], encrypted_data[IV_SIZE:IV_SIZE+TAG_SIZE])
    return plaintext.decode('utf-8')

