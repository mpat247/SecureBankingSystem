import os
import random

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Assuming we are using AES-256 for encryption
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16

# Function for RSA encryption
def rsa_encrypt(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

# Function for RSA decryption
def rsa_decrypt(private_key, encrypted_data):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)

# Function for AES encryption
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    iv = cipher.iv
    return iv + ct_bytes

# Function for AES decryption
def aes_decrypt(key, iv_and_ct):
    iv = iv_and_ct[:AES_BLOCK_SIZE]
    ct = iv_and_ct[AES_BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES_BLOCK_SIZE)

# Function to load RSA key from file
def load_rsa_key(path):
    with open(path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())
    return key

# Function to save RSA key to file
def save_rsa_key(key, path):
    with open(path, 'wb') as key_file:
        key_file.write(key.export_key())

# Utility to generate a secure random AES key
def generate_aes_key():
    return get_random_bytes(AES_KEY_SIZE)

def generate_nonce():
    return random.randint(1000, 9999)