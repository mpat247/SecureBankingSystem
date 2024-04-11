import hmac
import os
import random
import time
import glob
from datetime import datetime, timedelta

from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import logging
import colorlog
import hashlib
import base64

# Setup logging
logger = logging.getLogger('ToolsLogger')
logger.setLevel(logging.INFO)
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s[%(levelname)s]: %(message)s',
    log_colors={
        'INFO': 'cyan',
        'ERROR': 'red',
        'DEBUG': 'green',
    }
))
logger.addHandler(handler)

# Assuming we are using AES-256 for encryption
AES_KEY_SIZE = 16
AES_BLOCK_SIZE = 16


# Function for AES encryption
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

# Function for AES decryption in ECB mode
def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES_BLOCK_SIZE)
    return plaintext

# ADD CBC MODE

def aes_encrypt_cbc(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    encrypted_data = base64.b64encode(iv + ct_bytes).decode('utf-8')
    return encrypted_data

def aes_decrypt_cbc(key, encrypted_data_b64):
    iv_ciphertext = base64.b64decode(encrypted_data_b64)
    iv = iv_ciphertext[:AES.block_size]
    ct_bytes = iv_ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ct_bytes), AES.block_size).decode('utf-8')
    return plaintext

def generate_aes_key():
    return get_random_bytes(16)

def generate_nonce():
    return random.randint(1000, 9999)

def get_timestamp():
    return int(time.time())

def is_timestamp_valid(sent_timestamp, current_timestamp, window=100):
    # Allow a 10-second window for the message to be valid
    # print(abs(current_timestamp - sent_timestamp) <= window)
    return abs(current_timestamp - sent_timestamp) <= window

def save_shared_key(key, folder_path, file_name):
   
    # Create the folder if it doesn't exist
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Concatenate the folder path and file name to create the full file path
    file_path = os.path.join(folder_path, file_name)

    # Write the key to the file
    with open(file_path, 'wb') as key_file:
        key_file.write(key)

    return file_path

def remove_shared_key(id):
    path = f'keys/{id}_shared_key.bin'
    try:
        os.remove(path)
        logger.info(f"Removed Shared Key with Client: {id} at this path: {path}")
    except FileNotFoundError:
        logger.error(f"Key file not found: {path}")

def retrieve_aes_key_from_file(aes_key_file_path):

    try:
        print(aes_key_file_path)
        with open(aes_key_file_path, 'rb') as key_file:
            aes_key = key_file.read()
            print(len(aes_key))
            if len(aes_key) != AES_KEY_SIZE:
                logger.error(f"Incorrect AES key length: {len(aes_key)} bytes. Expected {AES_KEY_SIZE} bytes.")
                return None
        return aes_key
    except FileNotFoundError:
        logger.error(f"AES key file '{aes_key_file_path}' not found.")
        return None
    except Exception as e:
        logger.error(f"Error while retrieving AES key: {e}")
        return None
    
def generate_master_secret(shared_key, client_nonce, server_nonce, timestamp):
    master_secret_input = f"{shared_key}{client_nonce}{server_nonce}{timestamp}".encode()
    master_secret = hashlib.sha256(master_secret_input).digest()
    return master_secret

def derive_keys_from_master_secret(master_secret):
    enc_key_input = f"enc{master_secret}".encode()
    enc_key = hashlib.sha256(enc_key_input).digest()

    mac_key_input = f"mac{master_secret}".encode()
    mac_key = hashlib.sha256(mac_key_input).digest()

    return enc_key, mac_key

def hash_password(password):
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    print(hashed_pw)
    return hashed_pw

def verify_password(hashed_password, provided_password):
    return hash_password(provided_password) == hashed_password

def generate_mac(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).digest()

def verify_mac(message, received_mac_b64, secret_key):
    received_mac = base64.b64decode(received_mac_b64)
    return hmac.compare_digest(hmac.new(secret_key, message.encode(), hashlib.sha256).digest(), received_mac)

def is_timestamp_fresh(timestamp, allowed_delay=300):
    # Check if the timestamp is within the allowed_delay seconds from current time
    current_timestamp = int(time.time())
    message_timestamp = int(timestamp)
    return abs(current_timestamp - message_timestamp) <= allowed_delay

