import os
import random
import time
import glob
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import logging
import colorlog

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

# Function for RSA encryption
# def rsa_encrypt(public_key, data):
#     cipher = PKCS1_OAEP.new(public_key)
#     return cipher.encrypt(data)

# # Function for RSA decryption
# def rsa_decrypt(private_key, encrypted_data):
#     cipher = PKCS1_OAEP.new(private_key)
#     return cipher.decrypt(encrypted_data)

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

# # Function to load RSA key from file
# def load_rsa_key(path):
#     with open(path, 'rb') as key_file:
#         key = RSA.import_key(key_file.read())
#     return key

# # Function to save RSA key to file
# def save_rsa_key(key, path):
#     with open(path, 'wb') as key_file:
#         key_file.write(key.export_key())

# Utility to generate a secure random AES key
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

# def generate_rsa_keys(flag=None):
#     if flag == True:
#         keys_folder_path = 'keys/'
#         key_files = glob.glob(f'{keys_folder_path}*.pem')

#         if len(key_files) == 2:
#             private_key_path = None
#             public_key_path = None

#             for file in key_files:
#                 if 'private' in file:
#                     private_key_path = file
#                 elif 'public' in file:
#                     public_key_path = file
#             if private_key_path and public_key_path:
#                 remove_keys(None, public_key_path, private_key_path)
#     key = RSA.generate(2048)
#     private_key = key.export_key()
#     public_key = key.publickey().export_key()
#     return private_key, public_key

# def save_private_key(private_key, filename):
#     with open(filename, 'wb') as pem_file:
#         pem_file.write(private_key)
#     logger.info(f"Private key saved to {filename}")

# def save_public_key(public_key, filename):
#     with open(filename, 'wb') as pem_file:
#         pem_file.write(public_key)
#     logger.info(f"Public key saved to {filename}")

def save_shared_key(key, folder_path, file_name):
    """
    Save a symmetric AES key to a file in the specified folder.

    Args:
        key (bytes): The AES key to be saved.
        folder_path (str): The path to the folder where the key will be saved.
        file_name (str): The name of the file to save the key to.

    Returns:
        str: The full path to the saved key file.
    """
    # Create the folder if it doesn't exist
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Concatenate the folder path and file name to create the full file path
    file_path = os.path.join(folder_path, file_name)

    # Write the key to the file
    with open(file_path, 'wb') as key_file:
        key_file.write(key)

    return file_path

# def remove_keys(id, publicKeyPath=None, privateKeyPath=None):
#     if publicKeyPath and privateKeyPath:
#         private_key_path = f'{privateKeyPath}'
#         public_key_path = f'{publicKeyPath}'

#         for path in [private_key_path, public_key_path]:
#             try:
#                 os.remove(path)
#                 logger.info(f"Removed key: {path}")
#             except FileNotFoundError:
#                 logger.error(f"Key file not found: {path}")
#     else:
#         private_key_path2 = f'keys/{id}_private_key.pem'
#         public_key_path2 = f'keys/{id}_public_key.pem'

#         for path in [private_key_path2, public_key_path2]:
#             try:
#                 os.remove(path)
#                 logger.info(f"Removed key: {path}")
#             except FileNotFoundError:
#                 logger.error(f"Key file not found: {path}")

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