from Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import secrets

AES_KEY = key_bytes = bytes.fromhex("b0d3e7e14b0f6f4e78231f45a8c1d9af")


def generate_rsa_keys():
    """
    Generate an RSA private/public key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def save_key_to_file(key, filename):
    """
    Save the RSA key to a file. Adjusts based on whether the key is public or private.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif isinstance(key, rsa.RSAPublicKey):
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise ValueError("Key must be an RSA public or private key")

    with open(filename, 'wb') as pem_file:
        pem_file.write(pem)

def load_private_key(filename):
    """
    Load an RSA private key from a file.
    """
    with open(filename, 'rb') as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def load_public_key(filename):
    """
    Load an RSA public key from a file.
    """
    with open(filename, 'rb') as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

def rsa_encrypt(message, public_key):
    """
    Encrypt a message using an RSA public key.
    """
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(ciphertext, private_key):
    """
    Decrypt a message using an RSA private key.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def generate_nonce(length=16):
    """
    Generate a nonce.
    """
    return os.urandom(length)

def pad(data, block_size):
    """
    Pad the data using PKCS7 padding.
    """
    pad_length = block_size - len(data) % block_size
    return data + bytes([pad_length] * pad_length)

def unpad(data, block_size):
    """
    Unpad the data using PKCS7 padding.
    """
    pad_length = data[-1]
    if pad_length < 1 or pad_length > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_length:] != bytes([pad_length] * pad_length):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_length]

def aes_encrypt(data):
    """
    Encrypts data using the pre-shared AES key.
    """
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

def aes_decrypt(encrypted_data):
    """
    Decrypts data using the pre-shared AES key.
    """
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data


def hkdf(input_key_material, length=32, salt=None):
    """
    Derive keys using HKDF.
    """
    if salt is None:
        salt = secrets.token_bytes(16)  # Using secrets for cryptographically secure salt generation.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(input_key_material)


def deserialize_public_key(pem):
    """
    Deserialize a public key from PEM format to a public key object.
    """
    return serialization.load_pem_public_key(
        pem,
        backend=default_backend()
    )

# Inside CryptoUtils.py
def generate_and_save_rsa_keys():
    private_key, public_key = generate_rsa_keys()
    save_key_to_file(private_key, "server_private_key.pem")
    save_key_to_file(public_key, "server_public_key.pem")

if __name__ == "__main__":
    generate_and_save_rsa_keys()