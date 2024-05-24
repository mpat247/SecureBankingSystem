# utils.py

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, serialization
import os
import hashlib

class CryptoUtils:
    @staticmethod
    def load_dh_parameters():
        with open("dh_parameters.pem", "rb") as f:
            parameters = serialization.load_pem_parameters(f.read(), backend=default_backend())
        return parameters

    @staticmethod
    def generate_keys(parameters):
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_keys(shared_secret):
        enc_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

        mac_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

        return enc_key, mac_key

    @staticmethod
    def encrypt(message, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    @staticmethod
    def decrypt(ciphertext, key):
        try:
            iv = ciphertext[:16]
            tag = ciphertext[16:32]
            enc_message = ciphertext[32:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            message = decryptor.update(enc_message) + decryptor.finalize()
            return message.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    @staticmethod
    def generate_mac(message, key):
        h = hmac.HMAC(key, SHA256(), backend=default_backend())
        h.update(message)
        return h.finalize()

    @staticmethod
    def verify_mac(message, received_mac, key):
        h = hmac.HMAC(key, SHA256(), backend=default_backend())
        h.update(message)
        try:
            h.verify(received_mac)
            return True
        except:
            return False

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def encrypt_log(log, key):
        return CryptoUtils.encrypt(log, key)

    @staticmethod
    def decrypt_log(encrypted_log, key):
        return CryptoUtils.decrypt(encrypted_log, key)
