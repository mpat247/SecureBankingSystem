from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

class CryptoUtils:
    @staticmethod
    def rsa_encrypt(public_key, message):
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(message)
        return ciphertext

    @staticmethod
    def rsa_decrypt(private_key, ciphertext):
        cipher = PKCS1_OAEP.new(private_key)
        message = cipher.decrypt(ciphertext)
        return message

    @staticmethod
    def aes_encrypt(key, message):
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        return ciphertext

    @staticmethod
    def aes_decrypt(key, ciphertext):
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.rstrip(b"\0")  # Remove padding
