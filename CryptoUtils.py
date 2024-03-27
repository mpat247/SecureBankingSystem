from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import random
import hashlib

# Hard-coded AES key (16 bytes to fit AES-128 bit requirement)
AES_KEY = b'\x1a\xa5\x82\xd3\xf4\xc7\xae\x1f\x05)\x89\x9c\x2b\xf7\xe3\x80'

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()  # Export private key to bytes
    public_key = key.publickey().export_key()  # Export public key to bytes
    return private_key, public_key


def rsa_encrypt(public_key, data):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(private_key, encrypted_data):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)

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

def generate_nonce():
    """Generates a 4-digit string nonce."""
    return '{:04d}'.format(random.randint(0, 9999))

def generate_session_id():
    """Generates a unique session ID."""
    return 'Session{:04d}'.format(random.randint(0, 9999))

def hash_password(password, salt=""):
    """
    Hashes a password with an optional salt.
    In real applications, each user should have a unique salt stored alongside their hashed password.
    """
    # Concatenate the password and the salt (if any)
    password_salt_combo = password + salt

    # Create a new SHA-256 hash object
    hash_object = hashlib.sha256()

    # Update the hash object with the bytes of the password-salt combo
    hash_object.update(password_salt_combo.encode())

    # Return the hexadecimal representation of the digest
    return hash_object.hexdigest()

def check_password_hash(password, stored_hash, salt=""):
    """
    Checks a password against a stored hash with an optional salt.
    """
    # Hash the password with the same salt used when it was originally hashed
    password_hash = hash_password(password, salt)

    # Compare the newly hashed password with the stored hash
    return password_hash == stored_hash
