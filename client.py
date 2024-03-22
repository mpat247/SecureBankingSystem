import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random

# Define the server host and port
HOST = 'localhost'  # Localhost
PORT = 4444

# Function to handle key distribution and authentication for the client
def perform_key_distribution_and_authentication(s):
    try:
        # Step 1: Client receives encrypted session key and decrypts it
        print("Step 1: Client receives encrypted session key and decrypts it")

        # Receive the encrypted session key from server
        encrypted_session_key = s.recv(1024)
        print(f"Received encrypted session key: {encrypted_session_key.hex()}")

        # Generate a temporary RSA key pair for session key decryption
        temp_key = RSA.generate(1024)
        cipher_rsa = PKCS1_OAEP.new(temp_key)

        # Decrypt the session key using the temporary private key
        session_key_decrypted = cipher_rsa.decrypt(encrypted_session_key)
        print(f"Decrypted session key: {session_key_decrypted.hex()}")

        # Step 2: Client generates nonce (Na) and sends it to server
        print("Step 2: Client generates nonce (Na) and sends it to server")

        # Generate nonce (Na) for client
        na = b"random_nonce"  # Replace with actual nonce generation
        print(f"Generated nonce Na: {na.hex()}")

        # Send the nonce (Na) to server
        s.send(na)
        print(f"Sent nonce Na to server: {na.hex()}")

        # Step 3: Client receives encrypted nonce (Nb) from server and decrypts it
        print("Step 3: Client receives encrypted nonce (Nb) from server and decrypts it")

        # Receive the encrypted nonce (Nb) from server
        encrypted_nb = s.recv(1024)
        print(f"Received encrypted nonce Nb: {encrypted_nb.hex()}")

        # Decrypt nonce (Nb) using session key
        cipher_aes = AES.new(session_key_decrypted, AES.MODE_ECB)
        nonce_nb_decrypted = unpad(cipher_aes.decrypt(encrypted_nb), AES.block_size)
        print(f"Decrypted nonce Nb by client: {nonce_nb_decrypted.hex()}")

        # Step 4: Client sends acknowledgment to server
        print("Step 4: Client sends acknowledgment to server")

        # Send acknowledgment message (not implemented in client)
        # print("Sent acknowledgment to server")

        # Continue with username/password authentication or other actions...
        # Rest of the code...

    except Exception as e:
        print("An error occurred:", str(e))

# Function to start the client
def client():
    try:
        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Connect to the server
            s.connect((HOST, PORT))

            # Receive server's public key
            server_public_key = s.recv(1024)
            print("Received server's public key")

            # Initialize RSA cipher with server's public key
            server_rsa_key = RSA.import_key(server_public_key)
            cipher_rsa = PKCS1_OAEP.new(server_rsa_key)

            # Generate RSA key pair for the client
            global client_key
            client_key = RSA.generate(1024)

            # Send client's public key to the server
            s.send(client_key.publickey().export_key())
            print("Sent client's public key to server")

            # Perform key distribution and authentication
            perform_key_distribution_and_authentication(s)

    except Exception as e:
        print("An error occurred:", str(e))

if __name__ == "__main__":
    # Create multiple client connections
    client()
