import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random

# Define the server host and port
HOST = 'localhost'  # Localhost
PORT = 4444

# Global variable to store client IDs
client_id_counter = 0
client_ids = {}

# Global variable to store the server's RSA key pair
server_key = RSA.generate(1024)
server_public_key = server_key.publickey().export_key()

# Function to check user credentials from the text file
def check_credentials(username, password, filename):
    with open(filename, 'r') as file:
        for line in file:
            stored_username, stored_password = line.strip().split(',')
            if stored_username == username and stored_password == password:
                return True
    return False

# Function to handle key distribution and authentication for a client
def perform_key_distribution_and_authentication(conn, addr):
    global client_ids, server_public_key

    # Generate a random 8-digit client ID
    client_id = random.randint(10000000, 99999999)

    # Assign ID to the current client
    client_ids[client_id] = conn

    print(f'Connected by {addr}, Client ID: {client_id}')

    # Step 1: Client identifies itself to the server
    print("Step 1: Client identifies itself to the server")

    # Step 2: Server sends its public key to client
    print("Step 2: Server sends its public key to client")

    # Send the server's public key to client
    conn.send(server_public_key)
    print("Server's public key sent to client")

    # Step 3: Client receives the encrypted session key and decrypts it
    print("Step 3: Client receives the encrypted session key and decrypts it")

    # Generate session key
    session_key = get_random_bytes(16)
    print(f"Generated session key: {session_key.hex()}")

    # Encrypt the session key with client's public key
    cipher_rsa = PKCS1_OAEP.new(server_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # Send the encrypted session key to client
    conn.send(encrypted_session_key)
    print("Encrypted session key sent to client")

    # Receive the encrypted session key from client
    encrypted_session_key_from_client = conn.recv(1024)

    # Decrypt the session key using server's private key
    session_key_decrypted = cipher_rsa.decrypt(encrypted_session_key_from_client)
    print(f"Decrypted session key by server: {session_key_decrypted.hex()}")

    # Step 4: Client and server exchange nonces
    print("Step 4: Client and server exchange nonces")

    # Generate nonce (Nb) for server
    nb = get_random_bytes(16)
    print(f"Generated nonce Nb: {nb.hex()}")

    # Encrypt nonce (Nb) using session key
    cipher_aes = AES.new(session_key_decrypted, AES.MODE_ECB)
    encrypted_nb = cipher_aes.encrypt(pad(nb, AES.block_size))
    print(f"Encrypted Nb: {encrypted_nb.hex()}")

    # Send the encrypted nonce (Nb) to client
    conn.send(encrypted_nb)
    print("Encrypted Nb sent to client")

    # Receive the encrypted nonce (Na) from client
    encrypted_na = conn.recv(1024)
    print(f"Received encrypted Na: {encrypted_na.hex()}")

    # Decrypt nonce (Na) using session key
    nonce_na_decrypted = unpad(cipher_aes.decrypt(encrypted_na), AES.block_size)
    print(f"Decrypted Na: {nonce_na_decrypted.hex()}")

    # Step 5: Server verifies the nonces and sends acknowledgment
    print("Step 5: Server verifies the nonces and sends acknowledgment")

    # Verify nonces match
    if nonce_na_decrypted == na:
        print("Nonces matched. Client authenticated successfully.")
        # Send acknowledgment
        ack_message = b"Acknowledgment"
        encrypted_ack = cipher_aes.encrypt(pad(ack_message, AES.block_size))
        print(f"Encrypted acknowledgment: {encrypted_ack.hex()}")
        conn.send(encrypted_ack)
        print("Encrypted acknowledgment sent to client")
    else:
        print("Nonces did not match. Authentication failed.")

    # Continue with username/password authentication or other actions...
    # Rest of the code...

# Function to handle client connections
def handle_client(conn, addr):
    perform_key_distribution_and_authentication(conn, addr)

    # Continue with further actions for authenticated clients...

# Function to start the server
def start_server():
    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind the socket to the address and port
        s.bind((HOST, PORT))

        # Listen for incoming connections
        s.listen()
        print(f'Server listening on {HOST}:{PORT}')

        # Accept incoming connections and handle them
        while True:
            # Accept a new connection
            conn, addr = s.accept()
            # Create a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    start_server()
