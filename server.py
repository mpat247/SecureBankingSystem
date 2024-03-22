import random
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Define the server host and port
HOST = 'localhost'  # Localhost
PORT = 4444

# Global variable to store client IDs
client_id_counter = 0
client_ids = {}

# Global variable to store the server's RSA key pair
server_key = RSA.generate(1024)

# Function to check user credentials from the text file
def check_credentials(username, password, filename):
    with open(filename, 'r') as file:
        for line in file:
            stored_username, stored_password = line.strip().split(',')
            if stored_username == username and stored_password == password:
                return True
    return False

# Function to handle key distribution and authentication for a client
def perform_key_distribution_and_authentication(conn):
    global client_ids

    # Generate a random 8-digit client ID
    client_id = random.randint(10000000, 99999999)

    # Assign ID to the current client
    client_ids[client_id] = conn

    print(f'Connected by {addr}, Client ID: {client_id}')

    # Step 1: Client identifies itself to the server
    print("Step 1: Client identifies itself to the server")

    # Step 2: Server generates a session key and sends it to client
    print("Step 2: Server generates a session key and sends it to client")

    # Generate session key
    session_key = get_random_bytes(16)
    print(f"Generated session key: {session_key.hex()}")

    # Encrypt the session key with client's public key
    cipher_rsa = PKCS1_OAEP.new(server_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # Send the encrypted session key to client
    conn.send(encrypted_session_key)
    print("Encrypted session key sent to client")

    # Step 3: Client receives the encrypted session key and decrypts it
    print("Step 3: Client receives the encrypted session key and decrypts it")

    # Receive the encrypted session key from server
    encrypted_session_key_from_server = conn.recv(1024)

    # Decrypt the session key using client's private key
    session_key_decrypted = cipher_rsa.decrypt(encrypted_session_key_from_server)
    print(f"Decrypted session key by client: {session_key_decrypted.hex()}")

    # Step 4: Client and server exchange nonces
    print("Step 4: Client and server exchange nonces")

    # Generate nonce (Na) for client
    na = get_random_bytes(16)
    print(f"Generated nonce Na: {na.hex()}")

    # Encrypt nonce (Na) using session key
    cipher_aes = AES.new(session_key_decrypted, AES.MODE_ECB)
    encrypted_na = cipher_aes.encrypt(pad(na, AES.block_size))
    print(f"Encrypted Na: {encrypted_na.hex()}")

    # Send the encrypted nonce (Na) to server
    conn.send(encrypted_na)
    print("Encrypted Na sent to server")

    # Receive the encrypted nonce (Nb) from server
    encrypted_nb = conn.recv(1024)
    print(f"Received encrypted Nb: {encrypted_nb.hex()}")

    # Decrypt nonce (Nb) using session key
    nonce_nb_decrypted = cipher_aes.decrypt(encrypted_nb)
    print(f"Decrypted Nb: {nonce_nb_decrypted.hex()}")

    # Step 5: Server verifies the nonces and sends acknowledgment
    print("Step 5: Server verifies the nonces and sends acknowledgment")

    # Encrypt acknowledgment using session key
    ack_message = b"Acknowledgment"
    encrypted_ack = cipher_aes.encrypt(pad(ack_message, AES.block_size))
    print(f"Encrypted acknowledgment: {encrypted_ack.hex()}")

    # Send the encrypted acknowledgment to client
    conn.send(encrypted_ack)
    print("Encrypted acknowledgment sent to client")

    # Continue with username/password authentication or other actions...

    # Rest of the code...

# Function to handle client connections
def handle_client(conn, addr):
    perform_key_distribution_and_authentication(conn)

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
            client_thread


if __name__ == "__main__":
    start_server()
