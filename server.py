import socket
import threading
import logging
from CryptoUtils import rsa_decrypt, aes_encrypt, aes_decrypt, generate_nonce, hkdf, deserialize_public_key, load_private_key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

HOST = 'localhost'
PORT = 4444

class ClientHandler(threading.Thread):
    def __init__(self, client_socket, client_address, server_private_key):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.server_private_key = server_private_key

    def run(self):
        logging.info(f"Handling client connection from {self.client_address}")
        try:
            # Receive and RSA decrypt the initial message
            encrypted_message = self.client_socket.recv(1024)
            plaintext_message = rsa_decrypt(encrypted_message, self.server_private_key)
            logging.info(f"Decrypted RSA message from {self.client_address}: {plaintext_message}")

            # Extract client nonce from the decrypted message
            nonce_client = plaintext_message
            logging.info(f"Nonce received from client {self.client_address}: {nonce_client.hex()}")

            # Generate server nonce and master secret
            nonce_server = generate_nonce()
            master_secret = hkdf(nonce_client + nonce_server)
            logging.info(f"Generated server nonce for {self.client_address}: {nonce_server.hex()}")
            logging.info(f"Generated master secret for {self.client_address}: {master_secret.hex()}")

            # Encrypt and send server nonce using AES encryption
            encrypted_nonce_server = aes_encrypt(nonce_server)
            self.client_socket.sendall(encrypted_nonce_server)
            logging.info(f"Sent encrypted server nonce to {self.client_address}")

            # Wait for further AES encrypted communication (Example)
            encrypted_msg = self.client_socket.recv(1024)
            try:
                msg = aes_decrypt(encrypted_msg).decode('utf-8')
                logging.info(f"Received AES encrypted message from {self.client_address}: {msg}")
                response = "Acknowledged".encode('utf-8')
                encrypted_response = aes_encrypt(response)
                self.client_socket.sendall(encrypted_response)
                logging.info(f"Sent AES encrypted response to {self.client_address}")
            except UnicodeDecodeError:
                logging.error("Error decoding message. Data may not be valid UTF-8.")

        except Exception as e:
            logging.error(f"An error occurred with {self.client_address}: {e}")
        finally:
            self.client_socket.close()

class BankServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_private_key = load_private_key('server_private_key.pem')

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            logging.info(f"Server is listening on {self.host}:{self.port}")
            try:
                while True:
                    client_socket, client_address = server_socket.accept()
                    handler = ClientHandler(client_socket, client_address, self.server_private_key)
                    handler.start()
            except KeyboardInterrupt:
                logging.info("Server is shutting down.")

if __name__ == "__main__":
    server = BankServer(HOST, PORT)
    server.start()
