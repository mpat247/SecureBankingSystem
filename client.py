import socket
import logging
from CryptoUtils import rsa_encrypt, generate_nonce, hkdf, deserialize_public_key, aes_decrypt, aes_encrypt

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

HOST = 'localhost'
PORT = 4444


class BankClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        # Load the server's public key from file
        with open('server_public_key.pem', 'rb') as f:
            self.server_public_key = deserialize_public_key(f.read())

    def connect_to_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                # Connect to the server
                client_socket.connect((self.host, self.port))
                logging.info(f"Connected to server at {self.host}:{self.port}")

                # Encrypt and send client nonce using RSA
                nonce_client = generate_nonce()
                encrypted_message = rsa_encrypt(nonce_client, self.server_public_key)
                client_socket.sendall(encrypted_message)

                # Receive and decrypt the server's AES-encrypted response
                encrypted_reply = client_socket.recv(1024)

                # Derive master secret from client nonce
                master_secret = hkdf(nonce_client + b'some_predefined_or_agreed_value')
                aes_key = master_secret[:16]  # Derive AES key from master secret

                decrypted_reply = aes_decrypt(encrypted_reply)

                # Attempt to decode the reply as UTF-8 text if expected to be text
                try:
                    reply = decrypted_reply.decode('utf-8')
                    logging.info(f"Received from server: {reply}")
                except UnicodeDecodeError:
                    # Handle binary data or log error
                    logging.error("Received binary data, not decoding as text.")

            except Exception as e:
                logging.error(f"Failed to connect to server: {e}")


if __name__ == "__main__":
    client = BankClient(HOST, PORT)
    client.connect_to_server()
