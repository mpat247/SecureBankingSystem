import os
import random
import socket
import logging
import colorlog
from tools import *
import sys

# Setup logging
logger = logging.getLogger('ClientLogger')
if not logger.handlers:
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

HOST = 'localhost'
PORT = 5003


def save_keys(sock, clientID):
    private_key, public_key = generate_rsa_keys()
    save_private_key(private_key, f'keys/{clientID}_private_key.pem')
    save_public_key(public_key, f'keys/{clientID}_public_key.pem')
    logger.info("Client keys generated and saved.")
    logger.info("Connected to server.")
    shared_key = get_random_bytes(16)
    logger.info(f'Shared key with client: {clientID}: {shared_key}')
    save_shared_key(shared_key, 'keys/', f'{clientID}_shared_key.bin')
    message = f"{clientID}"
    sock.sendall(message.encode())
    logger.info("Message sent to server. Waiting for response...")
    serverID = sock.recv(1024)
    logger.info(f"Received response: {serverID.decode()}")
    return private_key, public_key, serverID.decode(), shared_key

def client_operation():
    clientID = f'ATMClient_{random.randint(1000, 9999)}'
    logger.info(f"Starting client with ID {clientID}")
    # Generate and save RSA keys for this client session


    try:
        while True:
            with socket.create_connection((HOST, PORT)) as sock:
                # intial connection and saving keys
                private_key, public_key, serverID, shared_key = save_keys(sock, clientID)
                print(private_key, public_key, shared_key)
                print(serverID)
                try:
                    # Print socket and shared key for debugging
                    print("Socket:", sock)
                    print("Shared key:", shared_key)

                    # Generate nonce and timestamp
                    nonce_c = generate_nonce()
                    print("Nonce generated:", nonce_c)
                    timestamp_c = str(get_timestamp()).encode()
                    print("Timestamp encoded:", timestamp_c)

                    # Concatenate nonce and timestamp, and then encode to bytes
                    nonce_timestamp = f"{nonce_c}|{timestamp_c.decode()}"
                    print("Combined nonce and timestamp:", nonce_timestamp)
                    nonce_timestamp_bytes = nonce_timestamp.encode()
                    print("Combined nonce and timestamp encoded:", nonce_timestamp_bytes)

                    # Encrypt the nonce and timestamp using AES
                    encrypted_nonce_timestamp = aes_encrypt(shared_key, nonce_timestamp_bytes)
                    print("Encrypted nonce and timestamp:", encrypted_nonce_timestamp)

                    # Send encrypted nonce and timestamp to server
                    sock.sendall(encrypted_nonce_timestamp)
                    print("Encrypted nonce and timestamp sent to server.")

                    # Receive server's response
                    encrypted_response = sock.recv(1024)
                    print("Received encrypted response from server.")

                    # Decrypt the response
                    decrypted_response = aes_decrypt(shared_key, encrypted_response)
                    decoded_response = decrypted_response.decode()  # Decode the decrypted response
                    nonce_c_received, nonce_s, timestamp_s = decoded_response.split("|")  # Split the decoded response into its variables

                    # Check if received nonce and timestamp are valid
                    if nonce_c != nonce_c_received or not is_timestamp_valid(int(timestamp_s), get_timestamp()):
                        print("Nonce or timestamp invalid in server's response.")
                        return False

                    # Generate new nonce and timestamp to send back to server
                    nonce_c2 = generate_nonce()
                    timestamp_c2 = str(get_timestamp()).encode()
                    encrypted_final = aes_encrypt(shared_key, f"{nonce_s}|{nonce_c2}|{timestamp_c2}")

                    # Send encrypted final response to server
                    sock.sendall(encrypted_final)
                    print("Encrypted final response sent to server.")

                    # Receive server's final response
                    encrypted_final_response = sock.recv(1024)
                    print("Received encrypted final response from server.")

                    # Decrypt the final response
                    decrypted_final_response = aes_decrypt(shared_key, encrypted_final_response)
                    decoded_final_response = decrypted_final_response.decode()  # Decode the final response
                    nonce_c2_received, timestamp_s2 = decoded_final_response.split("|")  # Split the final response into its variables

                    # Check if received new nonce is valid
                    if nonce_c2 != nonce_c2_received or not is_timestamp_valid(int(timestamp_s2), get_timestamp()):
                        print("Nonce or timestamp invalid in server's final response.")
                        return False

                    print("Server authenticated successfully.")
                    raise Exception("Initial verification failed")
                except Exception as e:
                    print("Error:", e)

            # Input to continue or quit
            quit_command = input("Enter 'q' to quit or any other key to continue: ").strip().lower()
            if quit_command == 'q':
                break
    finally:
        # Remove keys before exiting
        remove_keys(clientID)
        remove_shared_key(clientID)
        logger.info("Client keys removed. Exiting.")

if __name__ == "__main__":
    try:
        client_operation()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        logger.info("Interrupt received, shutting down...")
        sys.exit(0)
