import os
import random
import socket
import logging
import colorlog
from generateKeys import generate_rsa_keys, save_private_key, save_public_key, remove_keys
from CryptoUtils import *
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
PORT = 5000

def client_operation():
    clientID = f'ATMClient_{random.randint(1000, 9999)}'
    logger.info(f"Starting client with ID {clientID}")
    nonceC1 = generate_nonce()
    # Generate and save RSA keys for this client session
    private_key, public_key = generate_rsa_keys()
    save_private_key(private_key, f'keys/{clientID}_private_key.pem')
    save_public_key(public_key, f'keys/{clientID}_public_key.pem')
    logger.info("Client keys generated and saved.")

    try:
        while True:
            with socket.create_connection((HOST, PORT)) as sock:
                logger.info("Connected to server.")
                message = f"Hello from {clientID}"
                sock.sendall(message.encode())
                logger.info("Message sent to server. Waiting for response...")
                serverID = sock.recv(1024)
                logger.info(f"Received response: {serverID.decode()}")


            # Input to continue or quit
            quit_command = input("Enter 'q' to quit or any other key to continue: ").strip().lower()
            if quit_command == 'q':
                break
    finally:
        # Remove keys before exiting
        remove_keys(clientID)
        logger.info("Client keys removed. Exiting.")

if __name__ == "__main__":
    try:
        client_operation()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        logger.info("Interrupt received, shutting down...")
        sys.exit(0)
