import os
import random
import socket
import logging
import colorlog
from threading import Thread
from generateKeys import generate_rsa_keys, save_private_key, save_public_key, remove_keys
import atexit
import signal
import sys

# Setup logging
logger = logging.getLogger('ServerLogger')
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

def handle_client_connection(client_socket, client_address):
    try:
        client_id = client_socket.recv(1024).decode()
        if client_id:
            logger.info(f"Message from {client_address}: {client_id}")
            response_message = serverID
            client_socket.sendall(response_message.encode())


    except Exception as e:
        logger.error(f"Error from {client_address}: {e}")
    finally:
        logger.info(f"Client {client_address} disconnected")
        client_socket.close()

def cleanup_server_keys(serverID, server_socket):

    server_socket.close()

def shutdown_signal_handler(signal, frame):
    global serverID
    global server_socket
    logger.info("Shutdown signal received. Cleaning up...")
    cleanup_server_keys(serverID, server_socket)
    sys.exit(0)

server_socket = None
serverID = None

def start_server():
    global serverID
    global server_socket
    serverID = f'BankServer{random.randint(1000, 9999)}'
    serverPublicKey, serverPrivateKey = generate_rsa_keys(flag=True)
    save_private_key(serverPrivateKey, f'keys/{serverID}_private_key.pem')
    save_public_key(serverPublicKey, f'keys/{serverID}_public_key.pem')
    logger.info(f'Server ID: {serverID} - Keys generated.')

    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_signal_handler)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    logger.info(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            logger.info(f"Client {client_address} connected")
            client_handler = Thread(target=handle_client_connection, args=(client_socket, client_address))
            client_handler.start()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down server...")
        cleanup_server_keys(serverID, server_socket)
    finally:
        if server_socket:
            server_socket.close()
        logger.info("Server shutdown")

if __name__ == "__main__":
    start_server()
