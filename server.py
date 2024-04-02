import os
import random
import socket
import logging
import colorlog
from threading import Thread
from tools import *
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
            'INFO': 'green',
            'ERROR': 'red',
            'DEBUG': 'yellow',
        }
    ))
    logger.addHandler(handler)

HOST = 'localhost'
PORT = 5003

def handle_client_connection(client_socket, client_address):
    try:
        client_id = client_socket.recv(1024).decode()
        logger.info(f"Message from {client_address}: {client_id}")
        path = f'keys/{client_id}_shared_key.bin'

        shared_key = retrieve_aes_key_from_file(path)
        if (not(shared_key)):
            print(f'{shared_key} not found')

        print(f'Shared key: {shared_key}')
        response_message = serverID
        client_socket.sendall(response_message.encode())

        try:
            print("Initial verification process started for client.")

            # Receive nonce and timestamp from client
            encrypted_nonce_timestamp = client_socket.recv(1024)
            print("Received encrypted nonce and timestamp from client.")

            decrypted_nonce_timestamp = aes_decrypt(shared_key, encrypted_nonce_timestamp)
            print("Decrypted nonce and timestamp from client.")

            nonce_c, timestamp_c = map(int, decrypted_nonce_timestamp.split(b"|"))
            print(type(nonce_c))
            print("Received nonce_c:", nonce_c)
            print("Received timestamp_c:", timestamp_c)

            print(is_timestamp_valid(int(timestamp_c), get_timestamp()))
            # Check if the timestamp is valid
            if not is_timestamp_valid(int(timestamp_c), get_timestamp()):
                print("Invalid timestamp received from client.")
                logger.info("Invalid timestamp received from client.")
                return False

            # Send back the client's nonce, server's nonce, and timestamp
            nonce_s = get_random_bytes(16)
            timestamp_s = str(get_timestamp()).encode()
            response = aes_encrypt(shared_key, f"{nonce_c}|{nonce_s}|{timestamp_s}")
            client_socket.sendall(response)
            print("Sent response containing server's nonce to client.")

            # Wait for client's response with the server's nonce
            encrypted_final = client_socket.recv(1024)
            print("Received encrypted final response from client.")

            decrypted_final = aes_decrypt(shared_key, encrypted_final)
            print("Decrypted final response from client.")

            nonce_s_received, nonce_c2, timestamp_c2 = decrypted_final.split(b"|")
            print("Received nonce_s_received:", nonce_s_received)
            print("Received nonce_c2:", nonce_c2)
            print("Received timestamp_c2:", timestamp_c2)

            # Final check
            if nonce_s != nonce_s_received or not is_timestamp_valid(int(timestamp_c2), get_timestamp()):
                print("Nonce or timestamp invalid in client's final response.")
                logger.info("Nonce or timestamp invalid in client's final response.")
                return False

            print("Client authenticated successfully.")
            logger.info("Client authenticated successfully.")  
        except Exception as e:
            raise Exception("Initial verification failed")





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
def save_server_keys(serverID):
    serverPrivateKey, serverPublicKey = generate_rsa_keys(flag=True)
    save_private_key(serverPrivateKey, f'keys/{serverID}_private_key.pem')
    save_public_key(serverPublicKey, f'keys/{serverID}_public_key.pem')
    logger.info(f'Server ID: {serverID} - Keys generated.')
    return serverPrivateKey, serverPublicKey

def start_server():
    global serverID
    global server_socket
    serverID = f'BankServer{random.randint(1000, 9999)}'
    serverPrivateKey, serverPublicKey = save_server_keys(serverID)

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
