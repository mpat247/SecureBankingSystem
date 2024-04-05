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

def register_user(username, password):
    default_balance = 0
    hashed_password = hash_password(password)  # This should return a string
    print("Hashed password while registering: "+hashed_password)
    with open("users.txt", "a") as file:
        file.write(f"{username}|{hashed_password}|{default_balance}\n")
    return "Registration successful."






def login_user(username, password):
    print('Reached Login Function: Attempting to login user.')

    with open("users.txt", "r") as file:  # Ensure text mode
        for line in file:
            stored_username, stored_password, balance = line.strip().split('|')
            print(stored_username)
            print(stored_password)
            print(balance)
            if stored_username == username:
                print(f'User {username} found in database. Verifying password...')
                print(f'Stored Password: {stored_password}')
                print(f'Received Password: {password}')
                if verify_password(stored_password, password):
                    print(f'Password verification successful for user {username}.')
                    return True, f"Login successful. Account balance: {balance}"

                else:
                    print(f'Password verification failed for user {username}.')
                    return False, "Login failed. Invalid username or password."

    print(f'User {username} not found in database.')
    return False, "Login failed. Invalid username or password."



def initial_verification(shared_key, client_socket):
    logger.info("Initial verification process started for client.")

    # Receive nonce and timestamp from client
    encrypted_nonce_timestamp = client_socket.recv(1024)
    logger.info("Received encrypted nonce and timestamp from client.")

    decrypted_nonce_timestamp = aes_decrypt(shared_key, encrypted_nonce_timestamp)
    logger.info("Decrypted nonce and timestamp from client.")

    nonce_c, timestamp_c = map(int, decrypted_nonce_timestamp.split(b"|"))
    logger.info(type(nonce_c))
    logger.info(f"Received nonce_c: {nonce_c}")
    logger.info(f"Received timestamp_c:{timestamp_c}")

    # print(is_timestamp_valid(int(timestamp_c), get_timestamp()))
    # Check if the timestamp is valid
    logger.info(not is_timestamp_valid(int(timestamp_c), get_timestamp()))
    if not is_timestamp_valid(int(timestamp_c), get_timestamp()):
        logger.error("Invalid timestamp received from client.")
        return False

    nonce_s = generate_nonce()
    logger.info(f"Nonce generated:{nonce_s}")
    timestamp_s = str(get_timestamp()).encode()
    logger.info(f"Timestamp encoded:{timestamp_s}")

    # Concatenate nonce and timestamp, and then encode to bytes
    nonce_timestamp = f"{nonce_s}|{timestamp_s.decode()}|{nonce_c}"
    logger.info(f"Combined nonce and timestamp and client nonce:{nonce_timestamp}")
    nonce_timestamp_bytes = nonce_timestamp.encode()
    logger.info(f"Combined nonce and timestamp and client nonce encoded: {nonce_timestamp_bytes}")

    # Encrypt the nonce and timestamp using AES
    encrypted_nonce_timestamp = aes_encrypt(shared_key, nonce_timestamp_bytes)
    logger.info(f"Encrypted nonce and timestamp client nonce: {encrypted_nonce_timestamp}")

    # Send encrypted nonce and timestamp to server
    client_socket.sendall(encrypted_nonce_timestamp)
    logger.info("Encrypted nonce and timestamp sent to Client.")

    # Receive nonce and timestamp from client
    encrypted_nonce_timestamp2 = client_socket.recv(1024)
    logger.info("Received encrypted nonce2 and timestamp2 from client.")

    decrypted_nonce_timestamp2 = aes_decrypt(shared_key, encrypted_nonce_timestamp2)
    logger.info("Decrypted nonce2 and timestamp2 from client.")

    nonce_c2, timestamp_c2, nonce_s_returned = map(int, decrypted_nonce_timestamp2.split(b"|"))
    logger.info(type(nonce_c2))
    logger.info(f"Received nonce_c2: {nonce_c2}")
    logger.info(f"Received timestamp_c2: {timestamp_c2}")
    logger.info(f"Received nonce_s: {nonce_s_returned}")

    # print(is_timestamp_valid(int(timestamp_c), get_timestamp()))
    # Check if the timestamp is valid
    logger.info(not is_timestamp_valid(int(timestamp_c2), get_timestamp()))
    logger.info((nonce_s != nonce_s_returned) or not is_timestamp_valid(int(timestamp_c), get_timestamp()))
    if (nonce_s != nonce_s_returned) or not is_timestamp_valid(int(timestamp_c), get_timestamp()):
        logger.info("Invalid timestamp received from client.")
        logger.info("Invalid timestamp received from client.")
        return False

    # MASTER SECRET

    timestamp_secret = str(get_timestamp()).encode()
    server_nonce_secret = generate_nonce()
    master_secret = generate_master_secret(shared_key, nonce_c2, server_nonce_secret, timestamp_secret)
    logger.info(type(master_secret))
    logger.info(f"Master secret: {master_secret}")
    # timestamp_s3 = str(get_timestamp()).encode()
    # print("Timestamp encoded:", timestamp_s3)

    # # Concatenate nonce and timestamp, and then encode to bytes

    # secure_master_key = f"{nonce_c2}|{timestamp_s3.decode()}|{master_secret}"
    # print("Master Secret with nonce and time stamp:", secure_master_key)
    # secure_master_key_bytes = secure_master_key.encode()
    # print("Master Secret encoded:", secure_master_key_bytes)

    # # Encrypt the nonce and timestamp using AES
    # encrypted_master_secret = aes_encrypt(shared_key, secure_master_key_bytes)
    # print("Encrypted Master Secret",encrypted_master_secret)
    master_secret_encrypted = aes_encrypt(shared_key, master_secret)
    # Send encrypted nonce and timestamp to server
    client_socket.sendall(master_secret_encrypted)
    logger.info("Encrypted Master Secret Sent to Client")

    enc_key, mac_key = derive_keys_from_master_secret(master_secret)
    logger.info(f'Encryption Key: {enc_key}')
    logger.info(f'MAC Key: {mac_key}')

    return enc_key, mac_key

def handle_user_actions(client_socket, enc_key, mac_key):
    while True:
        try:
            user_action_encrypted = client_socket.recv(1024)
            if not user_action_encrypted:
                break

            user_action = aes_decrypt(enc_key, user_action_encrypted).decode('utf-8')
            action, username, password = user_action.split('|', 2)

            if action.lower() == 'r':
                response = register_user(username, password)
                logger.info("User registered successfully.")
            elif action.lower() == 'l':
                success, response = login_user(username, password)
                if success:
                    logger.info(f"User {username} logged in successfully.")
                else:
                    response = "Login failed. Try again."
            else:
                response = "Unknown command. Please try again."

            encrypted_response = aes_encrypt(enc_key, response.encode())  # Correct
            client_socket.sendall(encrypted_response)  # Send bytes directly
        except Exception as e:
            logger.error(f"Error handling user action: {e}")
            break




def handle_client_connection(client_socket, client_address):
    try:
        # Acknowledge the connection and retrieve the client ID
        client_id = client_socket.recv(1024).decode()
        logger.info(f"Message from {client_address}: {client_id}")

        # Retrieve the shared AES key based on the client ID
        path = f'keys/{client_id}_shared_key.bin'
        shared_key = retrieve_aes_key_from_file(path)
        if not shared_key:
            logger.error(f"Shared key for {client_id} not found. Client disconnected.")
            client_socket.close()
            return
        else:
            response_message = serverID  # Make sure serverID is defined somewhere in your server code
            client_socket.sendall(response_message.encode())
    # Send a response back to the client, indicating successful connection


        # Perform initial verification using the shared AES key
        enc_key, mac_key = initial_verification(shared_key, client_socket)
        if not enc_key or not mac_key:
            logger.error("Authentication failed. Client disconnected.")
            client_socket.close()
            return
        else:
            logger.info("Authentication Successful and Keys Retrieved.")
            handle_user_actions(client_socket, enc_key, mac_key)


    except Exception as e:
        logger.error(f"Error with client {client_address}: {e}")
    finally:
        client_socket.close()
        logger.info(f"Client {client_address} disconnected")



def cleanup_server_keys(serverID, server_socket):

    server_socket.close()

server_socket = None

# Signal handler function
def shutdown_signal_handler(signum, frame):
    global server_socket
    print("Shutdown signal received. Cleaning up...")
    if server_socket:
        server_socket.close()
    print("Server gracefully shutdown.")
    sys.exit(0)

serverID = None
# def save_server_keys(serverID):
#     serverPrivateKey, serverPublicKey = generate_rsa_keys(flag=True)
#     save_private_key(serverPrivateKey, f'keys/{serverID}_private_key.pem')
#     save_public_key(serverPublicKey, f'keys/{serverID}_public_key.pem')
#     logger.info(f'Server ID: {serverID} - Keys generated.')
#     return serverPrivateKey, serverPublicKey

def start_server():
    global serverID
    global server_socket
    serverID = f'BankServer{random.randint(1000, 9999)}'
    # serverPrivateKey, serverPublicKey = save_server_keys(serverID)

    # Register signal handler for graceful shutdown

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    logger.info(f"Server listening on {HOST}:{PORT}")
    signal.signal(signal.SIGINT, shutdown_signal_handler)


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