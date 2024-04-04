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
PORT = 5005

def register_user(username, password):
    # Initialize the default balance to 0 for new users
    default_balance = 0
    with open("users.txt", "a") as file:
        file.write(f"{username}|{password}|{default_balance}\n")
        return "Registration successful."

def login_user(username, password):
    with open("users.txt", "r") as file:
        for line in file:
            stored_username, stored_password, balance = line.strip().split('|')
            if stored_username == username and stored_password == password:
                # Returning balance along with success message
                return True, f"Login successful. Account balance: {balance}"
    return False, "Login failed. Invalid username or password."




def handle_client_connection(client_socket, client_address):
    exits = False
    msg=''

    while exits == False:
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

                # print(is_timestamp_valid(int(timestamp_c), get_timestamp()))
                # Check if the timestamp is valid
                print(not is_timestamp_valid(int(timestamp_c), get_timestamp()))
                if not is_timestamp_valid(int(timestamp_c), get_timestamp()):
                    print("Invalid timestamp received from client.")
                    logger.info("Invalid timestamp received from client.")
                    return False

                nonce_s = generate_nonce()
                print("Nonce generated:", nonce_s)
                timestamp_s = str(get_timestamp()).encode()
                print("Timestamp encoded:", timestamp_s)

                # Concatenate nonce and timestamp, and then encode to bytes
                nonce_timestamp = f"{nonce_s}|{timestamp_s.decode()}|{nonce_c}"
                print("Combined nonce and timestamp and client nonce:", nonce_timestamp)
                nonce_timestamp_bytes = nonce_timestamp.encode()
                print("Combined nonce and timestamp and client nonce encoded:", nonce_timestamp_bytes)

                # Encrypt the nonce and timestamp using AES
                encrypted_nonce_timestamp = aes_encrypt(shared_key, nonce_timestamp_bytes)
                print("Encrypted nonce and timestamp client nonce:", encrypted_nonce_timestamp)

                # Send encrypted nonce and timestamp to server
                client_socket.sendall(encrypted_nonce_timestamp)
                print("Encrypted nonce and timestamp sent to Client.")


                # Receive nonce and timestamp from client
                encrypted_nonce_timestamp2 = client_socket.recv(1024)
                print("Received encrypted nonce2 and timestamp2 from client.")

                decrypted_nonce_timestamp2 = aes_decrypt(shared_key, encrypted_nonce_timestamp2)
                print("Decrypted nonce2 and timestamp2 from client.")

                nonce_c2, timestamp_c2, nonce_s_returned = map(int, decrypted_nonce_timestamp2.split(b"|"))
                print(type(nonce_c2))
                print("Received nonce_c2:", nonce_c2)
                print("Received timestamp_c2:", timestamp_c2)
                print("Received nonce_s:", nonce_s_returned)

                # print(is_timestamp_valid(int(timestamp_c), get_timestamp()))
                # Check if the timestamp is valid
                print(not is_timestamp_valid(int(timestamp_c2), get_timestamp()))
                print((nonce_s != nonce_s_returned) or not is_timestamp_valid(int(timestamp_c), get_timestamp()))
                if (nonce_s != nonce_s_returned) or not is_timestamp_valid(int(timestamp_c), get_timestamp()):
                    print("Invalid timestamp received from client.")
                    logger.info("Invalid timestamp received from client.")
                    return False
                
                # MASTER SECRET
                
                timestamp_secret = str(get_timestamp()).encode()
                server_nonce_secret = generate_nonce()
                master_secret = generate_master_secret(shared_key, nonce_c2, server_nonce_secret, timestamp_secret)
                print(type(master_secret))
                print("Master secret: ", master_secret)
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
                print("Encrypted Master Secret Sent to Client")


                enc_key, mac_key = derive_keys_from_master_secret(master_secret)
                print(f'Enc Key: {enc_key}')
                print(f'Mac Key: {mac_key}')

                if not enc_key or not mac_key:
                    logger.error("Authentication failed.")
                    msg= "Authentication failed. Client disconnected"
                    exits = True
                    client_socket.close()
                else:
                    logger.info("Authentication Successful and Keys Retrieved.") 
                    

                    def userLogic():
                        login_credentials = client_socket.recv(1024).decode()
                        action, username, password = login_credentials.split('|', 2)
                        if action.lower() == 'r':
                            print("Intiating registration")
                            login_response = register_user(username, password)
                            print('Registration successful')
                            client_socket.sendall(login_response.encode())                             
                            userLogic()
                        elif action.lower() == 'l':
                            print('Initiating Login"')
                            success, login_response = login_user(username, password)
                            print("Login successful")
                            client_socket.sendall(login_response.encode())                             
                        else:
                            print('unknown command')
                            login_response = "Unknown command."
                            client_socket.sendall(login_response.encode()) 
                            userLogic()

                        return True

                    loginSuccess = userLogic()

                    if not loginSuccess:
                        logger.error("Login failed.")
                        msg= "Login failed. Client disconnected"
                        exits = True
                        client_socket.close()
                    else:
                        pass



                exits = True 
                # AUTHENTICATION COMPLETED  
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