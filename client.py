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
PORT = 5000


def save_keys(server_socket, clientID):
    # private_key, public_key = generate_rsa_keys()
    # save_private_key(private_key, f'keys/{clientID}_private_key.pem')
    # save_public_key(public_key, f'keys/{clientID}_public_key.pem')
    # logger.info("Client keys generated and saved.")
    logger.info("Connected to server.")
    shared_key = get_random_bytes(16)
    logger.info(f'Shared key with client: {clientID}: {shared_key}')
    save_shared_key(shared_key, 'keys/', f'{clientID}_shared_key.bin')
    message = f"{clientID}"
    server_socket.sendall(message.encode())
    logger.info("Message sent to server. Waiting for response...")
    serverID = server_socket.recv(1024)
    logger.info(f"Received response: {serverID.decode()}")
    return serverID.decode(), shared_key

def display_menu():
    choice = input("Would you like to login or register? 'L' for Login, 'R' for Registration: ").upper()
    if choice == 'L':
        return 'L'
    elif choice == 'R':
        return 'R'
    else:
        print("Invalid choice. Please select 'L' for Login or 'R' for Registration.")
        return display_menu()



def initial_verification(shared_key, server_socket):
    # Print socket and shared key for debugging
    print("Socket:", server_socket)
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
    server_socket.sendall(encrypted_nonce_timestamp)
    print("Encrypted nonce and timestamp sent to server.")

    # Receive nonce and timestamp from client
    encrypted_server_response = server_socket.recv(1024)
    print("Received encrypted nonce and timestamp from client.")

    decrypted_server_response = aes_decrypt(shared_key, encrypted_server_response)
    print("Decrypted nonce and timestamp from client.")

    nonce_s, timestamp_s, nonce_c_return = map(int, decrypted_server_response.split(b"|"))
    print(type(nonce_s))
    print("Received nonce_s:", nonce_s)
    print("Received timestamp_s:", timestamp_s)
    print("Received nonce_c:", nonce_c_return)

    # print(is_timestamp_valid(int(timestamp_c), get_timestamp()))
    # Check if the timestamp is valid
    # add nonce_c check
    print(not is_timestamp_valid(int(timestamp_s), get_timestamp()))
    print((nonce_c != nonce_c_return) or not is_timestamp_valid(int(timestamp_s), get_timestamp()))
    if (nonce_c != nonce_c_return) or not is_timestamp_valid(int(timestamp_s), get_timestamp()):
        logger.info("Invalid timestamp received from client or nonce not verified.")
        logger.info("Invalid timestamp received from client or nonce not verified.")
        return False

    #   logger.info("Server authenticated successfully.")

    # Generate nonce and timestamp
    nonce_c2 = generate_nonce()
    print("Nonce2 generated:", nonce_c2)
    timestamp_c2 = str(get_timestamp()).encode()
    print("Timestamp2 encoded:", timestamp_c)

    # Concatenate nonce and timestamp, and then encode to bytes
    nonce_timestamp2 = f"{nonce_c2}|{timestamp_c2.decode()}|{nonce_s}"
    print("Combined nonce2 and timestamp2 and server nonce:", nonce_timestamp2)
    nonce_timestamp_bytes2 = nonce_timestamp2.encode()
    print("Combined nonce2 and timestamp2 and server nonce encoded:", nonce_timestamp_bytes2)

    # Encrypt the nonce and timestamp using AES
    encrypted_nonce_timestamp2 = aes_encrypt(shared_key, nonce_timestamp_bytes2)
    print("Encrypted nonce2 and timestamp2:", encrypted_nonce_timestamp2)

    # Send encrypted nonce and timestamp to server
    server_socket.sendall(encrypted_nonce_timestamp2)
    print("Encrypted nonce2 and timestamp2 sent to server.")

    # MASTER SECRET

    # Receive master secret from client
    encrypted_master_secret = server_socket.recv(1024)
    print("Encrypted Master Secret from Server.", encrypted_master_secret)

    master_secret = aes_decrypt(shared_key, encrypted_master_secret)
    print("Decrypted Master Secret from Server.", master_secret)

    enc_key, mac_key = derive_keys_from_master_secret(master_secret)

    return enc_key, mac_key


def handle_user_actions(server_socket, enc_key, mac_key):
    while True:
        action = display_menu()
        print(action)# Prompts user for 'L' (login) or 'R' (registration)
        if action not in ['L', 'R']:
            print("Invalid choice. Please select 'L' for Login or 'R' for Registration.")
            continue

        username = input("Enter your username: ")
        password = input("Enter your password: ")
        print(f'PASSWORD: {password}')
        login_credentials = f"{action}|{username}|{password}".encode()

        # Encrypting the login or registration credentials
        credentials_encrypted = aes_encrypt(enc_key, login_credentials)
        server_socket.sendall(credentials_encrypted)

        # Receiving and decrypting the server's response
        response_encrypted = server_socket.recv(1024)
        response = aes_decrypt(enc_key, response_encrypted).decode('utf-8')
        print(response)

        if "successful" in response:
            print("Operation successful.")
            if "logged" in response:
                print("Ready for transactions.")
                break  # Assume login grants access to different functionalities; break loop
            else:
                print("Registration Successful. You may now log in.")
                continue
                # Do not break; allow the user to see the display menu again for possible login
        else:
            print("Operation failed or invalid credentials. Please try again.")


def client_operation():
    clientID = f'ATMClient_{random.randint(1000, 9999)}'
    logger.info(f"Starting client with ID {clientID}")
    # Generate and save RSA keys for this client session
    try:
        while True:
            with socket.create_connection((HOST, PORT)) as server_socket:

                exits = False
                msg = ""
                done = False
                # intial connection and saving keys
                serverID, shared_key = save_keys(server_socket, clientID)
                print( shared_key)
                print(serverID)
                while exits == False:
                    try:
                        # Key Distribution
                        enc_key, mac_key = initial_verification(shared_key, server_socket)
                        print(f'Encryption Key: {enc_key}')
                        print(f'MAC Key: {mac_key}')

                        if not enc_key or not mac_key:
                            logger.error("Authentication failed.")
                            msg= "Authentication failed"
                            exits = True
                            break
                        else:
                            logger.info('Authentication Successful and Keys Retrieved.')
                            handle_user_actions(server_socket, enc_key, mac_key)



                        # # Receive server's final response
                        # encrypted_final_response = server_socket.recv(1024)
                        # print("Received encrypted final response from server.")

                        # # Decrypt the final response
                        # decrypted_final_response = aes_decrypt(shared_key, encrypted_final_response)
                        # decoded_final_response = decrypted_final_response.decode()  # Decode the final response
                        # nonce_c2_received, timestamp_s2 = decoded_final_response.split("|")  # Split the final response into its variables

                        # # Check if received new nonce sis valid
                        # if nonce_c2 != nonce_c2_received or not is_timestamp_valid(int(timestamp_s2), get_timestamp()):
                        #     print("Nonce or timestamp invalid in server's final response.")
                        #     return False



                        # 4raise Exception("Initial verification failed")
                    
                        # AUTHENTICATION COMPLETED 
                        exits=True

                    except Exception as e:
                        print("Error:", e)

                if exits:
                    logger.error("Authentication failed")
                    break
                elif done:
                    logger.info("Authentication completed successfully")
                

            # # Input to continue or quit
            # quit_command = input("Enter 'q' to quit or any other key to continue: ").strip().lower()
            # if quit_command == 'q':
            #     break
    finally:
        # Remove keys before exiting
        # remove_keys(clientID)
        remove_shared_key(clientID)
        logger.info("Client keys removed. Exiting.")

if __name__ == "__main__":
    try:
        client_operation()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        logger.info("Interrupt received, shutting down...")
        sys.exit(0)