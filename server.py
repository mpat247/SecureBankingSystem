import os
import random
import socket
import logging
from datetime import datetime

import colorlog
from threading import Thread
from tools import *
import atexit
import signal
import sys
import base64

######################Console log colors#####################
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
PORT = 5008
serverID = None
server_socket = None


###########Initial verification###############
def initial_verification(shared_key, client_socket):
    try:
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

        master_secret_encrypted = aes_encrypt(shared_key, master_secret)
        # Send encrypted nonce and timestamp to server
        client_socket.sendall(master_secret_encrypted)
        logger.info("Encrypted Master Secret Sent to Client")

        enc_key, mac_key = derive_keys_from_master_secret(master_secret)
        logger.info(f'Encryption Key: {enc_key}')
        logger.info(f'MAC Key: {mac_key}')

        return enc_key, mac_key
    except Exception as e:
        logger.error(f'Intial Verification Failed: {e}')
        return None, None


##########Register User########################
# Adjusted register_user function
def register_user(username, password, enc_key):
    print(f'Registering User {username} {password} {enc_key}')
    users_file_path = 'users.txt'
    try:
        with open(users_file_path, 'r') as file:  # Open file in read mode (not binary mode)
            users = [line.strip().split('|') for line in file.readlines() if line]
    except FileNotFoundError:
        users = []

    if any(user[0] == username for user in users):
        return False, "Username already exists."

    hashed_password = hash_password(password)
    with open(users_file_path, 'a') as file:  # Open file in append mode to add new user
        file.write(f"{username}|{hashed_password}|0\n")

    return True, "Registration successful."

#################Login User############################
def login_user(username, provided_password, enc_key):
    users_file_path = 'users.txt'
    try:
        with open(users_file_path, 'r') as file:  # Open file in read mode (not binary mode)
            users = [line.strip().split('|') for line in file.readlines() if line]
    except FileNotFoundError:
        return False, "Users file not found.", None

    user_record = next((user for user in users if user[0] == username), None)

    if user_record and verify_password(user_record[1], provided_password):
        balance = user_record[2]  # Extract balance from user record
        return True, "Login successful.", balance
    else:
        return False, "Incorrect username or password.", None

############################Process Transaction Messages#############################

#######################Balance Updates###########################
def get_balance(username):

    try:
        with open('users.txt', 'r') as file:
            for line in file:
                user_info = line.strip().split('|')
                if len(user_info) != 3:
                    continue  # Skip any malformed lines

                if user_info[0] == username:
                    # Assuming balance is stored in plain text. If encrypted, decrypt here.
                    return True, user_info[2]  # Return the balance
    except FileNotFoundError:
        return False, "User file not found."

    return False, "User not found."


def update_balance(username, amount, operation):
    users = []
    updated = False

    try:
        # Load and decrypt user data
        with open('users.txt', 'r') as file:
            for line in file:
                user_info = line.strip().split('|')
                if len(user_info) < 3:
                    continue  # Skip malformed lines

                if user_info[0] == username:
                    current_balance = float(user_info[2])
                    if operation == 'deposit':
                        new_balance = current_balance + float(amount)
                    elif operation == 'withdrawal' and current_balance >= float(amount):
                        new_balance = current_balance - float(amount)
                    else:
                        return False, "Insufficient funds."

                    user_info[2] = str(new_balance)
                    updated = True

                users.append(user_info)

    except FileNotFoundError:
        return False, "User file not found."

    if not updated:
        return False, "User not found."

    # Encrypt and save updated user data
    try:
        with open('users.txt', 'w') as file:
            for user_info in users:
                file.write('|'.join(user_info) + '\n')
    except IOError:
        return False, "Failed to update user file."

    return True, user_info[2]

def process_deposit(username, amount):
    return update_balance(username, amount, 'deposit')

def process_withdrawal(username, amount):
    return update_balance(username, amount, 'withdrawal')

def process_balance_inquiry(username, key):
    success, balance = get_balance(username, key)
    if success:
        log_transaction(username, 'balance inquiry', 0, key)
    return success, f"Current balance: {balance}"

def log_transaction(username, action, amount, enc_key):
    log_entry = f"{datetime.now()}|{username}|{action}|{amount}"
    encrypted_log = aes_encrypt_cbc(enc_key, log_entry)  # Ensure aes_encrypt_cbc is correctly implemented
    with open("logs.txt", "ab") as file:
        file.write(encrypted_log + b'\n')


def process_log_inquiry(username, enc_key):
    decrypted_logs = []
    try:
        with open("logs.txt", "rb") as log_file:
            for encrypted_log in log_file.readlines():
                decrypted_log = aes_decrypt_cbc(enc_key,
                                                encrypted_log.strip())  # Assume aes_decrypt_cbc is correctly implemented
                if username in decrypted_log:
                    decrypted_logs.append(decrypted_log)
    except FileNotFoundError:
        return "Log file not found."

    if decrypted_logs:
        # Optionally: Encrypt the collective log data before sending it back
        encrypted_logs_data = aes_encrypt_cbc(enc_key, '\n'.join(
            decrypted_logs))  # Ensure compatibility with your aes_encrypt_cbc implementation
        return encrypted_logs_data
    else:
        return "No logs found for user."


def process_received_message(encrypted_message, mac_key, enc_key):
    try:
        decrypted_message = aes_decrypt_cbc(enc_key, encrypted_message)
        print(f"Decrypted message: {decrypted_message}")

        parts = decrypted_message.split('|')
        if len(parts) < 4:
            return None, "Incomplete message received."

        timestamp, action, username, amount, mac_b64 = parts[:5]
        print(f"Timestamp: {timestamp} | Action: {action} | Username: {username} | Amount: {amount} | B64: {mac_b64}")
        amount = parts[4] if len(parts) > 4 else ""

        base_message = '|'.join([timestamp, action, username, amount])
        if not verify_mac(base_message, mac_b64, mac_key):
            return None, "MAC verification failed."

        if not is_timestamp_fresh(timestamp):
            return None, "Timestamp not fresh."

        return {'action': action, 'username': username, 'amount': amount}, None
    except Exception as e:
        return None, f"Error processing message: {str(e)}"


def handle_transaction_action(action, username, amount, enc_key):
    # Note: 'amount' is expected to be a string representing a numerical value for 'D' and 'W' actions
    # For 'B' and 'L' actions, 'amount' could be ignored or empty
    if action == 'D':
        success, message = process_deposit(username, amount)  # process_deposit now directly returns the updated balance message
    elif action == 'W':
        success, message = process_withdrawal(username, amount)  # Same for process_withdrawal
    elif action == 'B':
        success, message = process_balance_inquiry(username)  # Removed enc_key as it's not used
    elif action == 'L':
        message = process_log_inquiry(username, enc_key)  # Assuming logs are encrypted and hence enc_key is needed
        success = True if message else False  # If message returned, log inquiry considered successful
    else:
        return False, "Unknown action"

    # Optionally, log the transaction here if success
    if success and action in ['D', 'W']:
        log_transaction(username, action, amount, enc_key)  # Assuming you'll modify log_transaction to handle encryption

    return success, message



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

        loggedIn = False

        ##########Authenticated, login and register now#############
        # Inside handle_client_connection function, after initial verification

        # Server side: Handling login and registration
        while not loggedIn:
            try:
                encrypted_login_message = client_socket.recv(1024)
                print(encrypted_login_message)
                decrypted_login_message = aes_decrypt(enc_key, encrypted_login_message)
                print(decrypted_login_message)
                message = decrypted_login_message.decode()
                print(message)

                action, username, password = message.split('|')

                if action.upper() == 'L':  # Login action
                    login_success, login_message, balance = login_user(username, password, enc_key)
                    if login_success:
                        login_success_response = aes_encrypt(enc_key,
                                                             "Login successful. Proceeding to transactions.".encode())
                        client_socket.sendall(login_success_response)
                        client_socket.sendall(balance.encode('utf-8'))

                        loggedIn = True
                    else:
                        login_failed_response = aes_encrypt(enc_key,
                                                            f"Login failed: {login_message}. Please try again.".encode())
                        client_socket.sendall(login_failed_response)

                elif action.upper() == 'R':  # Registration action
                    registration_success, registration_message = register_user(username, password, enc_key)
                    if registration_success:
                        registration_success_response = aes_encrypt(enc_key,
                                                                    "Registration successful. You can now login.".encode())
                        client_socket.sendall(registration_success_response)
                    else:
                        registration_failed_response = aes_encrypt(enc_key,
                                                                   f"Registration failed: {registration_message}. Please try again.".encode())
                        client_socket.sendall(registration_failed_response)

                else:
                    invalid_action_response = aes_encrypt(enc_key,
                                                          "Invalid action. Please use 'L' for Login or 'R' for Registration.".encode())
                    client_socket.sendall(invalid_action_response)


            except Exception as e:
                logger.error(f"Error during login/registration process: {e}")
                error_response = aes_encrypt(enc_key, "An error occurred. Please try again.".encode())
                client_socket.sendall(error_response)

        # Here, outside the loop, handle authenticated user's transactions or further actions
        while loggedIn:
            print("Logged in successfully")
            print("Continue to transaction")
            while True:
                encrypted_message = client_socket.recv(4096)  # Adjust buffer size as needed
                if not encrypted_message:
                    print("Client disconnected.")
                    break

                message_details, error = process_received_message(encrypted_message, mac_key, enc_key)
                if error:
                    print(f"Error processing received message: {error}")
                    continue

                # Extract details for clarity
                action = message_details['action']
                username = message_details['username']
                amount = message_details['amount']

                # Directly pass individual parameters instead of a grouped list
                response = handle_transaction_action(action, username, amount, enc_key)

                # Encrypt and send response
                encrypted_response = aes_encrypt_cbc(enc_key, response)
                client_socket.sendall(encrypted_response.encode('utf-8'))

        else:
            logger.error("Unable to Login. Exiting Program.")

    except Exception as e:
        logger.error(f"Error with client {client_address}: {e}")
    finally:
        client_socket.close()
        logger.info(f"Client {client_address} disconnected")

##########################Start server#################################
def start_server():
    global server_socket
    global serverID
    serverID = f'BankServer{random.randint(1000, 9999)}'
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    logger.info(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_handler = Thread(target=handle_client_connection, args=(client_socket, client_address))
            client_handler.start()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down server...")
        server_socket.close()
    finally:
        if server_socket:
            server_socket.close()
        logger.info("Server shutdown")


if __name__ == "__main__":
    start_server()
