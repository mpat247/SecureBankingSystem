import os
import random
import socket
import logging
import colorlog
from tools import *
import sys
import tkinter as tk
from tkinter import simpledialog, messagebox

#######################Console colors##################
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
PORT = 5009
#################### save client keys ##################
def save_keys(server_socket, clientID):
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

#######Initial Verificaiton, Securing channel and getting encryption and MAC keys###############
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


def client_operation():
    clientID = f'ATMClient_{random.randint(1000, 9999)}'
    logger.info(f"Starting client with ID {clientID}")
    # Generate and save RSA keys for this client session
    try:
        with socket.create_connection((HOST, PORT)) as server_socket:
            # intial connection and saving keys
            serverID, shared_key = save_keys(server_socket, clientID)
            print(shared_key)
            print(serverID)
            try:
                # Key Distribution
                enc_key, mac_key = initial_verification(shared_key, server_socket)
                print(f'Encryption Key: {enc_key}')
                print(f'MAC Key: {mac_key}')

                if not enc_key or not mac_key:
                    logger.error("Authentication failed.")

                else:
                    loggedIn = False

                    # Client side: Sending login or registration requests
                    while not loggedIn:
                        username, password, action = collect_user_input()
                        print(f'Username: {username} | Password: {password} | Action: {action}')
                        # Format and encrypt the message
                        message = f"{action}|{username}|{password}"
                        print(message)
                        print(message.encode('utf-8'))
                        encrypted_message = aes_encrypt(enc_key, message.encode())
                        print(encrypted_message)
                        # Send to server
                        server_socket.sendall(encrypted_message)

                        # Wait for and decrypt the response
                        encrypted_login_response = server_socket.recv(1024)
                        decrypted_login_response = aes_decrypt(enc_key, encrypted_login_response)
                        response = decrypted_login_response.decode()

                        # Example response processing
                        if "Login successful" in response:
                            messagebox.showinfo("Success", "Login successful!")
                            loggedIn = True
                        elif "Registration successful" in response:
                            messagebox.showinfo("Success", "Registration successful. Please log in.")
                        else:
                            messagebox.showerror("Error", response)

                    if loggedIn:
                        print("Logged in successfully")
                        print("Continue to transaction")

                    else:
                        logger.error("Unable to Login. Exiting Program.")

                # AUTHENTICATION COMPLETED

            except Exception as e:
                print("Error:", e)



            # # Input to continue or quit
            # quit_command = input("Enter 'q' to quit or any other key to continue: ").strip().lower()
            # if quit_command == 'q':
            #     break
    finally:
        # Remove keys before exiting
        # remove_keys(clientID)
        remove_shared_key(clientID)
        logger.info("Client keys removed. Exiting.")

import tkinter as tk
from tkinter import font as tkFont

def collect_user_input():
    # Initialize the variables to store user input
    user_info = {'username': '', 'password': '', 'action': ''}

    def on_submit():
        # Update user_info with inputs
        user_info['username'] = username_entry.get()
        user_info['password'] = password_entry.get()
        user_info['action'] = 'L' if login_var.get() else 'R'
        root.destroy()

    # Setup the root window
    root = tk.Tk()
    root.title("User Action")
    root.geometry('350x200')
    root.configure(bg='lightblue')

    # Font style
    fontStyle = tkFont.Font(family="Helvetica", size=12)
    buttonStyle = tkFont.Font(family="Helvetica", size=12, weight="bold")

    # Username Entry
    tk.Label(root, text="Username:", bg='lightblue', font=fontStyle).pack(pady=(20, 0))
    username_entry = tk.Entry(root, font=fontStyle)
    username_entry.pack()

    # Password Entry
    tk.Label(root, text="Password:", bg='lightblue', font=fontStyle).pack(pady=(10, 0))
    password_entry = tk.Entry(root, show="*", font=fontStyle)
    password_entry.pack()

    # Action Selection
    login_var = tk.BooleanVar(value=True)  # Default to Login
    tk.Radiobutton(root, text="Login", variable=login_var, value=True, bg='lightblue', font=fontStyle).pack()
    tk.Radiobutton(root, text="Register", variable=login_var, value=False, bg='lightblue', font=fontStyle).pack()

    # Submit Button
    tk.Button(root, text="Submit", command=on_submit, bg='#4CAF50', fg='white', font=buttonStyle).pack(pady=(10, 0))

    root.mainloop()
    return user_info['username'], user_info['password'], user_info['action']

# To run the function, you'll need to uncomment the following line:
# user_inputs = collect_user_input()
# Note: Uncommenting and running the above line outside of a Python environment that supports GUI operations may result in an error.


if __name__ == "__main__":
    try:
        client_operation()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        logger.info("Interrupt received, shutting down...")
        sys.exit(0)