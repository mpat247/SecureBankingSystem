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

def prepare_message(action, username, amount, mac_key, enc_key):
    timestamp = str(int(time.time()))
    print("Timestamp: " + timestamp)
    # Construct the base message
    base_message = f"{timestamp}|{action}|{username}"
    print(f'Base message: {base_message}')
    # Only add amount to the message if the action requires it and it's provided
    if action != 'L' and amount:
        base_message += f"|{amount}"
        print(base_message)

    # Generate MAC using the constructed base message and the secret MAC key
    mac = generate_mac(mac_key, base_message)
    print(mac)
    mac_b64 = base64.b64encode(mac).decode('utf-8')  # Convert MAC to base64 for transmission
    print(mac_b64)

    # Include the MAC in the full message
    full_message = f"{base_message}|{mac_b64}"
    print(full_message)

    # Encrypt the full message using AES in CBC mode with the encryption key
    encrypted_message = aes_encrypt_cbc(enc_key, full_message)
    print(encrypted_message)
    return encrypted_message


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
                        if action == 'Q':
                            break
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
                            userBalance = server_socket.recv(1024).decode('utf-8')
                            print(userBalance)
                            messagebox.showinfo("Success", "Login successful!")
                            loggedIn = True
                        elif "Registration successful" in response:
                            messagebox.showinfo("Success", "Registration successful. Please log in.")
                        else:
                            messagebox.showerror("Error", response)

                    while loggedIn:
                        action, amount = collect_transaction_input(username, userBalance)
                        print(action, amount)
                        if action == 'Q':
                            print("Logging out...")
                            break  # Exit the loop
                        print(action, username,amount, mac_key, enc_key)
                        encrypted_message = prepare_message(action, username, amount, mac_key, enc_key)
                        print(encrypted_message)
                        server_socket.sendall(encrypted_message.encode('utf-8'))

                        # Handle server response
                        encrypted_response = server_socket.recv(4096)
                        response = aes_decrypt_cbc(enc_key, encrypted_response.decode('utf-8'))
                        response_type, message = response.split('|',
                                                                1)  # Splitting only on the first '|' to ensure any additional '|' in the message don't affect splitting

                        if response_type == "Success":
                            messagebox.showinfo("Success", message)
                            if action == 'L':  # If the action was to view logs
                                show_logs_screen(
                                    message)  # Assuming show_logs_screen is a function you will define to display logs
                            else:
                                messagebox.showinfo("Success", message)  # For Deposit, Withdraw, or Balance Inquiry
                        elif response_type == "Error":
                            messagebox.showerror("Error", message)

                    print("Session ended.")


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



def collect_user_input():
    def finalize(action):
        user_info['username'] = username_entry.get() if username_entry else ''
        user_info['password'] = password_entry.get() if password_entry else ''
        user_info['action'] = action
        root.destroy()

    def on_close():
        # Handle the quit action when the window is closed
        finalize('Q')

    user_info = {'username': '', 'password': '', 'action': ''}

    root = tk.Tk()
    root.title("User Action")
    root.geometry('450x350')
    root.configure(bg='#2D3047')
    root.protocol("WM_DELETE_WINDOW", on_close)  # Handle the window close event

    # Font Styles
    labelFont = ('Arial', 12)
    entryFont = ('Arial', 12)
    buttonFont = ('Arial', 12, 'bold')

    # Define Entry widgets globally so they can be accessed in on_close if needed
    global username_entry, password_entry
    username_entry = tk.Entry(root, font=entryFont, bd=0, bg='#EFF1F3')
    password_entry = tk.Entry(root, show="*", font=entryFont, bd=0, bg='#EFF1F3')

    # Layout for Username and Password Entry
    tk.Label(root, text="Username:", bg='#2D3047', fg='white', font=labelFont).place(x=60, y=60)
    username_entry.place(x=160, y=60, width=220, height=30)

    tk.Label(root, text="Password:", bg='#2D3047', fg='white', font=labelFont).place(x=60, y=120)
    password_entry.place(x=160, y=120, width=220, height=30)

    # Action Buttons
    tk.Button(root, text="Login", bg='#00C897', fg='white', font=buttonFont, bd=0,
              command=lambda: finalize('L')).place(x=50, y=200, width=100, height=40)

    tk.Button(root, text="Register", bg='#FF6B6B', fg='white', font=buttonFont, bd=0,
              command=lambda: finalize('R')).place(x=180, y=200, width=100, height=40)

    tk.Button(root, text="Quit", bg='#757575', fg='white', font=buttonFont, bd=0,
              command=lambda: finalize('Q')).place(x=310, y=200, width=100, height=40)

    root.mainloop()

    return user_info['username'], user_info['password'], user_info['action']


def collect_transaction_input(username, balance):
    root = tk.Tk()
    root.title("Transaction")
    root.geometry('300x250')

    transaction_info = {'action': '', 'amount': ''}

    def set_action(action):
        transaction_info['action'] = action
        if action in ['D', 'W']:  # For deposit and withdraw, prompt for amount
            transaction_info['amount'] = simpledialog.askstring("Amount", "Enter amount:")
        root.destroy()

    tk.Label(root, text=f"Welcome {username}", font=("Arial", 14)).pack(pady=10)
    tk.Label(root, text=f"Your Balance: ${balance}", font=("Arial", 12)).pack(pady=5)

    tk.Button(root, text="Deposit", command=lambda: set_action('D')).pack(pady=2)
    tk.Button(root, text="Withdraw", command=lambda: set_action('W')).pack(pady=2)
    tk.Button(root, text="View Logs", command=lambda: set_action('L')).pack(pady=2)
    tk.Button(root, text="Log Out", command=lambda: set_action('Q')).pack(pady=2)

    root.mainloop()
    return transaction_info['action'], transaction_info.get('amount')


def show_logs_screen(logs_str):
    logs_window = tk.Tk()
    logs_window.title("Transaction Logs")
    logs_window.geometry('400x300')

    # Using Text widget to display logs
    text_area = tk.Text(logs_window, wrap='word')
    text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    text_area.insert(tk.END, logs_str)
    text_area.config(state=tk.DISABLED)  # Make the text area read-only

    logs_window.mainloop()


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