import socket
import threading
from CryptoUtils import aes_decrypt, aes_encrypt, generate_rsa_keys, generate_nonce, generate_session_id, hash_password, check_password_hash

HOST = 'localhost'
PORT = 4446

# Server's RSA keys (Note: These keys are not utilized in the given context but prepared for future use)
server_private_key, server_public_key = generate_rsa_keys()

def handle_client_connection(client_socket):
    try:
        print('Started securing channel with client.')
        encrypted_message = client_socket.recv(1024)

        # Decrypt the message from the client
        message = aes_decrypt(encrypted_message)
        client_id, nonce_client, client_public_key = message.decode().split('||')

        nonce_server = generate_nonce()
        session_id = generate_session_id()  # Generate a unique session ID for this connection
        response = f"{nonce_server}||{nonce_client}||{session_id}".encode()

        # Encrypt the response using AES and send it back to the client
        encrypted_reply = aes_encrypt(response)
        client_socket.send(encrypted_reply)

        print(f'Channel secured successfully with {client_id}. Session ID: {session_id}')

        # Process login credentials or allow new user creation
        process_user_choice(client_socket)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()

def process_user_choice(client_socket):
    # Send initial options to the client
    options_message = "WELCOME TO BANKING APP!\nLOG IN BY ENTERING YOUR INFO BELOW:\n\nEnter:\nQ - Quit\nN - New User\nL - Log In"
    encrypted_options = aes_encrypt(options_message.encode())
    client_socket.send(encrypted_options)

    # Receive and decrypt the user's choice
    encrypted_choice = client_socket.recv(1024)
    choice = aes_decrypt(encrypted_choice).decode()

    if choice.upper() == 'Q':
        # Quit option, close the connection
        print("Client chose to quit. Closing connection.")
        client_socket.close()  # Close the connection immediately
        return  # Exit the function
    elif choice.upper() == 'N':
        create_new_user(client_socket)
    elif choice.upper() == 'L':
        process_login_credentials(client_socket)
    else:
        # Invalid choice, close the connection
        print("Invalid choice. Closing connection.")
        client_socket.close()

def create_new_user(client_socket):
    encrypted_username = client_socket.recv(1024)
    username = aes_decrypt(encrypted_username).decode()

    encrypted_password = client_socket.recv(1024)
    password = aes_decrypt(encrypted_password).decode()

    # Generate salt for password hashing
    salt = generate_nonce()
    hashed_password = hash_password(password, salt)

    # Store user credentials in a file (in real-world scenario, use a database)
    with open("users.txt", "a") as file:
        file.write(f"{username}:{hashed_password}:{salt}\n")

    # Send confirmation message to the client
    confirmation_message = "User created successfully!"
    encrypted_confirmation = aes_encrypt(confirmation_message.encode())
    client_socket.send(encrypted_confirmation)

def verify_user_credentials(username, password):
    with open("users.txt", "r") as file:
        for line in file:
            stored_username, stored_hash, stored_salt = line.strip().split(':')
            if username == stored_username and check_password_hash(password, stored_hash, stored_salt):
                return True
    return False

def process_login_credentials(client_socket):
    encrypted_credentials = client_socket.recv(1024)
    credentials = aes_decrypt(encrypted_credentials).decode()
    username, password = credentials.split(":")

    if verify_user_credentials(username, password):
        response_message = "Authentication Successful"
    else:
        response_message = "Authentication Failed"

    encrypted_response = aes_encrypt(response_message.encode())
    client_socket.send(encrypted_response)

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=handle_client_connection, args=(client_socket,)).start()

if __name__ == "__main__":
    main()
