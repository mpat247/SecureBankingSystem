import socket
from CryptoUtils import aes_encrypt, aes_decrypt, generate_rsa_keys, generate_nonce

HOST = 'localhost'
PORT = 4446

def establish_secure_channel(client_socket):
    print('Started securing channel with server.')
    client_id = 'Client' + generate_nonce()
    nonce_client = generate_nonce()
    # Assuming client's public key needs to be shared initially; adjust as needed
    client_private_key, client_public_key = generate_rsa_keys()

    message = f"{client_id}||{nonce_client}".encode() + b'||' + client_public_key
    encrypted_message = aes_encrypt(message)
    client_socket.send(encrypted_message)

    encrypted_reply = client_socket.recv(1024)
    reply = aes_decrypt(encrypted_reply)
    nonce_server, nonce_client_confirm, session_id = reply.decode().split('||')

    print(f"Nonce from server: {nonce_server}, your nonce confirmation: {nonce_client_confirm}, session ID: {session_id}")

    if nonce_client_confirm != nonce_client:
        raise ValueError("Nonces don't match. Potential security breach.")

    print('Channel secured successfully with server.')

def prompt_and_send_login_credentials(client_socket):
    choice = input("Enter:\nQ - Quit\nN - New User\nL - Log In\nChoice: ").strip().upper()

    if choice == 'Q':
        print("Quitting...")
        return False
    elif choice == 'N':
        # Handle new user creation logic here
        print("New user creation is not implemented yet.")
        return False
    elif choice == 'L':
        username = input("Username: ")
        password = input("Password: ")  # In real applications, use getpass.getpass()

        credentials = f"{username}:{password}".encode()
        encrypted_credentials = aes_encrypt(credentials)
        client_socket.send(encrypted_credentials)

        # Receive and decrypt the server's response
        encrypted_response = client_socket.recv(1024)
        response = aes_decrypt(encrypted_response).decode()
        print(f"Login response: {response}")

        return response == "Authentication Successful"
    else:
        print("Invalid choice. Please try again.")
        return False


def main():
    client_socket = socket.create_connection((HOST, PORT))
    try:
        establish_secure_channel(client_socket)
        if prompt_and_send_login_credentials(client_socket):
            print("Login successful.")
            # The client can now proceed to perform other tasks.
        else:
            print("Login failed. Please check your credentials.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
