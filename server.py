import socket
import threading
from CryptoUtils import aes_decrypt, aes_encrypt, generate_nonce

HOST = 'localhost'
PORT = 4449

def handle_client_connection(client_socket):
    try:
        encrypted_message = client_socket.recv(1024)

        # Decrypt the message from the client
        message = aes_decrypt(encrypted_message)
        client_id, nonce_client, client_public_key = message.decode().split('||')

        nonce_server = generate_nonce()
        session_id = generate_nonce()  # Generate a unique session ID for this connection
        response = f"{nonce_server}||{nonce_client}||{session_id}".encode()

        # Encrypt the response using AES and send it back to the client
        encrypted_reply = aes_encrypt(response)
        client_socket.send(encrypted_reply)

        print(f'Channel secured successfully with {client_id}. Session ID: {session_id}')

        # Process user choice (Quit)
        while True:
            choice = receive_and_process_user_choice(client_socket)
            if choice == 'Q':
                print("Client chose to quit. Closing connection.")
                break  # Exit the loop and close connection
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()

def receive_and_process_user_choice(client_socket):
    # Send initial options to the client
    options_message = "Enter:\nQ - Quit"
    encrypted_options = aes_encrypt(options_message.encode())
    client_socket.send(encrypted_options)

    # Receive and decrypt the user's choice
    encrypted_choice = client_socket.recv(1024)
    choice = aes_decrypt(encrypted_choice).decode()

    return choice.upper()

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
