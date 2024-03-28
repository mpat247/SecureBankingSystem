import socket
from CryptoUtils import aes_encrypt, aes_decrypt, generate_rsa_keys, generate_nonce

HOST = 'localhost'
PORT = 4449

def establish_secure_channel(client_socket):
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

    if nonce_client_confirm != nonce_client:
        raise ValueError("Nonces don't match. Potential security breach.")


def main():
    client_socket = socket.create_connection((HOST, PORT))
    try:
        establish_secure_channel(client_socket)
        while True:
            choice = input("Enter Q to quit: ").strip().upper()
            if choice == 'Q':
                print("Quitting...")
                break
            else:
                print("Invalid choice. Please try again.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
