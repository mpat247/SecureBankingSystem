# server.py

import socket
from threading import Thread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from utils import CryptoUtils
import os
from datetime import datetime

class Server:
    def __init__(self, host='localhost', port=5005):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        self.log_enc_key = os.urandom(32)  # Key for encrypting logs
        print(f"Server started on {host}:{port}")

    def handle_client(self, client_socket):
        try:
            parameters = CryptoUtils.load_dh_parameters()
            server_private_key, server_public_key = CryptoUtils.generate_keys(parameters)
            client_public_key_bytes = client_socket.recv(4096)
            client_socket.send(server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            client_public_key = serialization.load_pem_public_key(client_public_key_bytes, backend=default_backend())
            shared_secret = server_private_key.exchange(client_public_key)
            enc_key, mac_key = CryptoUtils.derive_keys(shared_secret)
            print("Shared keys established")

            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                ciphertext, received_mac = data[:-32], data[-32:]
                if CryptoUtils.verify_mac(ciphertext, received_mac, mac_key):
                    plaintext = CryptoUtils.decrypt(ciphertext, enc_key)
                    if plaintext is None:
                        continue
                    command, *args = plaintext.split('|')
                    response = ""
                    if command == "REGISTER":
                        response = self.register_user(*args)
                    elif command == "LOGIN":
                        response = self.login_user(*args)
                    elif command == "DEPOSIT":
                        response = self.deposit(*args)
                    elif command == "WITHDRAW":
                        response = self.withdraw(*args)
                    elif command == "TRANSACTIONS":
                        response = self.view_transactions(*args)
                    elif command == "LOGOUT":
                        response = "SUCCESS|Logged out"
                    encrypted_response = CryptoUtils.encrypt(response, enc_key)
                    mac = CryptoUtils.generate_mac(encrypted_response, mac_key)
                    client_socket.send(encrypted_response + mac)
                else:
                    print("MAC verification failed")

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def register_user(self, username, password):
        try:
            if os.path.exists("users.txt"):
                with open("users.txt", "r") as file:
                    for line in file:
                        stored_username, _, _ = line.strip().split('|')
                        if stored_username == username:
                            return "ERROR|Username already exists"

            hashed_password = CryptoUtils.hash_password(password)
            with open("users.txt", "a") as file:
                file.write(f"{username}|{hashed_password}|1000\n")
            return "SUCCESS|User registered"
        except Exception as e:
            return f"ERROR|{e}"

    def login_user(self, username, password):
        try:
            if os.path.exists("users.txt"):
                hashed_password = CryptoUtils.hash_password(password)
                with open("users.txt", "r") as file:
                    for line in file:
                        stored_username, stored_password, balance = line.strip().split('|')
                        if stored_username == username and stored_password == hashed_password:
                            return f"SUCCESS|{balance}"
            return "ERROR|Invalid username or password"
        except Exception as e:
            return f"ERROR|{e}"

    def deposit(self, username, amount):
        try:
            self.update_balance(username, int(amount))
            self.log_transaction(username, "Deposit", amount)
            return "SUCCESS|Deposit successful"
        except Exception as e:
            return f"ERROR|{e}"

    def withdraw(self, username, amount):
        try:
            self.update_balance(username, -int(amount))
            self.log_transaction(username, "Withdraw", amount)
            return "SUCCESS|Withdrawal successful"
        except Exception as e:
            return f"ERROR|{e}"

    def view_transactions(self, username):
        try:
            transactions = []
            if os.path.exists("transactions.txt"):
                with open("transactions.txt", "rb") as file:
                    encrypted_logs = file.read()
                    logs = CryptoUtils.decrypt_log(encrypted_logs, self.log_enc_key)
                    if logs:
                        for log in logs.split('\n'):
                            if log:
                                stored_username, date, time, trans_type, amount = log.strip().split('|')
                                if stored_username == username:
                                    transactions.append(f"{date},{time},{trans_type},{amount}")
            return '|'.join(transactions)
        except Exception as e:
            return f"ERROR|{e}"

    def update_balance(self, username, amount):
        try:
            users = []
            if os.path.exists("users.txt"):
                with open("users.txt", "r") as file:
                    users = file.readlines()
            with open("users.txt", "w") as file:
                for user in users:
                    stored_username, stored_password, balance = user.strip().split('|')
                    if stored_username == username:
                        balance = str(int(balance) + amount)
                    file.write(f"{stored_username}|{stored_password}|{balance}\n")
        except Exception as e:
            print(f"Error updating balance: {e}")

    def log_transaction(self, username, trans_type, amount):
        try:
            date = datetime.now().strftime("%Y-%m-%d")
            time = datetime.now().strftime("%H:%M:%S")
            log_entry = f"{username}|{date}|{time}|{trans_type}|{amount}\n"
            if os.path.exists("transactions.txt"):
                with open("transactions.txt", "rb") as file:
                    encrypted_logs = file.read()
                    logs = CryptoUtils.decrypt_log(encrypted_logs, self.log_enc_key)
                    if logs:
                        logs += log_entry
                    else:
                        logs = log_entry
            else:
                logs = log_entry
            encrypted_logs = CryptoUtils.encrypt_log(logs, self.log_enc_key)
            with open("transactions.txt", "wb") as file:
                file.write(encrypted_logs)
        except Exception as e:
            print(f"Error logging transaction: {e}")

    def start(self):
        print("Waiting for clients...")
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            client_thread = Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    server = Server()
    server.start()
