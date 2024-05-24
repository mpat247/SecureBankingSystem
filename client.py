# client.py

import socket
import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from utils import CryptoUtils

class Client:
    def __init__(self, host='localhost', port=5005):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")
        self.perform_key_exchange()

    def perform_key_exchange(self):
        parameters = CryptoUtils.load_dh_parameters()
        client_private_key, client_public_key = CryptoUtils.generate_keys(parameters)
        self.client_socket.send(client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        server_public_key_bytes = self.client_socket.recv(4096)
        server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())
        shared_secret = client_private_key.exchange(server_public_key)
        self.enc_key, self.mac_key = CryptoUtils.derive_keys(shared_secret)
        print("Shared keys established")

    def send_message(self, message):
        ciphertext = CryptoUtils.encrypt(message, self.enc_key)
        mac = CryptoUtils.generate_mac(ciphertext, self.mac_key)
        self.client_socket.send(ciphertext + mac)
        response = self.client_socket.recv(4096)
        ciphertext, received_mac = response[:-32], response[-32:]
        if CryptoUtils.verify_mac(ciphertext, received_mac, self.mac_key):
            plaintext = CryptoUtils.decrypt(ciphertext, self.enc_key)
            return plaintext
        else:
            return "ERROR|MAC verification failed"

    def close(self):
        self.client_socket.close()

class App:
    def __init__(self, root, client):
        self.client = client
        self.root = root
        self.root.title("Banking System")
        self.username = None
        self.balance = 0
        self.setup_styles()
        self.create_login_register_widgets()

    def setup_styles(self):
        style = ttk.Style()
        style.configure('TButton', font=('Helvetica', 12), padding=10)
        style.configure('TLabel', font=('Helvetica', 14))
        style.configure('TEntry', font=('Helvetica', 12), padding=5)
        style.configure('Header.TLabel', font=('Helvetica', 18, 'bold'))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')

    def create_login_register_widgets(self):
        self.login_frame = ttk.Frame(self.root, padding=20)
        self.register_frame = ttk.Frame(self.root, padding=20)

        self.username_label = ttk.Label(self.login_frame, text="Username:")
        self.username_entry = ttk.Entry(self.login_frame)
        self.password_label = ttk.Label(self.login_frame, text="Password:")
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.register_button = ttk.Button(self.login_frame, text="Register", command=self.show_register_frame)

        self.username_label.pack(pady=5)
        self.username_entry.pack(pady=5)
        self.password_label.pack(pady=5)
        self.password_entry.pack(pady=5)
        self.login_button.pack(pady=10)
        self.register_button.pack(pady=5)

        self.register_username_label = ttk.Label(self.register_frame, text="Username:")
        self.register_username_entry = ttk.Entry(self.register_frame)
        self.register_password_label = ttk.Label(self.register_frame, text="Password:")
        self.register_password_entry = ttk.Entry(self.register_frame, show="*")
        self.register_confirm_button = ttk.Button(self.register_frame, text="Register", command=self.register)
        self.back_button = ttk.Button(self.register_frame, text="Back", command=self.show_login_frame)

        self.register_username_label.pack(pady=5)
        self.register_username_entry.pack(pady=5)
        self.register_password_label.pack(pady=5)
        self.register_password_entry.pack(pady=5)
        self.register_confirm_button.pack(pady=10)
        self.back_button.pack(pady=5)

        self.login_frame.pack()

    def show_login_frame(self):
        self.register_frame.pack_forget()
        self.login_frame.pack()

    def show_register_frame(self):
        self.login_frame.pack_forget()
        self.register_frame.pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        response = self.client.send_message(f"LOGIN|{username}|{password}")
        status, message = response.split('|')
        if status == "SUCCESS":
            self.username = username
            self.balance = int(message)
            self.show_main_page()
        else:
            messagebox.showerror("Login", message)

    def register(self):
        username = self.register_username_entry.get()
        password = self.register_password_entry.get()
        response = self.client.send_message(f"REGISTER|{username}|{password}")
        status, message = response.split('|')
        if status == "SUCCESS":
            messagebox.showinfo("Register", message)
            self.show_login_frame()
        else:
            messagebox.showerror("Register", message)

    def show_main_page(self):
        self.clear_frames()

        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack()

        welcome_label = ttk.Label(main_frame, text=f"Welcome, {self.username}", style='Header.TLabel')
        balance_label = ttk.Label(main_frame, text=f"Your balance: ${self.balance}", style='Success.TLabel' if self.balance >= 0 else 'Error.TLabel')

        deposit_button = ttk.Button(main_frame, text="Deposit", command=self.show_deposit_screen)
        withdraw_button = ttk.Button(main_frame, text="Withdraw", command=self.show_withdraw_screen)
        view_transactions_button = ttk.Button(main_frame, text="View Transactions", command=self.show_transactions)
        logout_button = ttk.Button(main_frame, text="Log Out", command=self.logout)

        welcome_label.pack(pady=10)
        balance_label.pack(pady=10)
        deposit_button.pack(pady=5)
        withdraw_button.pack(pady=5)
        view_transactions_button.pack(pady=5)
        logout_button.pack(pady=10)

    def show_deposit_screen(self):
        self.clear_frames()

        deposit_frame = ttk.Frame(self.root, padding=20)
        deposit_frame.pack()

        amount_label = ttk.Label(deposit_frame, text="Enter amount to deposit:")
        amount_entry = ttk.Entry(deposit_frame)
        submit_button = ttk.Button(deposit_frame, text="Deposit", command=lambda: self.deposit(amount_entry.get()))
        back_button = ttk.Button(deposit_frame, text="Back", command=self.show_main_page)

        amount_label.pack(pady=5)
        amount_entry.pack(pady=5)
        submit_button.pack(pady=10)
        back_button.pack(pady=5)

    def deposit(self, amount):
        try:
            amount = int(amount)
            self.balance += amount
            self.client.send_message(f"DEPOSIT|{self.username}|{amount}")
            self.show_main_page()
        except ValueError:
            messagebox.showerror("Error", "Invalid amount")

    def show_withdraw_screen(self):
        self.clear_frames()

        withdraw_frame = ttk.Frame(self.root, padding=20)
        withdraw_frame.pack()

        amount_label = ttk.Label(withdraw_frame, text="Enter amount to withdraw:")
        amount_entry = ttk.Entry(withdraw_frame)
        submit_button = ttk.Button(withdraw_frame, text="Withdraw", command=lambda: self.withdraw(amount_entry.get()))
        back_button = ttk.Button(withdraw_frame, text="Back", command=self.show_main_page)

        amount_label.pack(pady=5)
        amount_entry.pack(pady=5)
        submit_button.pack(pady=10)
        back_button.pack(pady=5)

    def withdraw(self, amount):
        try:
            amount = int(amount)
            self.balance -= amount
            self.client.send_message(f"WITHDRAW|{self.username}|{amount}")
            self.show_main_page()
        except ValueError:
            messagebox.showerror("Error", "Invalid amount")

    def show_transactions(self):
        self.clear_frames()

        transactions_frame = ttk.Frame(self.root, padding=20)
        transactions_frame.pack()

        transactions = self.client.send_message(f"TRANSACTIONS|{self.username}")
        transactions = transactions.split('|')

        for transaction in transactions:
            if transaction:
                date, time, trans_type, amount = transaction.split(',')
                color = "green" if trans_type == "Deposit" else "red"
                transaction_label = ttk.Label(transactions_frame, text=f"{date} {time} - {trans_type}: ${amount}", foreground=color)
                transaction_label.pack()

        back_button = ttk.Button(transactions_frame, text="Back", command=self.show_main_page)
        back_button.pack(pady=10)

    def logout(self):
        self.client.send_message(f"LOGOUT|{self.username}")
        self.client.close()
        self.clear_frames()
        self.create_login_register_widgets()

    def clear_frames(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    client = Client()
    root = tk.Tk()
    app = App(root, client)
    root.mainloop()
    client.close()
