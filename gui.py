import tkinter as tk
from tkinter import ttk, messagebox
import os

# User Data Management Functions
def load_users():
    if os.path.exists("users2.txt"):
        with open("users2.txt", "r") as file:
            for line in file:
                username, password, balance = line.strip().split(", ")
                users[username] = {'password': password, 'balance': float(balance)}

def save_user(username, password, balance=0):
    users[username] = {'password': password, 'balance': balance}
    with open("users2.txt", "w") as file:
        for user, info in users.items():
            file.write(f"{user}, {info['password']}, {info['balance']}\n")

# UI and Interaction Logic
def register():
    username = username_entry.get()
    password = password_entry.get()
    if username in users:
        messagebox.showerror("Registration Failed", "Username already exists.")
        return
    save_user(username, password)
    messagebox.showinfo("Registration Successful", "You are now registered, please login.")
    back_to_login()

def login():
    username = username_entry.get()
    password = password_entry.get()
    if username in users and users[username]['password'] == password:
        global current_user
        current_user = username
        show_transaction_screen()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

def show_transaction_screen():
    top_bar.config(text=f"User Action Center: {current_user}")
    entry_frame.pack_forget()
    transaction_frame.pack(expand=True, fill='both')
    update_balance_label()

def deposit():
    deposit_amount = deposit_entry.get()
    try:
        deposit_amount = float(deposit_amount)
        if deposit_amount > 0:
            users[current_user]['balance'] += deposit_amount
            update_balance_label()
            messagebox.showinfo("Deposit", f"Deposit of ${deposit_amount} successful")
            save_user_data()
        else:
            messagebox.showerror("Error", "Deposit amount must be a positive number")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid deposit amount")

def withdraw():
    withdraw_amount = withdraw_entry.get()
    try:
        withdraw_amount = float(withdraw_amount)
        if 0 < withdraw_amount <= users[current_user]['balance']:
            users[current_user]['balance'] -= withdraw_amount
            update_balance_label()
            messagebox.showinfo("Withdraw", f"Withdrawal of ${withdraw_amount} successful")
            save_user_data()
        else:
            messagebox.showerror("Error", "Insufficient balance")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid withdrawal amount")

def balance_inquiry():
    update_balance_label()

def update_balance_label():
    balance_label.config(text=f"Your current balance is ${users[current_user]['balance']:.2f}")

def back_to_login():
    for entry in [username_entry, password_entry, deposit_entry, withdraw_entry]:
        entry.delete(0, tk.END)
    transaction_frame.pack_forget()
    entry_frame.pack(expand=True)
    top_bar.config(text="Secure Banking System")

def save_user_data():
    with open("users2.txt", "w") as file:
        for user, info in users.items():
            file.write(f"{user}, {info['password']}, {info['balance']}\n")

# Initialize Users Data and Current User
users = {}
current_user = ""
load_users()

# Initialize Tkinter Root Window
root = tk.Tk()
root.title("Secure Banking System")
root.geometry("800x500")

# UI Styling
background_color = "#fafafa"
input_background = "#ffffff"
button_color = "#007bff"
button_hover = "#0056b3"
text_color = "#000000"
font_style = ('Arial', 12)
title_font_style = ('Arial', 24, 'bold')

root.configure(background=background_color)
style = ttk.Style(root)
style.theme_use('clam')
style.configure('TFrame', background=background_color)
style.configure('TLabel', font=font_style, background=background_color, foreground=text_color)
style.configure('TButton', font=font_style, background=button_color, foreground="white")
style.configure('TEntry', font=font_style, fieldbackground=input_background, foreground=text_color)
style.map('TButton', background=[('active', button_hover)])

# UI Layout
top_bar = ttk.Label(root, text="Secure Banking System", background=background_color, foreground=text_color, font=title_font_style)
top_bar.pack(pady=(20, 20))

entry_frame = ttk.Frame(root)
entry_frame.pack(expand=True, fill='both')

username_label = ttk.Label(entry_frame, text="Username:", font=font_style)
username_label.grid(row=0, column=0, padx=10, pady=10)
username_entry = ttk.Entry(entry_frame, font=font_style)
username_entry.grid(row=0, column=1, padx=10, pady=10)

password_label = ttk.Label(entry_frame, text="Password:", font=font_style)
password_label.grid(row=1, column=0, padx=10, pady=10)
password_entry = ttk.Entry(entry_frame, font=font_style, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=10)

login_button = ttk.Button(entry_frame, text="Login", command=login)
login_button.grid(row=2, column=0, columnspan=2, pady=10)

register_button = ttk.Button(entry_frame, text="Register", command=register)
register_button.grid(row=3, column=0, columnspan=2, pady=10)

transaction_frame = ttk.Frame(root)

deposit_label = ttk.Label(transaction_frame, text="Deposit Amount:", font=font_style)
deposit_label.grid(row=0, column=0, padx=10, pady=10)
deposit_entry = ttk.Entry(transaction_frame, font=font_style)
deposit_entry.grid(row=0, column=1, padx=10, pady=10)
deposit_button = ttk.Button(transaction_frame, text="Deposit", command=deposit)
deposit_button.grid(row=0, column=2, padx=10, pady=10)

withdraw_label = ttk.Label(transaction_frame, text="Withdraw Amount:", font=font_style)
withdraw_label.grid(row=1, column=0, padx=10, pady=10)
withdraw_entry = ttk.Entry(transaction_frame, font=font_style)
withdraw_entry.grid(row=1, column=1, padx=10, pady=10)
withdraw_button = ttk.Button(transaction_frame, text="Withdraw", command=withdraw)
withdraw_button.grid(row=1, column=2, padx=10, pady=10)

balance_button = ttk.Button(transaction_frame, text="Balance Inquiry", command=balance_inquiry)
balance_button.grid(row=2, column=0, padx=10, pady=10)
balance_label = ttk.Label(transaction_frame, text="", font=font_style)
balance_label.grid(row=2, column=1, columnspan=2, padx=10, pady=10)

back_button = ttk.Button(transaction_frame, text="Back to Login", command=back_to_login)
back_button.grid(row=3, column=0, columnspan=3, pady=10)

root.mainloop()
