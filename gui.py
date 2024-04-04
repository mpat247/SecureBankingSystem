import tkinter as tk
from tkinter import ttk, messagebox
import os

# Initial user data loading
users = {}

def load_users():
    if os.path.exists("users2.txt"):
        with open("users2.txt", "r") as file:
            for line in file:
                username, password, balance = line.strip().split(", ")
                users[username] = {'password': password, 'balance': float(balance)}

def save_user(username, password, balance=0):
    with open("users2.txt", "a") as file:
        file.write(f"{username}, {password}, {balance}\n")
    users[username] = {'password': password, 'balance': balance}

def register():
    username = username_entry.get()
    password = password_entry.get()
    # Direct registration without uniqueness check
    save_user(username, password)
    messagebox.showinfo("Registration Successful", "You are now registered, please login.")
    back_to_login()

def login():
    username = username_entry.get()
    password = password_entry.get()
    if username in users and users[username]['password'] == password:
        global balance
        balance = users[username]['balance']
        show_transaction_screen()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

def show_transaction_screen():
    top_bar.config(text="User Action Center")
    entry_frame.pack_forget()
    transaction_frame.pack(expand=True, fill='both')

def deposit():
    global balance
    deposit_amount = deposit_entry.get()
    try:
        deposit_amount = float(deposit_amount)
        if deposit_amount > 0:
            balance += deposit_amount
            users[username_entry.get()]['balance'] = balance  # Update in-memory user balance
            update_balance_label()
            messagebox.showinfo("Deposit", f"Deposit of ${deposit_amount} successful")
            save_user_data()  # Save updated balance to file
        else:
            messagebox.showerror("Error", "Deposit amount must be a positive number")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid deposit amount")

def withdraw():
    global balance
    withdraw_amount = withdraw_entry.get()
    try:
        withdraw_amount = float(withdraw_amount)
        if withdraw_amount > 0 and withdraw_amount <= balance:
            balance -= withdraw_amount
            users[username_entry.get()]['balance'] = balance  # Update in-memory user balance
            update_balance_label()
            messagebox.showinfo("Withdraw", f"Withdrawal of ${withdraw_amount} successful")
            save_user_data()  # Save updated balance to file
        elif withdraw_amount > balance:
            messagebox.showerror("Error", "Insufficient balance")
        else:
            messagebox.showerror("Error", "Withdrawal amount must be a positive number")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid withdrawal amount")

def balance_inquiry():
    update_balance_label()

def update_balance_label():
    balance_label.config(text=f"Your current balance is ${balance:.2f}")

def back_to_login():
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    deposit_entry.delete(0, tk.END)
    withdraw_entry.delete(0, tk.END)

    balance_label.config(text="")
    top_bar.config(text="Secure Banking System")
    transaction_frame.pack_forget()
    entry_frame.pack(expand=True)

def save_user_data():
    with open("users2.txt", "w") as file:
        for user, info in users.items():
            file.write(f"{user}, {info['password']}, {info['balance']}\n")

def center_window(event=None):
    window_width = root.winfo_width()
    window_height = root.winfo_height()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_coordinate = (screen_width - window_width) // 2
    y_coordinate = (screen_height - window_height) // 2
    root.geometry(f"+{x_coordinate}+{y_coordinate}")

load_users()

root = tk.Tk()
root.title("Secure Banking System")
root.geometry("600x400")

# Bright and Modern Color Scheme
background_color = "#FFFFFF"  # White background
input_background = "#F0F0F0"  # Light grey for input fields
button_color = "#4CAF50"  # Green for buttons
text_color = "#000000"  # Dark grey for text

# Modern Font Style
font_style = ('Roboto', 12)
title_font_style = ('Roboto', 20, 'bold')

root.configure(background=background_color)
style = ttk.Style(root)
style.configure('TFrame', background=background_color)
style.configure('TLabel', font=font_style, relief='flat', background=background_color, foreground=text_color)
style.configure('TButton', font=font_style, background=button_color, foreground="black", borderwidth=0, radius=10)
style.configure('TEntry', foreground="black", font=font_style, fieldbackground=input_background, borderwidth=0, radius=5)
style.map('TButton', background=[('active', button_color)], foreground=[('active', 'white')])

top_bar = ttk.Label(root, text="Secure Banking System", background=background_color, foreground=text_color, font=title_font_style)
top_bar.pack(pady=(20, 10))

entry_frame = ttk.Frame(root, style='TFrame')
entry_frame.pack(expand=True)

username_label = ttk.Label(entry_frame, text="Username:", style='TLabel')
username_label.grid(row=0, column=0, padx=10, pady=10)
username_entry = ttk.Entry(entry_frame, width=30)
username_entry.grid(row=0, column=1, padx=10, pady=10)

password_label = ttk.Label(entry_frame, text="Password:", style='TLabel')
password_label.grid(row=1, column=0, padx=10, pady=10)
password_entry = ttk.Entry(entry_frame, show="*", width=30)
password_entry.grid(row=1, column=1, padx=10, pady=10)

login_button = ttk.Button(entry_frame, text="Login", command=login)
login_button.grid(row=2, column=0, columnspan=2, pady=10)

transaction_frame = ttk.Frame(root, style='TFrame')

deposit_label = ttk.Label(transaction_frame, text="Deposit Amount:", style='TLabel')
deposit_label.grid(row=0, column=0, padx=10, pady=10)
deposit_entry = ttk.Entry(transaction_frame, width=20)
deposit_entry.grid(row=0, column=1, padx=10, pady=10)
deposit_button = ttk.Button(transaction_frame, text="Deposit", command=deposit)
deposit_button.grid(row=0, column=2, padx=10, pady=10)

withdraw_label = ttk.Label(transaction_frame, text="Withdraw Amount:", style='TLabel')
withdraw_label.grid(row=1, column=0, padx=10, pady=10)
withdraw_entry = ttk.Entry(transaction_frame, width=20)
withdraw_entry.grid(row=1, column=1, padx=10, pady=10)
withdraw_button = ttk.Button(transaction_frame, text="Withdraw", command=withdraw)
withdraw_button.grid(row=1, column=2, padx=10, pady=10)

balance_button = ttk.Button(transaction_frame, text="Balance Inquiry", command=balance_inquiry)
balance_button.grid(row=2, column=0, padx=10, pady=10)
balance_label = ttk.Label(transaction_frame, text="", font=font_style)
balance_label.grid(row=2, column=1, columnspan=2, padx=10, pady=10)

back_button = ttk.Button(transaction_frame, text="Back to Login", command=back_to_login)
back_button.grid(row=3, column=0, columnspan=3, pady=10)

# Registration button in entry_frame
register_button = ttk.Button(entry_frame, text="Register", command=register)
register_button.grid(row=3, column=0, columnspan=2, pady=10)

center_window()

root.mainloop()