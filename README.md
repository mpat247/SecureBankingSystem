# Secure Banking System

Simple Python client/server demo of a secure banking workflow. The server and
client exchange keys with Diffie-Hellman, encrypt traffic with AES-GCM, and
protect messages with HMAC while providing basic banking actions.

## Requirements

- Python 3
- `cryptography` library

Install dependencies:

```bash
pip install cryptography
```

## Run the application

Start the server:

```bash
python server.py
```

In a second terminal, start the client:

```bash
python client.py
```

The client opens a Tkinter GUI where you can register, log in, deposit, withdraw,
and view transactions.

## Data files

- `users.txt` stores user credentials and balances.
- `transactions.txt` stores encrypted transaction logs.
- `dh_parameters.pem` provides the Diffie-Hellman parameters.
