from server import BankServer

# Specify the host and port for the server
HOST = 'localhost'
PORT = 4444

def main():
    # Create and start the server with the specified host and port
    server = BankServer()
    server.start()

if __name__ == "__main__":
    main()
