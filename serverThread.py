from server import start_server

# Specify the host and port for the server
HOST = 'localhost'
PORT = 4444

def main():
    # Create and start the server with the specified host and port
    server = start_server()
    server.start()

if __name__ == "__main__":
    main()
