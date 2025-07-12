import socket
import threading
from encryption import decrypt_message, get_key

HOST = '127.0.0.1'
PORT = 12345
SECRET = 'shared_secret'  # Same as client
ENCRYPTION_ENABLED = True

key = get_key(SECRET)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = []

def handle_client(client):
    while True:
        try:
            msg = client.recv(1024).decode()

            if ENCRYPTION_ENABLED:
                decrypted = decrypt_message(msg, key)
            else:
                decrypted = msg

            print(f"[MESSAGE] {decrypted}")

            with open("server_log.txt", "a") as f:
                f.write(decrypted + "\n")

            broadcast(msg, client)

        except Exception as e:
            print(f"[DISCONNECT] A client disconnected: {e}")
            if client in clients:
                clients.remove(client)
            client.close()
            break

def broadcast(msg, sender):
    for client in clients:
        if client != sender:
            client.send(msg.encode())

print(f"[LISTENING] Server is running on {HOST}:{PORT}")
while True:
    client, addr = server.accept()
    print(f"[NEW CONNECTION] {addr}")
    clients.append(client)
    thread = threading.Thread(target=handle_client, args=(client,))
    thread.start()
