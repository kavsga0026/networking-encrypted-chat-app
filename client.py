import socket
import threading
from encryption import encrypt_message, get_key

HOST = '127.0.0.1'
PORT = 12345
SECRET = 'shared_secret'  # Must match the server
ENCRYPTION_ENABLED = True

# Ask user for a display name
username = input("Enter your username: ")

# Derive AES key from shared secret
key = get_key(SECRET)

# Connect to server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Function to receive messages from server
def receive_messages():
    while True:
        try:
            msg = client.recv(1024).decode()
            print(f"\n[RECEIVED] {msg}\nYou: ", end="")
        except Exception as e:
            print(f"[ERROR] {e}")
            break

# Function to send messages to server
def send_messages():
    while True:
        try:
            message = input("You: ")
            full_message = f"{username}: {message}"

            if ENCRYPTION_ENABLED:
                encrypted = encrypt_message(full_message, key)
                client.send(encrypted.encode())
            else:
                client.send(full_message.encode())

        except Exception as e:
            print(f"[ERROR] {e}")
            break

# Start receiving and sending in parallel threads
receive_thread = threading.Thread(target=receive_messages)
send_thread = threading.Thread(target=send_messages)

receive_thread.start()
send_thread.start()
