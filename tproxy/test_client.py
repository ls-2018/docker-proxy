#!/usr/bin/env python3
"""
Simple test client for the interactive tproxy example.
This script connects to the proxy and allows interactive communication.
"""

import socket
import threading
import sys

def receive_messages(sock):
    """Thread function to receive messages from the server."""
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            print(f"[Server]: {data.decode().strip()}")
    except Exception as e:
        print(f"Error receiving: {e}")

def send_messages(sock):
    """Thread function to send messages to the server."""
    try:
        while True:
            message = input()
            if message.lower() in ['quit', 'exit']:
                sock.send(message.encode())
                break
            sock.send(f"{message}\n".encode())
    except Exception as e:
        print(f"Error sending: {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 test_client.py <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    try:
        # Connect to the server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f"Connected to {host}:{port}")
        print("Type messages to send to the server. Type 'quit' or 'exit' to disconnect.")
        print("----------------------------------------")
        
        # Start threads for receiving and sending
        receive_thread = threading.Thread(target=receive_messages, args=(sock,))
        send_thread = threading.Thread(target=send_messages, args=(sock,))
        
        receive_thread.daemon = True
        send_thread.daemon = True
        
        receive_thread.start()
        send_thread.start()
        
        # Wait for send thread to finish (when user types quit)
        send_thread.join()
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()
        print("Disconnected.")

if __name__ == "__main__":
    main()
