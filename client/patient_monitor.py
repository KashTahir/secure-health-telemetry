"""
Patient Monitor Client
Reads hourly vitals of a single patient and sends it to the server

Author: Kashmain Tahir
"""

import socket
from utils.dh_utils import *

def connect_to_station():
    """
    creates a socket to connect to the server 
    """

    try:

        HOST = '127.0.0.1'
        PORT = 9000

        # set up
        monitor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        monitor_socket.connect((HOST, PORT))
        print("Connected to server")

        # sr_conn_socket, sr_conn_addr = monitor_socket.accept()
        # print(f"connected to patient monitor: {sr_conn_addr}")

        # key generation
        client_pr_key = generate_dh_private_key()
        client_pu_key = generate_dh_public_key(client_pr_key)

        # send key
        client_pu_key_bytes = pu_key_to_bytes(client_pu_key)
        # print("client_pu_key_bytes: ")
        # print(client_pu_key_bytes)
        monitor_socket.sendall(client_pu_key_bytes)
        print("Client Public Key sent to Server")

        # receive key
        server_pu_key_bytes = monitor_socket.recv(4096)
        print("Server public key received")
        # print(server_pu_key_bytes)
        server_pu_key = pu_key_to_obj(server_pu_key_bytes)
        

        # print("client_pr_key")
        # print(client_pr_key)
        # print("client_pu_key")
        # print(client_pu_key)

        # send data
        with open("data/test_normal.txt", "r") as file:
            patient_data = file.read()

        monitor_socket.sendall(patient_data.encode())
        print("Data sent to Monitoring Station")

        monitor_socket.close()


    except Exception as error:
        print(f"could not start patient monitor: {error}")



def print_client(text):
    """
    helper function to print statements from the client
    Args:
        text: the string to output
    """

    print(f"CLIENT -- {text}")


def main():
    connect_to_station()

if __name__ == "__main__":
    main()