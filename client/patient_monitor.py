"""
Patient Monitor Client
Reads hourly vitals of a single patient and sends it to the server

Author: Kashmain Tahir
"""

import socket
from utils.dh_utils import *
from utils.aes_utils import *

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

        # receive server public key
        server_pu_key_bytes = monitor_socket.recv(4096)
        print("Server public key received")
        # print(server_pu_key_bytes)
        server_pu_key = pu_key_to_obj(server_pu_key_bytes)

        # key generation
        dh_parameters = server_pu_key.parameters()
        client_pr_key = generate_dh_private_key(dh_parameters)
        client_pu_key = generate_dh_public_key(client_pr_key)


        # send key
        client_pu_key_bytes = pu_key_to_bytes(client_pu_key)
        # print("client_pu_key_bytes: ")
        # print(client_pu_key_bytes)
        monitor_socket.sendall(client_pu_key_bytes)
        print("Client Public Key sent to Server")


        # generating shared secret
        shared_secret = generate_secret(client_pr_key, server_pu_key)
        # print("client shared secret")
        # print(shared_secret)
        
        aes_key = generate_aes_key(shared_secret)
        # print("client aes_key")
        # print(aes_key.hex())
    
        # print("client_pr_key")
        # print(client_pr_key)
        # print("client_pu_key")
        # print(client_pu_key)

        # send data
        with open("data/test_normal.txt", "r") as file:
            patient_data = file.read()
        
        nonce, ciphertext = aesgcm_encrypt(aes_key, patient_data)
        packet_to_send = nonce + ciphertext
        # monitor_socket.sendall(nonce)
        # monitor_socket.sendall(ciphertext)
        monitor_socket.sendall(packet_to_send)

        # print("Ciphertext:")
        # print(packet_to_send)

        # monitor_socket.sendall(patient_data.encode())
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