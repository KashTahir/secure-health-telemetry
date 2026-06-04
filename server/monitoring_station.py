"""
Patient vitals Monitoring Server
Receives data from a patient monitor using TCP

Author: Kashmain Tahir
"""

import socket
from utils.dh_utils import *
from utils.aes_utils import *

def start_monitoring_station():
    """
    creates a server socket to receive data from client monitors
    """

    try:

        HOST = '127.0.0.1'
        PORT = 9000

        # set up
        station_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        station_socket.bind((HOST, PORT))
        station_socket.listen()
        print("Monitoring Station waiting for incoming connections...")

        # accept the connection from the client
        connection_socket, connection_addr = station_socket.accept()
        print(f"connected to patient monitor: {connection_addr}")

        # key generation
        print("Generating Diffie-Hellman Parameters")
        dh_parameters = generate_dh_params()
        server_pr_key = generate_dh_private_key(dh_parameters)
        server_pu_key = generate_dh_public_key(server_pr_key)

        # send key
        server_pu_key_bytes = pu_key_to_bytes(server_pu_key)
        # print("server_pu_key_bytes: ")
        # print(server_pu_key_bytes)
        connection_socket.sendall(server_pu_key_bytes)
        print("Server Public Key sent to Client")

        # receive key
        client_pu_key_bytes = connection_socket.recv(4096)
        print("Client public key received")
        # print(client_pu_key_bytes)
        client_pu_key = pu_key_to_obj(client_pu_key_bytes)

        # generating shared secret
        shared_secret = generate_secret(server_pr_key, client_pu_key)
        # print("server shared secret")
        # print(shared_secret)

        aes_key = generate_aes_key(shared_secret)
        print("AES key generated")
        # print("server aes_key")
        # print(aes_key.hex())

        # print("server_pr_key")
        # print(server_pr_key)
        # print("server_pu_key")
        # print(server_pu_key)

        
        # nonce = connection_socket.recv(NONCE_SIZE)

        CHUNK_SIZE = 1024
        data = b""
        # keep receiving data until all is done

        
        while True:
            incoming_data = connection_socket.recv(CHUNK_SIZE)
            
            if not incoming_data:
                break
            else:
                data += incoming_data

        # data = connection_socket.recv(1024)

        # print("Data Received")
        # print(data.decode())

        if (len(data) < NONCE_SIZE):
            print("Invalid data received")
            return
        
        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]
        plaintext = aesgcm_decrypt(aes_key, nonce, ciphertext)
        print(plaintext)

        connection_socket.close()
        station_socket.close()


    except Exception as error:
        print(f"could not start monitoring station: {error}")


def main():
    start_monitoring_station()

if __name__ == "__main__":
    main()