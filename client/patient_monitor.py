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
        print("AES key generated")
        # print("client aes_key")
        # print(aes_key.hex())

        # send data

        # read data or return if file is not found
        try:
            with open("data/test_normal.txt", "r") as file:
                patient_data = file.read()
        except FileNotFoundError:
            print("patient data not found")
            monitor_socket.close()
            return
        if not len(patient_data) > 0:
            print("patient data empty")
            monitor_socket.close()
            return

        nonce, ciphertext = aesgcm_encrypt(aes_key, patient_data)
        packet_to_send = nonce + ciphertext
        
        # FAIL INTEGRITY VERIFICATION DEMO
        TAMPER_MODE = False
        if TAMPER_MODE:
            print("TAMPER MODE ON")
            packet_to_send_bytes_arr = bytearray(packet_to_send)
            # XORing one of the bytes with 00000001 to modify the data 
            packet_to_send_bytes_arr[15] ^= 1
            packet_to_send = bytes(packet_to_send_bytes_arr)
            

        monitor_socket.sendall(packet_to_send)

        # print("Ciphertext:")
        # print(packet_to_send)

        # monitor_socket.sendall(patient_data.encode())
        print("Data sent to Monitoring Station")

        monitor_socket.close()


    except Exception as error:
        print(f"could not start patient monitor: {error}")


def main():
    connect_to_station()

if __name__ == "__main__":
    main()