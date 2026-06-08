"""
Patient Monitor Client
Reads hourly vitals of a single patient and sends it to the server

Author: Kashmain Tahir
"""

import socket
from utils.dh_utils import *
from utils.aes_utils import *
from utils.rsa_utils import *

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
        # server_pu_key_bytes = monitor_socket.recv(4096)
        # server_signature = monitor_socket.recv(256)

        server_pu_and_sign = monitor_socket.recv(4096)

        # splitting incoming data into key and signaure
        pu_end_marker = b"-----END PUBLIC KEY-----\n"
        end_marker_index = server_pu_and_sign.find(pu_end_marker)
        split_position = end_marker_index + len(pu_end_marker)
    
        server_pu_key_bytes = server_pu_and_sign[:split_position]
        server_signature = server_pu_and_sign[split_position:]

        RSA_SIGNATURE_LENGTH = 256
        while len(server_signature) < RSA_SIGNATURE_LENGTH:
            leftover_signature = monitor_socket.recv(256-len(server_signature))
            if not leftover_signature:
                print("could not receive full signature")
                monitor_socket.close()
                return
            server_signature += leftover_signature

        print("Server public key verified by client")

        # print(len(server_pu_key_bytes))
        # print(len(server_signature))

        # verify server public key
        server_rsa_pu_key = read_public_key("keys/server_pu.pem")
        verified = verify_signature(server_rsa_pu_key, server_signature, server_pu_key_bytes)
        if not verified:
            print("server public key authentication failed.")
            monitor_socket.close()
            return


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