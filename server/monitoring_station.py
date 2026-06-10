"""
Patient vitals Monitoring Server
Receives data from a patient monitor using TCP

Author: Kashmain Tahir
"""

import socket
from utils.dh_utils import *
from utils.aes_utils import *
from utils.rsa_utils import *

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
        print("Diffie-Hellman Parameters Generated")

        # send key
        server_pu_key_bytes = pu_key_to_bytes(server_pu_key)
        server_rsa_pr_key = read_private_key("keys/server_pr.pem")
        server_signature = sign_data(server_rsa_pr_key, server_pu_key_bytes)
        connection_socket.sendall(server_pu_key_bytes)
        connection_socket.sendall(server_signature)

        # print("server_pu_key_bytes: ")
        # print(server_pu_key_bytes)
        # connection_socket.sendall(server_pu_key_bytes)
        print("Server Public Key sent to Client")

        # receive key
        # client_pu_key_bytes = connection_socket.recv(4096)
        # print("Client public key received")
        # print(client_pu_key_bytes)

        client_pu_and_sign = connection_socket.recv(4096)
         # splitting incoming data into key and signaure
        pu_end_marker = b"-----END PUBLIC KEY-----\n"
        end_marker_index = client_pu_and_sign.find(pu_end_marker)
        split_position = end_marker_index + len(pu_end_marker)

        
        client_pu_key_bytes = client_pu_and_sign[:split_position]
        client_signature = client_pu_and_sign[split_position:]

        # receving complete signature from TCP stream
        RSA_SIGNATURE_LENGTH = 256
        while len(client_signature) < RSA_SIGNATURE_LENGTH:
            leftover_signature = connection_socket.recv(256-len(client_signature))
            if not leftover_signature:
                print("could not receive full signature")
                connection_socket.close()
                station_socket.close()
                return
            client_signature += leftover_signature

        # print(len(server_pu_key_bytes))
        # print(len(server_signature))

        # verify client public key
        client_rsa_pu_key = read_public_key("keys/client_pu.pem")
        verified = verify_signature(client_rsa_pu_key, client_signature, client_pu_key_bytes)
        if not verified:
            print("client public key authentication failed.")
            connection_socket.close()
            station_socket.close()
            return
        
        print("Client public key verified by server")

        client_pu_key = pu_key_to_obj(client_pu_key_bytes)

        # generating shared secret
        shared_secret = generate_secret(server_pr_key, client_pu_key)
        # print("server shared secret")
        # print(shared_secret)

        dh_channel_key = generate_dh_shared_key(shared_secret)
        print("Temporary DH key generated")
        # print("server aes_key")
        # print(aes_key.hex())

        session_key = generate_session_key()
        print("Server has generated session key")

        nonce, enc_session_key = aesgcm_encrypt_bytes(dh_channel_key, session_key)
        # print("1")
        key_packet_to_send = nonce + enc_session_key
        # print("2")
        connection_socket.sendall(key_packet_to_send)
        print("Server has sent session key")
        
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
        plaintext = aesgcm_decrypt(session_key, nonce, ciphertext)
        print(plaintext)

        connection_socket.close()
        station_socket.close()


    except Exception as error:
        print(f"could not start monitoring station: {error}")


def main():
    start_monitoring_station()

if __name__ == "__main__":
    main()