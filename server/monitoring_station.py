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
        server_log("waiting for incoming connections...")

        # accept the connection from the client
        connection_socket, connection_addr = station_socket.accept()
        server_log(f"connected to patient monitor: {connection_addr}")

        # key generation
        dh_parameters = generate_dh_params()
        server_pr_key = generate_dh_private_key(dh_parameters)
        server_pu_key = generate_dh_public_key(server_pr_key)

        # send key
        server_pu_key_bytes = pu_key_to_bytes(server_pu_key)
        server_rsa_pr_key = read_private_key("keys/server_pr.pem")
        server_signature = sign_data(server_rsa_pr_key, server_pu_key_bytes)

        # FAIL AUTHENTICATION VERIFICATION
        key_tamper_mode = False
        if key_tamper_mode:
            print("SERVER PUBLIC KEY TAMPER MODE")
            tampered_pu_key = bytearray(server_pu_key_bytes)
            # XORing one of the bytes with 00000001 to modify the data 
            tampered_pu_key[10] ^= 1
            server_pu_key_bytes = bytes(tampered_pu_key)
            connection_socket.close()
            station_socket.close()
            return

        connection_socket.sendall(server_pu_key_bytes)
        connection_socket.sendall(server_signature)
        server_log("Public Key sent to Monitor")

        # receive key
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
                server_log("could not receive full signature")
                connection_socket.close()
                station_socket.close()
                return
            client_signature += leftover_signature

        # verify client public key
        client_rsa_pu_key = read_public_key("keys/client_pu.pem")
        verified = verify_signature(client_rsa_pu_key, client_signature, client_pu_key_bytes)
        if not verified:
            server_log("client public key authentication failed.")
            connection_socket.close()
            station_socket.close()
            return
        
        server_log("Client public key verified")

        client_pu_key = pu_key_to_obj(client_pu_key_bytes)

        # generating shared secret
        shared_secret = generate_secret(server_pr_key, client_pu_key)
        dh_channel_key = generate_dh_shared_key(shared_secret)

        # 256-bit key for AES-GCM encryption
        session_key = generate_session_key()

        # encrypt session using AES-GCM and send it to client
        nonce, enc_session_key = aesgcm_encrypt_bytes(dh_channel_key, session_key)
        key_packet_to_send = nonce + enc_session_key
        connection_socket.sendall(key_packet_to_send)
        server_log("session key sent")

        CHUNK_SIZE = 1024
        data = b""

        # keep receiving data until all is done
        while True:
            incoming_data = connection_socket.recv(CHUNK_SIZE)
            
            if not incoming_data:
                break
            else:
                data += incoming_data

        if (len(data) < NONCE_SIZE):
            server_log("Invalid data received")
            return
        
        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]
        plaintext = aesgcm_decrypt(session_key, nonce, ciphertext)
        print(plaintext)

        connection_socket.close()
        station_socket.close()


    except Exception as error:
        server_log(f"could not start monitoring station: {error}")

def server_log(message):
    print("[STATION] " + message)

def main():
    start_monitoring_station()

if __name__ == "__main__":
    main()