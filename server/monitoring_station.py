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
    creates a server socket and accepts connection to receive data from client monitors
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

        # send signature and public key to the server
        server_pr_key = dh_server_key_exchange(connection_socket, station_socket)
        if not server_pr_key:
            return False

        # receive client public key and verify digital signature
        client_pu_key = verify_client_identity(connection_socket, station_socket)
        if not client_pu_key:
            return
        
        # generating Diffie-Hellman shared secret and temporary key
        shared_secret = generate_secret(server_pr_key, client_pu_key)
        dh_channel_key = generate_dh_shared_key(shared_secret)

        # generating a session key for AES-GCM encryption of communication
        session_key = generate_session_key()

        # encrypt session key using temporary DH key and send it to the client
        nonce, enc_session_key = aesgcm_encrypt_bytes(dh_channel_key, session_key)

         # SESSION KEY TAMPERING
        session_key_tamper_mode = False
        if session_key_tamper_mode:
            server_log("SESSION KEY TAMPERED")
            enc_session_key_byte_arr = bytearray(enc_session_key)
            # simulating an attack by modifying one byte of the session key 
            enc_session_key_byte_arr[30] ^= 1
            enc_session_key = bytes(enc_session_key_byte_arr)

        key_packet_to_send = nonce + enc_session_key
        connection_socket.sendall(key_packet_to_send)
        server_log("session key sent")

        # receive patient health telemetry from client
        receive_telemtery(connection_socket, session_key)

        connection_socket.close()
        station_socket.close()

    except Exception as error:
        server_log(f"could not start monitoring station: {error}")

def verify_client_identity(connection_socket, station_socket):
    """
    receive client public key and signature and verifies the signature
    """

     # receive client public key and signature
    client_pu_and_sign = connection_socket.recv(4096)
    
    # split key and signaure
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
            server_log("client public key authentication failed.")
            connection_socket.close()
            station_socket.close()
            return
        client_signature += leftover_signature

    # verify client public key using digital signature
    client_rsa_pu_key = read_public_key("keys/client_pu.pem")
    verified = verify_signature(client_rsa_pu_key, client_signature, client_pu_key_bytes)
    if not verified:
        server_log("client public key authentication failed.")
        connection_socket.close()
        station_socket.close()
        return
    
    server_log("Client public key verified")
    client_pu_key = pu_key_to_obj(client_pu_key_bytes)

    return client_pu_key


def receive_telemtery(connection_socket, session_key):
    """
    receive encrypted patient data from client and decrypts it
    """
    CHUNK_SIZE = 1024
    data = b""

    # receive patient data until everything is received from the TCP stream
    while True:
        incoming_data = connection_socket.recv(CHUNK_SIZE)
        
        if not incoming_data:
            break
        else:
            data += incoming_data

    if (len(data) < NONCE_SIZE):
        server_log("Invalid data received")
        return
    
    # decrypt AES-GCM ciphertext using the received nonce
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    plaintext = aesgcm_decrypt(session_key, nonce, ciphertext)

    server_log("Valid Telemetry Decrypted")
    server_log(plaintext)



def dh_server_key_exchange(connection_socket, station_socket):
    """
    generates DH private and public key, signs the public key, and sends to the client
    """

    # Diffie-Hellman key pair generation
    dh_parameters = generate_dh_params()
    server_pr_key = generate_dh_private_key(dh_parameters)
    server_pu_key = generate_dh_public_key(server_pr_key)

    # send signature and DH public key to the client
    server_pu_key_bytes = pu_key_to_bytes(server_pu_key)
    server_rsa_pr_key = read_private_key("keys/server_pr.pem")
    server_signature = sign_data(server_rsa_pr_key, server_pu_key_bytes)

    # FAIL AUTHENTICATION VERIFICATION
    key_tamper_mode = False
    if key_tamper_mode:
        server_log("SERVER PUBLIC KEY TAMPER MODE")
        tampered_pu_key = bytearray(server_pu_key_bytes)
        # simulating an attack by modifying one byte of public key
        tampered_pu_key[10] ^= 1
        server_pu_key_bytes = bytes(tampered_pu_key)
        # return

    connection_socket.sendall(server_pu_key_bytes)
    connection_socket.sendall(server_signature)
    server_log("Public Key sent to Monitor")

    return server_pr_key

def server_log(message):
    """
    prints log messages generated by the monitoring station with a prefix
    """
    print("[STATION] " + message)

def main():
    """
    starts the central monitoring station (server)
    """
    start_monitoring_station()

if __name__ == "__main__":
    main()