"""
Patient Monitor Client
Reads vitals of a single patient and sends it to the server

Author: Kashmain Tahir
"""

import socket
from utils.dh_utils import *
from utils.aes_utils import *
from utils.rsa_utils import *

def connect_to_station():
    """
    Connects to the server and securely transmits data to the server
    """

    try:
        # socket set up
        HOST = '127.0.0.1'
        PORT = 9000

        monitor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        monitor_socket.connect((HOST, PORT))
        client_log("connected to Monitoring Station")

        # receive server public key and verify digital signature
        server_pu_key = verify_server_identity(monitor_socket)
        if not server_pu_key:
            return

        dh_channel_key = dh_client_key_exchange(monitor_socket, server_pu_key)
        if not dh_channel_key:
            return False

        # receive encrypted session key from the server
        enc_session_key_packet = monitor_socket.recv(1024)
        nonce = enc_session_key_packet[:NONCE_SIZE]
        enc_session_key = enc_session_key_packet[NONCE_SIZE:]
        session_key = aesgcm_decrypt_bytes(dh_channel_key, nonce, enc_session_key)
        client_log("session key received")

        # send patient health telemetry
        send_telemtry(monitor_socket, session_key)

        monitor_socket.close()

    except Exception as error:
        client_log(f"could not start patient monitor: {error}")


def verify_server_identity(monitor_socket):
    """
    receive server public key and signature and verifies the signature
    """
    server_pu_and_sign = monitor_socket.recv(4096)

    # split key and signature
    pu_end_marker = b"-----END PUBLIC KEY-----\n"
    end_marker_index = server_pu_and_sign.find(pu_end_marker)
    split_position = end_marker_index + len(pu_end_marker)
    server_pu_key_bytes = server_pu_and_sign[:split_position]
    server_signature = server_pu_and_sign[split_position:]

    # receive complete signature from TCP stream
    RSA_SIGNATURE_LENGTH = 256
    while len(server_signature) < RSA_SIGNATURE_LENGTH:
        leftover_signature = monitor_socket.recv(256-len(server_signature))
        if not leftover_signature:
            client_log("server public key authentication failed.")
            monitor_socket.close()
            return
        server_signature += leftover_signature

    # verify server public key using digital signature
    server_rsa_pu_key = read_public_key("keys/server_pu.pem")
    verified = verify_signature(server_rsa_pu_key, server_signature, server_pu_key_bytes)
    if not verified:
        client_log("server public key authentication failed.")
        monitor_socket.close()
        return 
    
    client_log("Server public key verified")
    server_pu_key = pu_key_to_obj(server_pu_key_bytes)
    return server_pu_key


def send_telemtry(monitor_socket, session_key):
    """
    send encrypted patient health data that is read from a text file
    """
    
    # read data from file with error-handling
    try:
        with open("data/test_normal.txt", "r") as file:
            patient_data = file.read()
    except FileNotFoundError:
        client_log("patient data not found")
        monitor_socket.close()
        return
    
    if not len(patient_data) > 0:
        client_log("patient data empty")
        monitor_socket.close()
        return

    # encrypt patient data with session key
    nonce, ciphertext = aesgcm_encrypt(session_key, patient_data)
    packet_to_send = nonce + ciphertext
    
    # FAIL DATA INTEGRITY VERIFICATION
    data_tamper_mode = False
    if data_tamper_mode:
        client_log("DATA TAMPER MODE")
        packet_to_send_bytes_arr = bytearray(packet_to_send)
        # simulating an attack by modifying one byte of patient data 
        packet_to_send_bytes_arr[15] ^= 1
        packet_to_send = bytes(packet_to_send_bytes_arr)
        monitor_socket.close()
        return
        
    monitor_socket.sendall(packet_to_send)
    client_log("Patient Health Telemetry sent to Monitoring Station")


def dh_client_key_exchange(monitor_socket, server_pu_key):
    """
    generates DH private and public key, signs the public key, and sends to the server
    """

    # Diffie-Hellman key pair generation
    dh_parameters = server_pu_key.parameters()
    client_pr_key = generate_dh_private_key(dh_parameters)
    client_pu_key = generate_dh_public_key(client_pr_key)

    # send signature and DH public key to the server
    client_pu_key_bytes = pu_key_to_bytes(client_pu_key)
    client_rsa_pr_key = read_private_key("keys/client_pr.pem")
    client_signature = sign_data(client_rsa_pr_key, client_pu_key_bytes)

    # FAIL AUTHENTICATION VERIFICATION
    key_tamper_mode = False
    if key_tamper_mode:
        client_log("CLIENT PUBLIC KEY TAMPER MODE")
        tampered_pu_key = bytearray(client_pu_key_bytes)
        # simulating an attack by modifying one byte of public key
        tampered_pu_key[10] ^= 1
        client_pu_key_bytes = bytes(tampered_pu_key)
        return

    monitor_socket.sendall(client_pu_key_bytes)
    monitor_socket.sendall(client_signature)
    client_log("Public Key sent to Station")

     # generating Diffie-Hellman shared secret and temporary key
    shared_secret = generate_secret(client_pr_key, server_pu_key)
    dh_channel_key = generate_dh_shared_key(shared_secret)

    return dh_channel_key

def client_log(message):
    """
    prints log messages generated by the patient monitor with a prefix
    """
    print("[MONITOR] " + message)

def main():
    """
    starts the patient monitor (client)
    """
    connect_to_station()

if __name__ == "__main__":
    main()