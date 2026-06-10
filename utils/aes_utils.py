"""
Utility Class with functions for the implmentation of AES-GCM

Author: Kashmain Tahir
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# generate shared secret using their public keys and own private keys = K
def generate_secret(own_pr_key, peer_pu_key):
    shared_secret = own_pr_key.exchange(peer_pu_key)
    return shared_secret

# generate a AES-256 key from the shared secret
def generate_dh_shared_key(shared_secret):
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'health-telemetry-handshake-data',
        ).derive(shared_secret)
    
    return aes_key

def generate_session_key():
    AES_KEY_SIZE = 256
    return AESGCM.generate_key(bit_length=AES_KEY_SIZE)

# 96-bit nonce is the standard size
NONCE_SIZE = 12
# encrypt using AESGCM
def aesgcm_encrypt(aes_key, data):

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return nonce, ciphertext

# decrypt using AESGCM
def aesgcm_decrypt(aes_key, nonce, ciphertext):

    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except InvalidTag:
        print("Integrity Verification Failed. Could not decrypt data.")

def aesgcm_encrypt_bytes(aes_key, data_in_bytes):

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data_in_bytes, None)
    return nonce, ciphertext

# decrypt using AESGCM
def aesgcm_decrypt_bytes(aes_key, nonce, ciphertext):

    try:
        aesgcm = AESGCM(aes_key)
        plaintext_in_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_in_bytes
    except InvalidTag:
        print("Integrity Verification Failed. Could not decrypt data.")