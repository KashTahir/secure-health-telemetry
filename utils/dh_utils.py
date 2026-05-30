"""
Utility Class with functions for the implmentation of Diffie-Hellman

Author: Kashmain Tahir
"""
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# plan from ed:

# two integer values needed q − a prime number and α − a primitive root of q
def generate_dh_params():

    # key size set so that it is not too slow while maintaing standard security
    dh_params = dh.generate_parameters(
    generator=2,
    key_size=2048
    )

    return dh_params



# User A and User B need to select private keys X. X < q
def generate_dh_private_key(dh_params):
    pr_key = dh_params.generate_private_key()
    return pr_key

# User A and User B will calculate their public keys using their own Xs = Y
def generate_dh_public_key(private_key):
    pu_key = private_key.public_key()
    return pu_key

# share the public key
# convert public key objet to bytes to send over the network
def pu_key_to_bytes(pu_key_obj):
    pu_key_bytes = pu_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pu_key_bytes

def pu_key_to_obj(pu_key_bytes):
    pu_key_obj = serialization.load_pem_public_key(pu_key_bytes)
    return pu_key_obj
    

# generate shared secret using their public keys and own private keys = K
def generate_secret(own_pr_key, peer_pu_key):
    shared_secret = own_pr_key.exchange(peer_pu_key)
    return shared_secret


# generate a AES-256 key from the shared secret
def generate_aes_key(shared_secret):
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'health-telemetry-handshake-data',
        ).derive(shared_secret)
    
    return aes_key


