"""
Utility Class with functions for the implmentation of Diffie-Hellman

Author: Kashmain Tahir
"""
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def generate_dh_params():
    """
    generates Diffie-Hellman parameters used for private key generation
    """

    # key size is set so that it is not too slow while maintaing standard security
    dh_params = dh.generate_parameters(
    generator=2,
    key_size=2048
    )

    return dh_params

def generate_dh_private_key(dh_params):
    """
    generates Diffie-Hellman private key 
    """
    pr_key = dh_params.generate_private_key()
    return pr_key

def generate_dh_public_key(private_key):
    """
    generates Diffie-Hellman public key 
    """
    pu_key = private_key.public_key()
    return pu_key

def pu_key_to_bytes(pu_key_obj):
    """
    converts a public key objet to bytes to send over the network
    """
    pu_key_bytes = pu_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pu_key_bytes

def pu_key_to_obj(pu_key_bytes):
    """
    converts a bytes to a public key object
    """
    pu_key_obj = serialization.load_pem_public_key(pu_key_bytes)
    return pu_key_obj
    