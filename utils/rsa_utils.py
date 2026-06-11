"""
Utility Class with functions for the implmentation of RSA

Author: Kashmain Tahir
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def read_private_key(pr_key_file):
    """
    Reads an RSA private key from a PEM file and loads it
    """
    with open(pr_key_file, "rb") as pr_file:
        private_key = serialization.load_pem_private_key(
            pr_file.read(),
            password=None,
        )

    return private_key
        
def read_public_key(pu_key_file):
    """
    Reads an RSA public key from a PEM file and loads it
    """
    with open(pu_key_file, "rb") as pu_file:
        public_key = serialization.load_pem_public_key(
            pu_file.read()
        )

    return public_key

def sign_data(private_key, data):
    """
    Generates a digital signature for the given data based on the private key
    """

    signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    return signature

def verify_signature(public_key, signature, data):
    """
    Verifies the digital signature for the given data based on the public key
    """

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True
    
    except Exception:
        return False