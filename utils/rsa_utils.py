"""
Utility Class with functions for the implmentation of RSA

Author: Kashmain Tahir
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def read_private_key(pr_key_file):
    with open(pr_key_file, "rb") as pr_file:
        private_key = serialization.load_pem_private_key(
            pr_file.read(),
            password=None,
        )
    return private_key
        
def read_public_key(pu_key_file):
    with open(pu_key_file, "rb") as pu_file:
        public_key = serialization.load_pem_public_key(
            pu_file.read()
        )
    return public_key

def sign_data(private_key, data):
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
    

# pr_key = read_private_key("keys/server_pr.pem")
# pu_key = read_public_key("keys/server_pu.pem")

# message = b"Hello World"
# signature = sign_data(pr_key, message)

# # message2 = b"hello World"
# # pr_key2 = read_private_key("keys/client_pr.pem")
# # signature2 = sign_data(pr_key2, message)

# print(verify_signature(
#     pu_key,
#     signature,
#     message
# ))
