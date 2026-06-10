"""
Script to generate rsa key pairs

Author: Kashmain Tahir
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_key_pair(pr_key_file, pu_key_file):
    pr_key = generate_rsa_pr_key(pr_key_file)
    generate_rsa_pu_key(pr_key, pu_key_file)

def generate_rsa_pr_key(pr_key_file):
    print("generating rsa pr key")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(pr_key_file, "wb") as pr_file:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pr_file.write(pem)

    return private_key


def generate_rsa_pu_key(private_key, pu_key_file):
    print("generating rsa pu key")
    public_key = private_key.public_key()

    with open(pu_key_file, "wb") as pu_file:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pu_file.write(pem)


def main():
    generate_rsa_key_pair("keys/server_pr.pem", "keys/server_pu.pem")
    generate_rsa_key_pair("keys/client_pr.pem", "keys/client_pu.pem")
    print("all rsa keys generated")

if __name__ == "__main__":
    main()
