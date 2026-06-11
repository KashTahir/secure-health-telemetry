"""
Script to generate rsa key pairs

Author: Kashmain Tahir
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_key_pair(pr_key_file, pu_key_file):
    """
    Generates RSA key pairs and saves them into appropriate files
    """
    pr_key = generate_rsa_pr_key(pr_key_file)
    generate_rsa_pu_key(pr_key, pu_key_file)

def generate_rsa_pr_key(pr_key_file):
    """
    Generates RSA private key and saves it into a PEM file
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # write the private key to the file
    with open(pr_key_file, "wb") as pr_file:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pr_file.write(pem)

    return private_key


def generate_rsa_pu_key(private_key, pu_key_file):
    """
    Generates RSA public key and saves it into a PEM file
    """
    public_key = private_key.public_key()

    # write the public key to the file
    with open(pu_key_file, "wb") as pu_file:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pu_file.write(pem)


def main():
    """
    Generate RSA key pairs for the server and client
    """
    print("Generating RSA key pairs...")
    generate_rsa_key_pair("keys/server_pr.pem", "keys/server_pu.pem")
    print("Server RSA key pairs successfully generated")
    generate_rsa_key_pair("keys/client_pr.pem", "keys/client_pu.pem")
    print("Client RSA key pairs successfully generated")

if __name__ == "__main__":
    main()
