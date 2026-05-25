"""
Patient Monitor Client
Reads hourly vitals of a single patient and sends it to the server

Author: Kashmain Tahir
"""

import socket

def connect_to_station():
    """
    creates a socket to connect to the server 
    """

    try:

        HOST = '127.0.0.1'
        PORT = 9000

        # set up
        monitor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        monitor_socket.connect((HOST, PORT))
        print("Connected to server")

        # send data

        with open("data/test_normal.txt", "r") as file:
            patient_data = file.read()

        monitor_socket.sendall(patient_data.encode())
        print("Data sent to Monitoring Station")

        monitor_socket.close()


    except Exception as error:
        print(f"could not start patient monitor: {error}")



def print_client(text):
    """
    helper function to print statements from the client
    Args:
        text: the string to output
    """

    print(f"CLIENT -- {text}")


def main():
    connect_to_station()

if __name__ == "__main__":
    main()