"""
Patient vitals Monitoring Server
Receives data from a patient monitor using TCP

Author: Kashmain Tahir
"""

import socket


def start_monitoring_station():
    """
    creates a server socket to receive data from client monitors
    """

    try:

        HOST = '127.0.0.1'
        PORT = 9000

        # set up
        station_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        station_socket.bind((HOST, PORT))
        station_socket.listen()
        print_server("Monitoring Station waiting for incoming connections...")

        # accept the connection from the client
        connection_socket, connection_addr = station_socket.accept()

        data = b""
        # keep receiving data until all is done

        CHUNK_SIZE = 1024
        while True:
            incoming_data = connection_socket.recv(CHUNK_SIZE)
            
            if not incoming_data:
                break
            else:
                data += incoming_data

        # data = connection_socket.recv(1024)

        print_server("data received")
        print(data.decode())

        connection_socket.close()
        station_socket.close()


    except Exception as error:
        print(f"SERVER -- could not start monitoring station: {error}")


def print_server(text):
    """
    helper function to print statements from the server
    Args:
        text: the string to output
    """

    print(f"SERVER -- {text}")


def main():
    start_monitoring_station()

if __name__ == "__main__":
    main()