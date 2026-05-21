import socket


def start_monitoring_station():

    try:

        # set up
        station_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        station_socket.bind(('127.0.0.1', 9000))
        station_socket.listen()
        print("SERVER -- Monitoring Station waiting for incoming connections...")

        # accept
        connection_socket, connection_addr = station_socket.accept()
        data = connection_socket.recv(1024)
        print("SERVER -- data received")
        print(data.decode())

        connection_socket.close()
        station_socket.close()


    except Exception as error:
        print(f"SERVER -- could not start monitoring station: {error}")


def main():
    start_monitoring_station()


if __name__ == "__main__":
    main()