import socket


def connect_to_station():

    try:

        # set up
        monitor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        monitor_socket.connect(('127.0.0.1', 9000))
        print("CLIENT --Connected to server")

        sample_data = """patient id: 100\nheart rate: 100\noxygen:100%"""
        monitor_socket.sendall(sample_data.encode())
        print("CLIENT -- data sent")

        monitor_socket.close()


    except Exception as error:
        print(f"CLIENT -- could not start patient monitor: {error}")


def main():
    connect_to_station()


if __name__ == "__main__":
    main()