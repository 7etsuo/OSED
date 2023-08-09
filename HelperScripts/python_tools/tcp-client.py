import socket

target_host = "127.0.0.1"
target_port = 9998


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))

    client.send(b"AAAABBBBCCCC\r\n")
    response = client.recv(4096)

    print(response.decode("utf-8"))
    client.close()


if __name__ == '__main__':
    main()
