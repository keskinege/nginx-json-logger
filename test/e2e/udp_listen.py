import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5514))
while True:
    data, _ = s.recvfrom(65535)
    print(data.decode("utf-8", "replace"), flush=True)
