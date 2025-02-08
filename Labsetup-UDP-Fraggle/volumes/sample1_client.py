#!/bin/env python3
import socket

# TODO: IP & port configuration
# Tip: suffix
IP_dst = "0.0.0.0"
port_dst = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
data = b"Hello, Server!!\n"

# TODO: binding
sock.bind(("0.0.0.0",9090))
sock.sendto(data, (IP_dst, port_dst))

print("UDP packet is sent")
