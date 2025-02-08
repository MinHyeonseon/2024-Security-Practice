#!/bin/env python3
import socket

# TODO: IP & port configuration
# Tip: suffix
IP_dst = "127.0.0.1"
port_dst = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
data = b"Hello, Server!!\n"

# TODO: binding
sock.bind((IP_dst,7777))
sock.sendto(data, (IP_dst, port_dst))

print("UDP packet is sent")
