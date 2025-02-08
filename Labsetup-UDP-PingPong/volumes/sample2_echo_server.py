#!/bin/env python3
import socket

# TODO: IP & port configuration
# Tip: suffix
IP_bind = "0.0.0.0"
port_server = 7

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_bind,port_server))

print("UDP echo server is running ...")

while True:
	data, (ip_src, port_src) = sock.recvfrom(1024)
	print("Sender: {} and Port: {}".format(ip_src, port_src))
	print("Received message: {}".format(data))

	# Send back reply with the copied data
	sock.sendto(data,(ip_src,port_src))
