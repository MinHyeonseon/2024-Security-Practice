#!/usr/bin/env python3
from scapy.all import *

IP_V = 
MAC_V_real = 
IP_T = 
MAC_T_fake = 

ether = Ether(src = MAC_T_fake, dst = )
arp = ARP(psrc = , hwsrc = , pdst = )

arp.op = 

frame = ether/arp
sendp(frame)
