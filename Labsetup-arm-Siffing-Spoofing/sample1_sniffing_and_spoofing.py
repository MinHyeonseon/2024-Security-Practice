#!/usr/bin/python3
from scapy.all import *

my_iface = 'br-3cbef7265634'
my_filter = 'icmp and src host 10.9.0.6'


def spoof_pkt(pkt):
	if ICMP in pkt and pkt[ICMP].type == 8:
		print("----------------------")
		print("Original Packet...")
		print("Source IP: ", pkt[IP].src)
		print("Destination IP: ", pkt[IP].dst)

		ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl, ttl=50)
		icmp = ICMP(id=pkt[ICMP].id, type=0, seq=pkt[ICMP].seq )

		data = pkt[Raw].load
		newpkt = ip/icmp/data
		print("-----------------------")
		print("Spoofed source IP: ", newpkt[IP].src)
		print("Spoofed destination IP: ", newpkt[IP].dst)
		print()

		send(newpkt, verbose=0)


pkt = sniff(iface=my_iface, filter=my_filter,prn=spoof_pkt)
