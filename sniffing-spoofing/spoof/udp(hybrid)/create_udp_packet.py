#!/usr/bin/python3

from scapy.all import *

IPpkt = IP(dst='10.0.2.7', chksum=0)
UDPpkt = UDP(dport=9090, chksum=0)
data="Create UDP Packet By Python!\n"
pkt = IPpkt/UDPpkt/data


with open('ip.bin', 'wb') as f:
    f.write(bytes(pkt))
