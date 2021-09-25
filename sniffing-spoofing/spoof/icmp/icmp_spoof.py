#!/usr/bin/python3
from scapy.all import *
import time


#print("SENDING SPOOFED ICMP PACKET.........")
pstart = time.time()
ip = IP(src="1.2.3.4", dst="10.0.2.7") 
icmp = ICMP()                               
pkt = ip/icmp                                
print("python creating packet time :", time.time() - pstart)
#pkt.show()
start= time.time()
for i in range(100):
    send(pkt,verbose=0)                          

print("python icmp spoofing time (100) :", time.time() - start)
