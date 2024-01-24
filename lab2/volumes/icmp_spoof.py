#!/usr/bin/env python3
from scapy.all import *
print('Sending spoofed icmp packet')
a = IP()
a.dst = '10.0.2.3' 
b = ICMP()
a.show()
b.show() 
p = a/b 
send(p)