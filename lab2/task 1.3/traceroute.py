#!/usr/bin/env python3
from scapy.all import *
while True:
	a = IP()
	a.dst = sys.argv[1] 
	ttl = 3

	a.ttl = ttl
	b = ICMP()
	p = a/b 
	resp = sr1(p, timeout=2, verbose=0)

	if resp is None:
		print("No reply")
	elif resp[ICMP].type == 0 :
		print("%d hops away: " % (a.ttl), resp[IP].src)
		print("Done", resp[IP].src)
	else :
		print("%d hops away: " % (a.ttl), resp[IP].src)
	
	if ttl==30:
		break
