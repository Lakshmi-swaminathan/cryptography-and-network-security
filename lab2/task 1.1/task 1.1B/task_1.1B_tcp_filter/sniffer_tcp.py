#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	print('Sniffing TCP packet...')
	pkt.show()

# Capturing TCP packets from IP address 10.9.0.5(Host A) with destination port 23
pkt = sniff(iface='br-46f4ebc25eee', filter='tcp and host 10.9.0.5 and dst port 23', prn=print_pkt)
