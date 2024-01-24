#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	print('Sniffing packets...')
	pkt.show()
	
pkt = sniff(iface='br-46f4ebc25eee', filter='icmp', prn=print_pkt)