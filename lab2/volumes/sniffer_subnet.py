#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

# Capture packets from or to a particular subnet
pkt = sniff(iface='br-46f4ebc25eee', filter='net 128.230.0.0/16', prn=print_pkt)
