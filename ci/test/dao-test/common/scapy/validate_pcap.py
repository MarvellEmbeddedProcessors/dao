#!/usr/bin/python3
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

import sys
import difflib
from scapy.all import *

if len(sys.argv) < 3:
	print("Usage validate_pcap.py [tx_pcap_file] [rx_pcap_file]\n")
	exit(1)

sent_file = None
recv_file = None
sent_file_name = "/tmp/sent.txt"
recv_file_name = "/tmp/recv.txt"
good_pkts_count = 0
total_pkts_count = 0

def check_sanity(xmit_list, recv_list):
	global sent_file
	global recv_file
	global good_pkts_count
	global total_pkts_count
	if not sent_file:
		sent_file = open(sent_file_name, "wb+")
	if not recv_file:
		recv_file = open(recv_file_name, "wb+")

	itr = 0
	for pkt in xmit_list:
		if len(xmit_list) != len(recv_list):
			break

		recv_pkt = recv_list[itr]
		itr = itr + 1

		sent_buf = pkt.show2(dump=True)
		sent_file.write(bytes(sent_buf, 'UTF-8'))

		recv_buf = recv_pkt.show2(dump=True)
		recv_file.write(bytes(recv_buf, 'UTF-8'))

		diff = difflib.unified_diff(sent_buf.splitlines(1), recv_buf.splitlines(1), fromfile='expected', tofile='received')
		good=1
		for line in diff:
			good=0
		good_pkts_count = good_pkts_count + good
	# Close files
	sent_file.close()
	recv_file.close()
	return

if __name__ == "__main__":
	if len(sys.argv) > 2:
		tx_pcap_file = sys.argv[1]
		rx_pcap_file = sys.argv[2]

	recv_list = sniff(offline=rx_pcap_file)
	xmit_list = sniff(offline=tx_pcap_file)
	total_pkts_count = len(xmit_list)
	if total_pkts_count != 0:
		check_sanity(xmit_list, recv_list)

	if (total_pkts_count != good_pkts_count):
		print("1")
