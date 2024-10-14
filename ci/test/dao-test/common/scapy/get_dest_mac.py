#!/usr/bin/python3
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2024 Marvell.

import sys
from scapy.all import rdpcap

# Define a function to print all destination MAC addresses from a pcap file
def print_destination_mac_addresses(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Iterate over each packet in the pcap file
    for packet in packets:
        # Check if the packet has an Ethernet layer
        if packet.haslayer('Ether'):
            # Print the destination MAC address
            print(packet['Ether'].dst)

# Check if the script is run with a pcap file argument
if len(sys.argv) != 2:
    print("Usage: python script.py <pcap_file>")
else:
    # Call the function with the pcap file provided as an argument
    print_destination_mac_addresses(sys.argv[1])

