#!/usr/bin/env python3

import scapy.all as scapy
import time

mac_list = []

def scan_network():
    # Define the range of IP addresses to scan - Will define the target IP in the file.
    ip_range = "192.168.1.1/24"

    # Create an ARP request packet to send to the broadcast MAC address
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and capture the responses
    answered, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    # Check if the MAC address has already been seen before
    for packet in answered:
        mac_address = packet[1].hwsrc
        if mac_address not in mac_list:
            mac_list.append(mac_address)
            print(f"New device detected! IP: {packet[1].psrc}\tMAC: {mac_address}")


if __name__ == '__main__':
    while True:
        scan_network()
        time.sleep(10)  # wait 10 seconds before scanning again
