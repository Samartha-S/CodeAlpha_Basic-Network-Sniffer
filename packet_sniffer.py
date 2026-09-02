#!/usr/bin/env python3
"""
Simple Network Packet Sniffer using Scapy
Captures packets and displays source IP, destination IP, protocol, packet size, and basic payload data.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import sys


def analyze_packet(packet):
    """
    Callback function that processes each captured packet.
    Extracts and prints relevant information.
    """
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]

    protocol = "OTHER"
    payload_preview = ""

    if packet.haslayer(TCP):
        protocol = "TCP"
        if packet.haslayer(Raw):
            payload_bytes = bytes(packet[Raw].load)
            payload_preview = payload_bytes[:64].decode("utf-8", errors="replace").strip()
    elif packet.haslayer(UDP):
        protocol = "UDP"
        if packet.haslayer(Raw):
            payload_bytes = bytes(packet[Raw].load)
            payload_preview = payload_bytes[:64].decode("utf-8", errors="replace").strip()
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    packet_size = len(packet)

    print("-" * 80)
    print(f"Source IP      : {ip_layer.src}")
    print(f"Destination IP : {ip_layer.dst}")
    print(f"Protocol       : {protocol}")
    print(f"Packet Size    : {packet_size} bytes")
    if payload_preview:
        print(f"Payload        : {payload_preview}")
    else:
        print(f"Payload        : <no data>")
    print("-" * 80)


def main():
    print("Starting packet sniffer... (Press Ctrl+C to stop)\n")

    try:
        sniff(filter="ip", prn=analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\n\nSniffer stopped.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        print("Note: Packet capture usually requires root privileges.")
        sys.exit(1)


if __name__ == "__main__":
    main()
