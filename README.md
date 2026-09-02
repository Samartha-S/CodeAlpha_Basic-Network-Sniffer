# CodeAlpha_Basic-Network-Sniffer

A simple Python network packet sniffer built with Scapy. It captures live packets on your network interface and displays:

Source IP
Destination IP
Protocol (TCP / UDP / ICMP / OTHER)
Packet size (bytes)
A preview of the payload (up to 64 bytes, decoded as UTF-8)
Requirements
Python 3.6+
Scapy
Root / administrator privileges (raw socket access)
Installation
sudo pip3 install scapy
Usage
sudo python3 packet_sniffer.py
Press Ctrl+C to stop capturing.

Example output
Starting packet sniffer... (Press Ctrl+C to stop)

--------------------------------------------------------------------------------
Source IP      : 142.250.190.78
Destination IP : 192.168.1.10
Protocol       : TCP
Packet Size    : 74 bytes
Payload        : <no data>
--------------------------------------------------------------------------------
Notes
Packet capture requires elevated privileges because it needs to open a raw socket.
On Windows, install Npcap and run the script from an Administrator terminal.
Only IP packets are processed (the BPF filter is set to ip).
License
MIT
