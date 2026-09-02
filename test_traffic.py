#!/usr/bin/env python3
"""
Generate test traffic for CyberOctet testing
"""

import time
import socket
import threading
from scapy.all import IP, TCP, UDP, ICMP, Ether, sr1, send

def generate_http_traffic():
    """Generate HTTP-like traffic"""
    try:
        # Create a TCP packet to port 80
        packet = Ether()/IP(dst="8.8.8.8")/TCP(dport=80, sport=12345)
        send(packet, verbose=False)
        print("Generated HTTP-like traffic")
    except:
        print("Could not generate HTTP traffic")

def generate_dns_traffic():
    """Generate DNS-like traffic"""
    try:
        # Create a UDP packet to port 53 (DNS)
        packet = Ether()/IP(dst="8.8.8.8")/UDP(dport=53, sport=54321)/b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        send(packet, verbose=False)
        print("Generated DNS traffic")
    except:
        print("Could not generate DNS traffic")

def generate_ping_traffic():
    """Generate ICMP ping traffic"""
    try:
        # Create ICMP echo request
        packet = Ether()/IP(dst="8.8.8.8")/ICMP()
        send(packet, verbose=False)
        print("Generated ICMP ping traffic")
    except:
        print("Could not generate ICMP traffic")

def generate_tcp_traffic():
    """Generate general TCP traffic"""
    try:
        # Create TCP SYN packet
        packet = Ether()/IP(dst="1.1.1.1")/TCP(dport=443, sport=54321, flags="S")
        send(packet, verbose=False)
        print("Generated TCP SYN traffic")
    except:
        print("Could not generate TCP traffic")

def main():
    """Generate various types of test traffic"""
    print("🔄 Generating test traffic for CyberOctet...")
    print("Make sure CyberOctet is running and capturing packets!")
    print("=" * 50)
    
    # Generate different types of traffic
    traffic_generators = [
        generate_ping_traffic,
        generate_dns_traffic,
        generate_http_traffic,
        generate_tcp_traffic
    ]
    
    for i, generator in enumerate(traffic_generators, 1):
        print(f"\n{i}. ", end="")
        generator()
        time.sleep(1)  # Wait between packets
    
    print("\n✅ Test traffic generation complete!")
    print("Check CyberOctet for captured packets.")

if __name__ == "__main__":
    main()
