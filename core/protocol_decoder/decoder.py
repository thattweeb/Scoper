"""
Comprehensive Protocol Decoder for CyberOctet
Decodes all common network protocols with detailed field extraction
"""

import struct
import socket
import binascii
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DHCP
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.packet import Packet

from core.config import Config


@dataclass
class ProtocolField:
    """Represents a single protocol field"""
    name: str
    value: Any
    offset: int
    length: int
    description: str
    hex_value: str = ""
    
    def __post_init__(self):
        if isinstance(self.value, bytes):
            self.hex_value = binascii.hexlify(self.value).decode('ascii')


@dataclass
class ProtocolLayer:
    """Represents a protocol layer in the packet"""
    name: str
    fields: List[ProtocolField]
    raw_data: bytes
    offset: int
    description: str
    length: int = 0  # Length of this protocol layer
    
    def __post_init__(self):
        """Calculate length from raw_data if not set"""
        if self.length == 0:
            self.length = len(self.raw_data)


class ProtocolDecoder:
    """Main protocol decoder class"""
    
    def __init__(self):
        self.protocol_parsers = {
            'ethernet': self._parse_ethernet,
            'arp': self._parse_arp,
            'ipv4': self._parse_ipv4,
            'ipv6': self._parse_ipv6,
            'tcp': self._parse_tcp,
            'udp': self._parse_udp,
            'icmp': self._parse_icmp,
            'dns': self._parse_dns,
            'dhcp': self._parse_dhcp,
            'http': self._parse_http,
        }
    
    def decode_packet(self, packet_data: bytes, packet_info) -> List[ProtocolLayer]:
        """Decode a complete packet into protocol layers"""
        layers = []
        
        try:
            # Parse with Scapy first
            from scapy.all import Ether
            scapy_packet = Ether(packet_data)
            
            # Parse Ethernet layer
            if Ether in scapy_packet:
                eth_layer = self._parse_ethernet(scapy_packet[Ether], 0)
                layers.append(eth_layer)
                
                # Parse subsequent layers based on Ether type
                eth_type = scapy_packet[Ether].type
                
                if eth_type == 0x0800:  # IPv4
                    if IP in scapy_packet:
                        ip_layer = self._parse_ipv4(scapy_packet[IP], eth_layer.offset + eth_layer.length)
                        layers.append(ip_layer)
                        
                        # Parse transport layer
                        self._parse_transport_layer(scapy_packet, layers, ip_layer.offset + ip_layer.length)
                        
                elif eth_type == 0x86DD:  # IPv6
                    if IPv6 in scapy_packet:
                        ipv6_layer = self._parse_ipv6(scapy_packet[IPv6], eth_layer.offset + eth_layer.length)
                        layers.append(ipv6_layer)
                        
                        # Parse transport layer for IPv6
                        self._parse_transport_layer(scapy_packet, layers, ipv6_layer.offset + ipv6_layer.length)
                        
                elif eth_type == 0x0806:  # ARP
                    if ARP in scapy_packet:
                        arp_layer = self._parse_arp(scapy_packet[ARP], eth_layer.offset + eth_layer.length)
                        layers.append(arp_layer)
            
        except Exception as e:
            print(f"Error decoding packet: {e}")
            # Add raw layer as fallback
            layers.append(ProtocolLayer(
                name="Raw",
                fields=[ProtocolField("data", packet_data, 0, len(packet_data), "Raw packet data")],
                raw_data=packet_data,
                offset=0,
                description="Undecoded packet data"
            ))
        
        return layers
    
    def _parse_transport_layer(self, scapy_packet: Packet, layers: List[ProtocolLayer], base_offset: int):
        """Parse transport layer protocols"""
        if TCP in scapy_packet:
            tcp_layer = self._parse_tcp(scapy_packet[TCP], base_offset)
            layers.append(tcp_layer)
            
            # Parse application layers for TCP
            self._parse_application_layer_tcp(scapy_packet, layers, base_offset + tcp_layer.length)
            
        elif UDP in scapy_packet:
            udp_layer = self._parse_udp(scapy_packet[UDP], base_offset)
            layers.append(udp_layer)
            
            # Parse application layers for UDP
            self._parse_application_layer_udp(scapy_packet, layers, base_offset + udp_layer.length)
    
    def _parse_application_layer_tcp(self, scapy_packet: Packet, layers: List[ProtocolLayer], base_offset: int):
        """Parse TCP application layer protocols"""
        if HTTP in scapy_packet or HTTPRequest in scapy_packet or HTTPResponse in scapy_packet:
            http_layer = self._parse_http(scapy_packet, base_offset)
            layers.append(http_layer)
    
    def _parse_application_layer_udp(self, scapy_packet: Packet, layers: List[ProtocolLayer], base_offset: int):
        """Parse UDP application layer protocols"""
        if DNS in scapy_packet:
            dns_layer = self._parse_dns(scapy_packet[DNS], base_offset)
            layers.append(dns_layer)
        elif DHCP in scapy_packet:
            dhcp_layer = self._parse_dhcp(scapy_packet[DHCP], base_offset)
            layers.append(dhcp_layer)
    
    def _parse_ethernet(self, eth_packet: Ether, offset: int) -> ProtocolLayer:
        """Parse Ethernet II header"""
        fields = [
            ProtocolField("Destination MAC", eth_packet.dst, offset, 6, "Destination MAC address"),
            ProtocolField("Source MAC", eth_packet.src, offset + 6, 6, "Source MAC address"),
            ProtocolField("EtherType", f"0x{eth_packet.type:04x}", offset + 12, 2, 
                         self._get_ether_type_name(eth_packet.type)),
        ]
        
        return ProtocolLayer(
            name="Ethernet II",
            fields=fields,
            raw_data=bytes(eth_packet),
            offset=offset,
            description="Ethernet II frame header"
        )
    
    def _parse_arp(self, arp_packet: ARP, offset: int) -> ProtocolLayer:
        """Parse ARP packet"""
        fields = [
            ProtocolField("Hardware Type", arp_packet.hwtype, offset, 2, "Type of hardware address"),
            ProtocolField("Protocol Type", f"0x{arp_packet.ptype:04x}", offset + 2, 2, "Protocol address type"),
            ProtocolField("Hardware Length", arp_packet.hwlen, offset + 4, 1, "Length of hardware address"),
            ProtocolField("Protocol Length", arp_packet.plen, offset + 5, 1, "Length of protocol address"),
            ProtocolField("Operation", arp_packet.op, offset + 6, 2, 
                         "Request (1) or Reply (2)" if arp_packet.op in [1, 2] else str(arp_packet.op)),
            ProtocolField("Sender MAC", arp_packet.hwsrc, offset + 8, 6, "Sender hardware address"),
            ProtocolField("Sender IP", arp_packet.psrc, offset + 14, 4, "Sender protocol address"),
            ProtocolField("Target MAC", arp_packet.hwdst, offset + 18, 6, "Target hardware address"),
            ProtocolField("Target IP", arp_packet.pdst, offset + 24, 4, "Target protocol address"),
        ]
        
        return ProtocolLayer(
            name="ARP",
            fields=fields,
            raw_data=bytes(arp_packet),
            offset=offset,
            description="Address Resolution Protocol"
        )
    
    def _parse_ipv4(self, ip_packet: IP, offset: int) -> ProtocolLayer:
        """Parse IPv4 header"""
        flags = ip_packet.flags
        flag_str = f"DF={bool(flags & 0x2)}, MF={bool(flags & 0x1)}"
        
        fields = [
            ProtocolField("Version", ip_packet.version, offset, 1, "IP version (4)"),
            ProtocolField("Header Length", ip_packet.ihl, offset, 1, "Header length in 32-bit words"),
            ProtocolField("Type of Service", f"0x{ip_packet.tos:02x}", offset + 1, 1, "Differentiated Services"),
            ProtocolField("Total Length", ip_packet.len, offset + 2, 2, "Total packet length"),
            ProtocolField("Identification", ip_packet.id, offset + 4, 2, "Packet identification"),
            ProtocolField("Flags", flag_str, offset + 6, 1, "Fragmentation flags"),
            ProtocolField("Fragment Offset", ip_packet.frag, offset + 6, 2, "Fragment offset"),
            ProtocolField("TTL", ip_packet.ttl, offset + 8, 1, "Time to live"),
            ProtocolField("Protocol", ip_packet.proto, offset + 9, 1, self._get_ip_proto_name(ip_packet.proto)),
            ProtocolField("Header Checksum", f"0x{ip_packet.chksum:04x}", offset + 10, 2, "Header checksum"),
            ProtocolField("Source IP", ip_packet.src, offset + 12, 4, "Source IP address"),
            ProtocolField("Destination IP", ip_packet.dst, offset + 16, 4, "Destination IP address"),
        ]
        
        # Add options if present
        if ip_packet.options:
            opt_offset = offset + 20
            for i, opt in enumerate(ip_packet.options):
                fields.append(ProtocolField(f"Option {i+1}", opt, opt_offset, len(opt), "IP option"))
                opt_offset += len(opt)
        
        return ProtocolLayer(
            name="IPv4",
            fields=fields,
            raw_data=bytes(ip_packet),
            offset=offset,
            description="Internet Protocol version 4"
        )
    
    def _parse_ipv6(self, ipv6_packet: IPv6, offset: int) -> ProtocolLayer:
        """Parse IPv6 header"""
        fields = [
            ProtocolField("Version", ipv6_packet.version, offset, 4, "IP version (6)"),
            ProtocolField("Traffic Class", f"0x{ipv6_packet.tc:02x}", offset, 1, "Differentiated Services"),
            ProtocolField("Flow Label", ipv6_packet.fl, offset, 3, "Flow label"),
            ProtocolField("Payload Length", ipv6_packet.plen, offset + 4, 2, "Payload length"),
            ProtocolField("Next Header", ipv6_packet.nh, offset + 6, 1, self._get_ip_proto_name(ipv6_packet.nh)),
            ProtocolField("Hop Limit", ipv6_packet.hlim, offset + 7, 1, "Hop limit"),
            ProtocolField("Source IP", ipv6_packet.src, offset + 8, 16, "Source IPv6 address"),
            ProtocolField("Destination IP", ipv6_packet.dst, offset + 24, 16, "Destination IPv6 address"),
        ]
        
        return ProtocolLayer(
            name="IPv6",
            fields=fields,
            raw_data=bytes(ipv6_packet),
            offset=offset,
            description="Internet Protocol version 6"
        )
    
    def _parse_tcp(self, tcp_packet: TCP, offset: int) -> ProtocolLayer:
        """Parse TCP header"""
        flags = tcp_packet.flags
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        if flags & 0x40: flag_names.append("ECE")
        if flags & 0x80: flag_names.append("CWR")
        
        fields = [
            ProtocolField("Source Port", tcp_packet.sport, offset, 2, "Source TCP port"),
            ProtocolField("Destination Port", tcp_packet.dport, offset + 2, 2, "Destination TCP port"),
            ProtocolField("Sequence Number", tcp_packet.seq, offset + 4, 4, "Sequence number"),
            ProtocolField("Acknowledgment Number", tcp_packet.ack, offset + 8, 4, "Acknowledgment number"),
            ProtocolField("Header Length", tcp_packet.dataofs, offset + 12, 1, "Header length in 32-bit words"),
            ProtocolField("Flags", f"0x{flags:02x} ({', '.join(flag_names)})", offset + 13, 1, "TCP flags"),
            ProtocolField("Window Size", tcp_packet.window, offset + 14, 2, "Receive window size"),
            ProtocolField("Checksum", f"0x{tcp_packet.chksum:04x}", offset + 16, 2, "TCP checksum"),
            ProtocolField("Urgent Pointer", tcp_packet.urgptr, offset + 18, 2, "Urgent pointer"),
        ]
        
        # Add options if present
        if tcp_packet.options:
            opt_offset = offset + 20
            for i, opt in enumerate(tcp_packet.options):
                fields.append(ProtocolField(f"Option {i+1}", opt, opt_offset, len(opt), "TCP option"))
                opt_offset += len(opt)
        
        return ProtocolLayer(
            name="TCP",
            fields=fields,
            raw_data=bytes(tcp_packet),
            offset=offset,
            description="Transmission Control Protocol"
        )
    
    def _parse_udp(self, udp_packet: UDP, offset: int) -> ProtocolLayer:
        """Parse UDP header"""
        fields = [
            ProtocolField("Source Port", udp_packet.sport, offset, 2, "Source UDP port"),
            ProtocolField("Destination Port", udp_packet.dport, offset + 2, 2, "Destination UDP port"),
            ProtocolField("Length", udp_packet.len, offset + 4, 2, "UDP header + data length"),
            ProtocolField("Checksum", f"0x{udp_packet.chksum:04x}", offset + 6, 2, "UDP checksum"),
        ]
        
        return ProtocolLayer(
            name="UDP",
            fields=fields,
            raw_data=bytes(udp_packet),
            offset=offset,
            description="User Datagram Protocol"
        )
    
    def _parse_icmp(self, icmp_packet: ICMP, offset: int) -> ProtocolLayer:
        """Parse ICMP header"""
        fields = [
            ProtocolField("Type", icmp_packet.type, offset, 1, self._get_icmp_type_name(icmp_packet.type)),
            ProtocolField("Code", icmp_packet.code, offset + 1, 1, "ICMP code"),
            ProtocolField("Checksum", f"0x{icmp_packet.chksum:04x}", offset + 2, 2, "ICMP checksum"),
        ]
        
        # Add type-specific fields
        if icmp_packet.type == 0:  # Echo Reply
            fields.extend([
                ProtocolField("Identifier", icmp_packet.id, offset + 4, 2, "Echo identifier"),
                ProtocolField("Sequence Number", icmp_packet.seq, offset + 6, 2, "Echo sequence number"),
            ])
        elif icmp_packet.type == 8:  # Echo Request
            fields.extend([
                ProtocolField("Identifier", icmp_packet.id, offset + 4, 2, "Echo identifier"),
                ProtocolField("Sequence Number", icmp_packet.seq, offset + 6, 2, "Echo sequence number"),
            ])
        
        return ProtocolLayer(
            name="ICMP",
            fields=fields,
            raw_data=bytes(icmp_packet),
            offset=offset,
            description="Internet Control Message Protocol"
        )
    
    def _parse_dns(self, dns_packet: DNS, offset: int) -> ProtocolLayer:
        """Parse DNS packet"""
        fields = [
            ProtocolField("Transaction ID", f"0x{dns_packet.id:04x}", offset, 2, "DNS transaction ID"),
            ProtocolField("Flags", f"0x{dns_packet.qr:04x}", offset + 2, 2, "DNS flags"),
            ProtocolField("Questions", dns_packet.qdcount, offset + 4, 2, "Number of questions"),
            ProtocolField("Answer RRs", dns_packet.ancount, offset + 6, 2, "Number of answers"),
            ProtocolField("Authority RRs", dns_packet.nscount, offset + 8, 2, "Number of authority records"),
            ProtocolField("Additional RRs", dns_packet.arcount, offset + 10, 2, "Number of additional records"),
        ]
        
        # Add questions
        if dns_packet.qd:
            for i, q in enumerate(dns_packet.qd):
                fields.append(ProtocolField(f"Question {i+1}", q.qname, offset, 0, f"Query: {q.qname} (type {q.qtype})"))
        
        # Add answers
        if dns_packet.an:
            for i, a in enumerate(dns_packet.an):
                fields.append(ProtocolField(f"Answer {i+1}", a.rrname, offset, 0, f"Answer: {a.rrname} -> {a.rdata}"))
        
        return ProtocolLayer(
            name="DNS",
            fields=fields,
            raw_data=bytes(dns_packet),
            offset=offset,
            description="Domain Name System"
        )
    
    def _parse_dhcp(self, dhcp_packet: DHCP, offset: int) -> ProtocolLayer:
        """Parse DHCP packet"""
        fields = [
            ProtocolField("Message Type", dhcp_packet.options.get('message-type', 'Unknown'), offset, 1, "DHCP message type"),
            ProtocolField("Transaction ID", f"0x{dhcp_packet.xid:08x}", offset + 4, 4, "DHCP transaction ID"),
            ProtocolField("Seconds", dhcp_packet.secs, offset + 8, 2, "Seconds elapsed"),
            ProtocolField("Flags", f"0x{dhcp_packet.flags:04x}", offset + 10, 2, "DHCP flags"),
            ProtocolField("Client IP", dhcp_packet.ciaddr, offset + 12, 4, "Client IP address"),
            ProtocolField("Your IP", dhcp_packet.yiaddr, offset + 16, 4, "Your IP address"),
            ProtocolField("Server IP", dhcp_packet.siaddr, offset + 20, 4, "Server IP address"),
            ProtocolField("Gateway IP", dhcp_packet.giaddr, offset + 24, 4, "Gateway IP address"),
            ProtocolField("Client MAC", dhcp_packet.chaddr[:6], offset + 28, 6, "Client hardware address"),
        ]
        
        return ProtocolLayer(
            name="DHCP",
            fields=fields,
            raw_data=bytes(dhcp_packet),
            offset=offset,
            description="Dynamic Host Configuration Protocol"
        )
    
    def _parse_http(self, scapy_packet: Packet, offset: int) -> ProtocolLayer:
        """Parse HTTP packet"""
        fields = []
        
        # Try to extract HTTP data
        if hasattr(scapy_packet, 'payload'):
            payload = scapy_packet.payload
            if hasattr(payload, 'payload'):
                http_payload = payload.payload
                if http_payload:
                    http_data = bytes(http_payload).decode('utf-8', errors='ignore')
                    
                    # Parse HTTP request/response
                    lines = http_data.split('\r\n')
                    if lines:
                        # First line is request/response line
                        fields.append(ProtocolField("HTTP Line", lines[0], offset, len(lines[0]), "HTTP request/response line"))
                        
                        # Parse headers
                        for i, line in enumerate(lines[1:]):
                            if ':' in line:
                                header_name, header_value = line.split(':', 1)
                                fields.append(ProtocolField(f"Header: {header_name.strip()}", 
                                                         header_value.strip(), 
                                                         offset, 0, f"HTTP header"))
                            elif not line.strip():  # Empty line indicates end of headers
                                break
        
        return ProtocolLayer(
            name="HTTP",
            fields=fields,
            raw_data=b'',
            offset=offset,
            description="Hypertext Transfer Protocol"
        )
    
    def _get_ether_type_name(self, ether_type: int) -> str:
        """Get Ethernet type name"""
        ether_types = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8035: "RARP",
            0x8100: "802.1Q VLAN",
        }
        return ether_types.get(ether_type, f"Unknown (0x{ether_type:04x})")
    
    def _get_ip_proto_name(self, proto: int) -> str:
        """Get IP protocol name"""
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            58: "ICMPv6",
        }
        return protocols.get(proto, f"Unknown ({proto})")
    
    def _get_icmp_type_name(self, icmp_type: int) -> str:
        """Get ICMP type name"""
        types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply",
        }
        return types.get(icmp_type, f"Unknown ({icmp_type})")
