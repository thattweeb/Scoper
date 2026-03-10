"""
PCAP File Manager for CyberOctet
Handles saving and loading of packet capture files
"""

import os
import struct
import time
from typing import List, Optional, BinaryIO, Tuple
from pathlib import Path

from scapy.all import wrpcap, rdpcap, PcapWriter, PcapReader
from scapy.packet import Packet

from core.config import Config
from core.capture_engine import PacketInfo


class PCAPManager:
    """Manages PCAP/PCAPNG file operations"""
    
    # PCAP file header format
    PCAP_HEADER_FORMAT = '<LHHLLLL'
    PCAP_HEADER_SIZE = 24
    
    # PCAP record header format
    PCAP_RECORD_FORMAT = '<LLLL'
    PCAP_RECORD_SIZE = 16
    
    # Magic numbers for different file formats
    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
    PCAPNG_MAGIC = 0x0a0d0d0a
    
    def __init__(self):
        self.captures_dir = Path(Config.PATHS['captures_dir'])
        self.captures_dir.mkdir(exist_ok=True)
    
    def save_capture(self, packets: List[PacketInfo], filename: str, 
                    format_type: str = 'pcap') -> bool:
        """Save captured packets to file"""
        try:
            filepath = self.captures_dir / filename
            
            if format_type.lower() == 'pcap':
                return self._save_pcap(packets, filepath)
            elif format_type.lower() == 'pcapng':
                return self._save_pcapng(packets, filepath)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
                
        except Exception as e:
            print(f"Error saving capture: {e}")
            return False
    
    def _save_pcap(self, packets: List[PacketInfo], filepath: Path) -> bool:
        """Save packets in PCAP format"""
        try:
            # Convert PacketInfo to Scapy packets
            scapy_packets = []
            for packet_info in packets:
                from scapy.all import Ether
                scapy_packet = Ether(packet_info.raw_data)
                scapy_packets.append(scapy_packet)
            
            # Write using Scapy
            wrpcap(str(filepath), scapy_packets)
            return True
            
        except Exception as e:
            print(f"Error saving PCAP: {e}")
            return False
    
    def _save_pcapng(self, packets: List[PacketInfo], filepath: Path) -> bool:
        """Save packets in PCAPNG format"""
        try:
            # Convert PacketInfo to Scapy packets
            scapy_packets = []
            for packet_info in packets:
                from scapy.all import Ether
                scapy_packet = Ether(packet_info.raw_data)
                scapy_packets.append(scapy_packet)
            
            # Write using Scapy with PCAPNG
            writer = PcapWriter(str(filepath), linktype=1, sync=True)
            for packet in scapy_packets:
                writer.write(packet)
            writer.close()
            
            return True
            
        except Exception as e:
            print(f"Error saving PCAPNG: {e}")
            return False
    
    def load_capture(self, filename: str) -> Optional[List[PacketInfo]]:
        """Load packets from capture file"""
        try:
            filepath = self.captures_dir / filename
            
            if not filepath.exists():
                print(f"File not found: {filepath}")
                return None
            
            # Determine file format
            format_type = self._detect_format(filepath)
            
            if format_type == 'pcap':
                return self._load_pcap(filepath)
            elif format_type == 'pcapng':
                return self._load_pcapng(filepath)
            else:
                print(f"Unsupported file format: {format_type}")
                return None
                
        except Exception as e:
            print(f"Error loading capture: {e}")
            return None
    
    def _detect_format(self, filepath: Path) -> str:
        """Detect file format by reading magic number"""
        try:
            with open(filepath, 'rb') as f:
                magic = struct.unpack('<L', f.read(4))[0]
                
                if magic == self.PCAP_MAGIC or magic == self.PCAP_MAGIC_SWAPPED:
                    return 'pcap'
                elif magic == self.PCAPNG_MAGIC:
                    return 'pcapng'
                else:
                    return 'unknown'
                    
        except Exception:
            return 'unknown'
    
    def _load_pcap(self, filepath: Path) -> Optional[List[PacketInfo]]:
        """Load packets from PCAP file"""
        try:
            # Read using Scapy
            scapy_packets = rdpcap(str(filepath))
            
            # Convert to PacketInfo
            packet_infos = []
            for i, scapy_packet in enumerate(scapy_packets):
                packet_info = self._scapy_to_packet_info(scapy_packet, f"pcap_file_{filepath.name}")
                packet_infos.append(packet_info)
            
            return packet_infos
            
        except Exception as e:
            print(f"Error loading PCAP: {e}")
            return None
    
    def _load_pcapng(self, filepath: Path) -> Optional[List[PacketInfo]]:
        """Load packets from PCAPNG file"""
        try:
            # Read using Scapy
            scapy_packets = rdpcap(str(filepath))
            
            # Convert to PacketInfo
            packet_infos = []
            for i, scapy_packet in enumerate(scapy_packets):
                packet_info = self._scapy_to_packet_info(scapy_packet, f"pcapng_file_{filepath.name}")
                packet_infos.append(packet_info)
            
            return packet_infos
            
        except Exception as e:
            print(f"Error loading PCAPNG: {e}")
            return None
    
    def _scapy_to_packet_info(self, scapy_packet: Packet, interface: str) -> PacketInfo:
        """Convert Scapy packet to PacketInfo"""
        timestamp = time.time()
        raw_data = bytes(scapy_packet)
        length = len(raw_data)
        
        # Default values
        protocol = "unknown"
        src_ip = ""
        dst_ip = ""
        src_port = None
        dst_port = None
        flags = None
        seq_num = None
        ack_num = None
        
        # Parse packet layers
        if scapy_packet.haslayer('Ether'):
            eth = scapy_packet['Ether']
            
            if scapy_packet.haslayer('IP'):
                ip = scapy_packet['IP']
                src_ip = ip.src
                dst_ip = ip.dst
                protocol = "ipv4"
                
                if scapy_packet.haslayer('TCP'):
                    tcp = scapy_packet['TCP']
                    protocol = "tcp"
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    flags = str(tcp.flags)
                    seq_num = tcp.seq
                    ack_num = tcp.ack
                    
                elif scapy_packet.haslayer('UDP'):
                    udp = scapy_packet['UDP']
                    protocol = "udp"
                    src_port = udp.sport
                    dst_port = udp.dport
                    
                elif scapy_packet.haslayer('ICMP'):
                    protocol = "icmp"
                    
            elif scapy_packet.haslayer('IPv6'):
                ipv6 = scapy_packet['IPv6']
                src_ip = ipv6.src
                dst_ip = ipv6.dst
                protocol = "ipv6"
                
                if scapy_packet.haslayer('TCP'):
                    tcp = scapy_packet['TCP']
                    protocol = "tcp"
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    flags = str(tcp.flags)
                    seq_num = tcp.seq
                    ack_num = tcp.ack
                    
                elif scapy_packet.haslayer('UDP'):
                    udp = scapy_packet['UDP']
                    protocol = "udp"
                    src_port = udp.sport
                    dst_port = udp.dport
                    
            elif scapy_packet.haslayer('ARP'):
                protocol = "arp"
                arp = scapy_packet['ARP']
                src_ip = arp.psrc
                dst_ip = arp.pdst
        
        return PacketInfo(
            timestamp=timestamp,
            raw_data=raw_data,
            length=length,
            interface=interface,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flags=flags,
            seq_num=seq_num,
            ack_num=ack_num
        )
    
    def get_capture_list(self) -> List[dict]:
        """Get list of available capture files"""
        captures = []
        
        try:
            for filepath in self.captures_dir.glob("*.pcap"):
                stat = filepath.stat()
                captures.append({
                    'name': filepath.name,
                    'path': str(filepath),
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'format': 'pcap'
                })
            
            for filepath in self.captures_dir.glob("*.pcapng"):
                stat = filepath.stat()
                captures.append({
                    'name': filepath.name,
                    'path': str(filepath),
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'format': 'pcapng'
                })
            
            # Sort by modification time (newest first)
            captures.sort(key=lambda x: x['modified'], reverse=True)
            
        except Exception as e:
            print(f"Error getting capture list: {e}")
        
        return captures
    
    def delete_capture(self, filename: str) -> bool:
        """Delete a capture file"""
        try:
            filepath = self.captures_dir / filename
            if filepath.exists():
                filepath.unlink()
                return True
            return False
            
        except Exception as e:
            print(f"Error deleting capture: {e}")
            return False
    
    def export_filtered_packets(self, packets: List[PacketInfo], 
                              filename: str, filter_func=None) -> bool:
        """Export filtered packets to file"""
        try:
            if filter_func:
                filtered_packets = [p for p in packets if filter_func(p)]
            else:
                filtered_packets = packets
            
            return self.save_capture(filtered_packets, filename)
            
        except Exception as e:
            print(f"Error exporting filtered packets: {e}")
            return False
    
    def get_capture_info(self, filename: str) -> Optional[dict]:
        """Get information about a capture file"""
        try:
            filepath = self.captures_dir / filename
            
            if not filepath.exists():
                return None
            
            format_type = self._detect_format(filepath)
            stat = filepath.stat()
            
            # Load first packet to get more info
            packets = self.load_capture(filename)
            if packets:
                first_packet = packets[0]
                last_packet = packets[-1]
                
                return {
                    'name': filename,
                    'path': str(filepath),
                    'format': format_type,
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'packet_count': len(packets),
                    'first_timestamp': first_packet.timestamp,
                    'last_timestamp': last_packet.timestamp,
                    'duration': last_packet.timestamp - first_packet.timestamp,
                    'protocols': list(set(p.protocol for p in packets))
                }
            else:
                return {
                    'name': filename,
                    'path': str(filepath),
                    'format': format_type,
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'packet_count': 0,
                    'error': 'Could not read packets'
                }
                
        except Exception as e:
            print(f"Error getting capture info: {e}")
            return None
