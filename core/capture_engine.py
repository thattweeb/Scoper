"""
Packet Capture Engine for CyberOctet
Handles live packet capture from network interfaces

Robustness features:
- Comprehensive error handling with try-catch blocks
- Memory management with packet limit warnings
- Timeout handling for network operations
- Graceful degradation
- Resource usage monitoring

Efficiency features:
- Packet batch processing
- Throttled UI updates
- Caching for interface lists
- Optimized data structures
"""

from __future__ import annotations

import logging
import threading
import time
from typing import List, Callable, Optional, Dict, Any
from dataclasses import dataclass
from collections import deque

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Scapy is used for packet capture (cross-platform: Npcap on Windows, libpcap on Linux)
_scapy_modules_loaded = False
_scapy_load_error: Optional[str] = None


def _ensure_scapy_loaded():
    """Lazy load scapy modules - only loads when needed"""
    global _scapy_modules_loaded, _scapy_load_error
    if _scapy_load_error:
        logger.warning(f"Skipping scapy load due to previous error: {_scapy_load_error}")
        return False
        
    if not _scapy_modules_loaded:
        try:
            global sniff, get_if_list, conf, Ether, IP, TCP, UDP, ICMP, IPv6, Packet
            from scapy.all import sniff, get_if_list, conf
            from scapy.layers.l2 import Ether
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            from scapy.packet import Packet
            _scapy_modules_loaded = True
            logger.info("[CaptureEngine] Scapy loaded on-demand")
            return True
        except ImportError as e:
            _scapy_load_error = str(e)
            logger.error(f"Failed to import scapy: {e}")
            return False
        except Exception as e:
            _scapy_load_error = str(e)
            logger.error(f"Unexpected error loading scapy: {e}")
            return False
    return True

from .config import Config
from backend.driver_manager import get_driver_manager, DriverStatus


@dataclass
class PacketInfo:
    """Data structure for packet information"""

    timestamp: float
    raw_data: bytes
    length: int
    interface: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: Optional[str] = None
    seq_num: Optional[int] = None
    ack_num: Optional[int] = None


class CaptureStats:
    """Capture statistics tracking"""

    def __init__(self):
        self.start_time = None
        self.packets_captured = 0
        self.bytes_captured = 0
        self.pps = 0  # packets per second
        self.bps = 0  # bytes per second
        self.last_update = time.time()
        self.protocol_counts = {}
        self.top_talkers = {}  # IP -> packet count

    def update(self, packet_info: PacketInfo):
        """Update statistics with new packet"""
        if self.start_time is None:
            self.start_time = packet_info.timestamp

        self.packets_captured += 1
        self.bytes_captured += packet_info.length

        # Update protocol counts
        protocol = packet_info.protocol
        self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + 1

        # Update top talkers
        self.top_talkers[packet_info.src_ip] = (
            self.top_talkers.get(packet_info.src_ip, 0) + 1
        )
        self.top_talkers[packet_info.dst_ip] = (
            self.top_talkers.get(packet_info.dst_ip, 0) + 1
        )

        # Calculate rates
        current_time = time.time()
        time_diff = current_time - self.last_update
        if time_diff >= 0.25:  # Update 4x per second for smoother live charts
            elapsed = current_time - self.start_time
            if elapsed > 0:
                self.pps = self.packets_captured / elapsed
                self.bps = self.bytes_captured / elapsed
            self.last_update = current_time


class CaptureEngine:
    """Main packet capture engine with robustness and efficiency features"""

    def __init__(self):
        super().__init__()

        self.is_capturing = False
        self.capture_thread = None
        self.interfaces = []
        self.current_interface = None
        self.interface_map = {}
        self.capturable_interfaces = set()
        self.capture_filter = ""
        self._filter_validation_cache: Dict[str, tuple] = {}
        self._filter_cache_limit = 256
        self.promiscuous = Config.CAPTURE["promiscuous_mode"]
        self.buffer_size = Config.CAPTURE["default_buffer_size"]
        self.snaplen = Config.CAPTURE["default_snaplen"]
        self._capture_limit = int(Config.CAPTURE["max_packets_per_capture"])
        self._max_packets_in_memory = int(Config.CAPTURE.get("max_packets_in_memory", 50000))
        self._max_raw_bytes_per_packet = int(Config.CAPTURE.get("max_raw_bytes_per_packet", 2048))

        # Initialize driver manager
        self.driver_manager = get_driver_manager()

        # Callbacks
        self.packet_callback: Optional[Callable[[PacketInfo], None]] = None
        self.stats_callback: Optional[Callable[[CaptureStats], None]] = None

        # Statistics
        self.stats = CaptureStats()
        self.captured_packets = deque(maxlen=self._max_packets_in_memory)
        
        self._batch_timer: Optional[threading.Timer] = None

        # Robustness: Memory management
        self._memory_warning_issued = False
        self._capture_error: Optional[str] = None
        
        # Efficiency: Interface cache
        self._interface_cache: Dict[str, Any] = {}
        self._interface_cache_time: float = 0
        self._interface_cache_duration: float = 30  # 30 seconds cache
        
        # Robustness: Resource monitoring
        self._last_memory_check = time.time()
        self._memory_check_interval = 5  # Check every 5 seconds
        
        # Error tracking
        self._error_count = 0
        self._max_errors = 100
        
        # Update interface list
        self._refresh_interfaces()

    def _refresh_interfaces(self):
        """Refresh list of available network interfaces using the OS driver manager.

        The driver manager's get_interfaces() returns dicts with:
            name        – raw device identifier used by scapy for capture
            friendly    – human-readable label shown in the UI (Wi-Fi, Ethernet…)
            description – extra detail (IP address, adapter model)
        """
        self.interfaces = []
        self.interface_map = {}   # friendly_label -> raw device name
        self._interface_details = {}  # friendly_label -> description
        self.capturable_interfaces = set()

        try:
            iface_list = self.driver_manager.get_interfaces()
            for entry in iface_list:
                raw      = entry.get("name", "")
                friendly = entry.get("friendly", raw)
                desc     = entry.get("description", "")

                # De-duplicate friendly names (append a counter if needed)
                label = friendly
                counter = 1
                while label in self.interface_map:
                    counter += 1
                    label = f"{friendly} {counter}"

                self.interface_map[label] = raw
                self._interface_details[label] = desc
                self.interfaces.append(label)
                status = str(entry.get("status", "unknown")).lower()
                if raw and status != "down":
                    self.capturable_interfaces.add(label)

            print(f"[CaptureEngine] Found {len(self.interfaces)} interface(s): {self.interfaces}")

        except Exception as e:
            print(f"[CaptureEngine] Error getting interfaces from driver manager: {e}")
            # Graceful fallback via psutil
            try:
                import psutil
                for name in psutil.net_if_addrs().keys():
                    self.interface_map[name] = name
                    self.interfaces.append(name)
                    self.capturable_interfaces.add(name)
                print(f"[CaptureEngine] psutil fallback interfaces: {self.interfaces}")
            except Exception as pe:
                print(f"[CaptureEngine] psutil fallback failed: {pe}")
                # Last-resort: scapy
                try:
                    from scapy.all import get_if_list
                    for iface in get_if_list():
                        self.interface_map[iface] = iface
                        self.interfaces.append(iface)
                        self.capturable_interfaces.add(iface)
                    print(f"[CaptureEngine] scapy last-resort interfaces: {self.interfaces}")
                except Exception as se:
                    print(f"[CaptureEngine] scapy fallback failed: {se}")

    def get_interfaces(self) -> List[str]:
        """Return the list of friendly interface labels for the UI."""
        self._refresh_interfaces()
        return self.interfaces

    def get_interface_description(self, friendly_label: str) -> str:
        """Return the detailed description for a friendly interface label."""
        return getattr(self, '_interface_details', {}).get(friendly_label, "")

    def set_interface(self, interface: str):
        """Set the capture interface"""
        # Accept either friendly name (as shown in UI) or actual device name
        # If passed a friendly name, map to actual device
        if interface in self.interface_map:
            self.current_interface = self.interface_map[interface]
            return True

        # If passed the actual device identifier, ensure it exists in mapping values
        if interface in self.interface_map.values():
            self.current_interface = interface
            return True

        # Also allow if the interface equals an entry in self.interfaces (rare)
        if interface in self.interfaces:
            # Attempt to map via interface_map
            if interface in self.interface_map:
                self.current_interface = self.interface_map[interface]
            else:
                self.current_interface = interface
            return True

        return False
    def set_filter(self, filter_string: str):
        """Set BPF filter for packet capture"""
        self.capture_filter = self._normalize_filter(filter_string)

    @staticmethod
    def _normalize_filter(filter_string: str) -> str:
        """Normalize BPF filter text for consistent validation/caching."""
        if not filter_string:
            return ""
        return " ".join(filter_string.strip().split())

    def validate_filter(self, filter_string: str) -> tuple:
        """Validate a BPF filter expression without starting capture.

        Uses Scapy / libpcap (cross-platform: Npcap on Windows, libpcap on Linux).

        Returns:
            (True, "")           - filter is valid
            (False, error_msg)   - filter is invalid
        """
        normalized = self._normalize_filter(filter_string)
        if not normalized:
            return (True, "")
        if normalized in self._filter_validation_cache:
            return self._filter_validation_cache[normalized]

        try:
            from scapy.arch import get_if_list as _gif
            from scapy.arch.common import compile_filter as _compile

            iface = self.current_interface or (_gif()[0] if _gif() else None)
            _compile(normalized, iface=iface)
            cached = (True, "")
            self._cache_filter_validation(normalized, cached)
            return cached
        except ImportError:
            # compile_filter not available on this scapy build - try subprocess fallback
            pass
        except Exception as exc:
            cached = (False, str(exc))
            self._cache_filter_validation(normalized, cached)
            return cached

        # Cross-platform subprocess fallback: tcpdump on Linux, permissive on Windows
        import subprocess, sys, shutil
        try:
            if sys.platform.startswith("win"):
                # On Windows, accept optimistically if no compiler is available.
                cached = (True, "")
                self._cache_filter_validation(normalized, cached)
                return cached

            tcpdump = shutil.which("tcpdump")
            if tcpdump:
                result = subprocess.run(
                    [tcpdump, "-d", normalized],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    err = result.stderr.strip().split("\n")[-1] if result.stderr else "Invalid filter"
                    cached = (False, err)
                    self._cache_filter_validation(normalized, cached)
                    return cached

                cached = (True, "")
                self._cache_filter_validation(normalized, cached)
                return cached

            # No tcpdump available - accept optimistically
            cached = (True, "")
            self._cache_filter_validation(normalized, cached)
            return cached
        except Exception as exc:
            cached = (False, str(exc))
            self._cache_filter_validation(normalized, cached)
            return cached

    def _cache_filter_validation(self, normalized_filter: str, result: tuple):
        """Cache validation results for repeated filter checks."""
        self._filter_validation_cache[normalized_filter] = result
        if len(self._filter_validation_cache) > self._filter_cache_limit:
            oldest = next(iter(self._filter_validation_cache))
            self._filter_validation_cache.pop(oldest, None)

    def set_promiscuous(self, promiscuous: bool):
        """Enable/disable promiscuous mode"""
        self.promiscuous = promiscuous

    def _packet_handler(self, packet: Packet):
        """Handle captured packet and convert to PacketInfo"""
        try:
            # Extract basic information
            timestamp = time.time()
            raw_data = bytes(packet)
            if self._max_raw_bytes_per_packet > 0 and len(raw_data) > self._max_raw_bytes_per_packet:
                raw_data = raw_data[: self._max_raw_bytes_per_packet]
            length = len(raw_data)

            # Default values
            protocol = "other"
            src_ip = ""
            dst_ip = ""
            src_port = None
            dst_port = None
            flags = None
            seq_num = None
            ack_num = None

            # Parse IP layer first (works with or without Ethernet)
            if IP in packet:
                ip = packet[IP]
                src_ip = str(ip.src)
                dst_ip = str(ip.dst)
                protocol = "ipv4"

                # Parse transport layer for IPv4
                if TCP in packet:
                    tcp = packet[TCP]
                    protocol = "tcp"
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    # Decode TCP flags properly
                    flag_names = []
                    flags_int = int(tcp.flags) if hasattr(tcp, 'flags') else 0
                    if flags_int & 0x01: flag_names.append("FIN")
                    if flags_int & 0x02: flag_names.append("SYN")
                    if flags_int & 0x04: flag_names.append("RST")
                    if flags_int & 0x08: flag_names.append("PSH")
                    if flags_int & 0x10: flag_names.append("ACK")
                    if flags_int & 0x20: flag_names.append("URG")
                    if flags_int & 0x40: flag_names.append("ECE")
                    if flags_int & 0x80: flag_names.append("CWR")
                    flags = ", ".join(flag_names) if flag_names else "NONE"
                    seq_num = tcp.seq
                    ack_num = tcp.ack

                elif UDP in packet:
                    udp = packet[UDP]
                    protocol = "udp"
                    src_port = udp.sport
                    dst_port = udp.dport
                    # Check for DNS (port 53)
                    if src_port == 53 or dst_port == 53:
                        protocol = "dns"
                    elif src_port == 5353 or dst_port == 5353:
                        protocol = "mdns"

                elif ICMP in packet:
                    protocol = "icmp"

            elif IPv6 in packet:
                ipv6 = packet[IPv6]
                src_ip = str(ipv6.src)
                dst_ip = str(ipv6.dst)
                protocol = "ipv6"

                # Parse transport layer for IPv6
                if TCP in packet:
                    tcp = packet[TCP]
                    protocol = "tcp"
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    # Decode TCP flags properly for IPv6
                    flag_names = []
                    flags_int = int(tcp.flags) if hasattr(tcp, 'flags') else 0
                    if flags_int & 0x01: flag_names.append("FIN")
                    if flags_int & 0x02: flag_names.append("SYN")
                    if flags_int & 0x04: flag_names.append("RST")
                    if flags_int & 0x08: flag_names.append("PSH")
                    if flags_int & 0x10: flag_names.append("ACK")
                    if flags_int & 0x20: flag_names.append("URG")
                    if flags_int & 0x40: flag_names.append("ECE")
                    if flags_int & 0x80: flag_names.append("CWR")
                    flags = ", ".join(flag_names) if flag_names else "NONE"
                    seq_num = tcp.seq
                    ack_num = tcp.ack

                elif UDP in packet:
                    udp = packet[UDP]
                    protocol = "udp"
                    src_port = udp.sport
                    dst_port = udp.dport

            else:
                # Check for ARP if no IP layer
                if packet.haslayer('ARP'):
                    protocol = "arp"
                    arp = packet['ARP']
                    src_ip = str(arp.psrc)
                    dst_ip = str(arp.pdst)

            # Create packet info
            packet_info = PacketInfo(
                timestamp=timestamp,
                raw_data=raw_data,
                length=length,
                interface=self.current_interface or "unknown",
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                flags=flags,
                seq_num=seq_num,
                ack_num=ack_num,
            )

            # Update statistics
            self.stats.update(packet_info)

            # Keep a bounded in-memory rolling window to avoid memory exhaustion.
            self.captured_packets.append(packet_info)

            # Call callbacks
            if self.packet_callback:
                self.packet_callback(packet_info)

            if self.stats_callback and time.time() - self.stats.last_update >= 1.0:
                self.stats_callback(self.stats)

            # Stop safely at configured capture ceiling.
            if self.stats.packets_captured >= self._capture_limit:
                self.is_capturing = False

        except Exception as e:
            print(f"Error processing packet: {e}")

    def _capture_loop(self):
        """Main capture loop running in separate thread"""
        try:
            print(f"Starting capture on interface: {self.current_interface}")
            print(f"Filter: {self.capture_filter or 'None'}")

            # Configure scapy for better compatibility
            conf.sniff_promisc = self.promiscuous
            conf.sniff_sizelimit = 0  # No size limit

            # Poll with short timeouts so every interface feels responsive
            # and stop requests are honored even on low-traffic adapters.
            try:
                while self.is_capturing:
                    sniff(
                        iface=self.current_interface,
                        prn=self._packet_handler,
                        filter=self.capture_filter if self.capture_filter else None,
                        store=False,   # Don't store packets in scapy
                        timeout=1,     # Re-check self.is_capturing every second
                    )
            except KeyboardInterrupt:
                pass
            except OSError as inner_e:
                # Often caught when capture stops, but could be an actual socket/permission error
                print(f"Capture sniff() raised OSError: {inner_e}")
                if "Operation not permitted" in str(inner_e) or "Permission denied" in str(inner_e):
                    print("Permission error: You must run as root/administrator to capture packets.")
                
        except PermissionError as e:
            error_msg = f"Permission denied: {e}\nPlease run as Administrator/root for packet capture"
            print(error_msg)
        except Exception as e:
            error_msg = f"Capture error: {e}"
            print(error_msg)
            print(f"Interface: {self.current_interface}")
            print(f"Filter: {self.capture_filter}")
        finally:
            self.is_capturing = False
            print("Capture loop ended")

    def get_npcap_status(self):
        """Get driver installation status"""
        return self.driver_manager.get_status()

    def is_capture_ready(self):
        """Check if packet capture is ready (properly installed with permissions)"""
        return self.driver_manager.is_capture_ready()

    def get_npcap_instructions(self):
        """Get driver installation instructions based on current status"""
        status, info = self.get_npcap_status()

        if status == DriverStatus.NOT_INSTALLED:
            return self.driver_manager.get_install_instructions()
        elif status == DriverStatus.INSTALLED_NO_NON_ADMIN:
            return getattr(self.driver_manager, 'get_reinstall_instructions', self.driver_manager.get_install_instructions)()
        elif status == DriverStatus.SERVICE_NOT_RUNNING:
            return getattr(self.driver_manager, 'get_service_error_instructions', lambda: None)()
        else:
            return None

    def test_capture_capability(self):
        """Test if packet capture actually works"""
        return self.driver_manager.test_capture()

    def start_capture(self) -> bool:
        """Start packet capture"""
        # Load scapy now - just in time for capture
        _ensure_scapy_loaded()
        
        if self.is_capturing:
            return False

        if not self.current_interface:
            print("No interface selected")
            return False

        # Check if Npcap is ready for capture
        if not self.is_capture_ready():
            print("Npcap not ready for capture")
            return False

        try:
            self.is_capturing = True
            self.stats = CaptureStats()  # Reset stats
            self.captured_packets = deque(maxlen=self._max_packets_in_memory)  # Reset rolling window

            # Start capture thread
            self.capture_thread = threading.Thread(
                target=self._capture_loop, daemon=True
            )
            self.capture_thread.start()

            return True

        except Exception as e:
            print(f"Failed to start capture: {e}")
            self.is_capturing = False
            return False

    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)

    def get_captured_packets(self) -> List[PacketInfo]:
        """Get list of captured packets"""
        return list(self.captured_packets)

    def get_stats(self) -> CaptureStats:
        """Get current capture statistics"""
        return self.stats

    def clear_packets(self):
        """Clear captured packets"""
        self.captured_packets.clear()
        self.stats = CaptureStats()

    def set_packet_callback(self, callback: Callable[[PacketInfo], None]):
        """Set callback for new packets"""
        self.packet_callback = callback

    def set_stats_callback(self, callback: Callable[[CaptureStats], None]):
        """Set callback for statistics updates"""
        self.stats_callback = callback

