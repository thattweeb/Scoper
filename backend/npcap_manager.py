"""
Npcap Manager for CyberOctet
Handles Npcap detection, installation guidance, and non-admin capture support on Windows.
NOTE: This module is Windows-only at runtime, but is safely importable on all platforms.
"""

import os
import sys
import subprocess
from typing import Tuple, Optional, Dict, Any, List

# winreg is Windows-only — guard so the module is safely importable on Linux/macOS
if sys.platform.startswith("win"):
    import winreg
else:
    winreg = None  # type: ignore[assignment]

try:
    import win32service
    WIN32_SERVICE_AVAILABLE = True
except ImportError:
    WIN32_SERVICE_AVAILABLE = False
    if sys.platform.startswith("win"):
        print("Warning: pywin32 not available. Install with: pip install pywin32")


from .driver_manager import DriverManager, DriverStatus

# Backward-compatibility alias — existing UI code imports NpcapStatus from here
NpcapStatus = DriverStatus

# ──────────────────────────────────────────────────
# Friendly-name helpers
# ──────────────────────────────────────────────────

# Keywords that map adapter descriptions → friendly labels
_FRIENDLY_NAME_KEYWORDS: List[tuple] = [
    # Wi-Fi
    ("wi-fi",        "Wi-Fi"),
    ("wifi",         "WiFi"),
    ("wireless",     "Wireless 802.11"),
    ("802.11",       "Wireless 802.11"),
    ("wlan",         "WLAN"),
    # Ethernet
    ("local area",   "Local Area"),
    ("realtek",      "Realtek"),
    ("intel(r) ethernet", "Intel(R) Ethernet"),
    ("broadcom",     "Broadcom"),
    ("ethernet",     "Ethernet"),
    # Loopback
    ("npcap loopback", "Npcap Loopback"),
    ("loopback",     "Loopback"),
    # Bluetooth
    ("bluetooth",    "Bluetooth"),
    # Virtual
    ("vmware",       "VMware Adapter"),
    ("hyper-v",      "Hyper-V Adapter"),
    ("virtual",      "Virtual Adapter"),
    # VPN
    ("tap",          "TAP VPN"),
    ("vpn",          "VPN"),
]

class NpcapManager(DriverManager):
    """Manages Npcap detection and configuration"""

    # Npcap registry keys and paths
    NPCAP_REGISTRY_KEY = r"SOFTWARE\Npcap"
    NPCAP_SERVICE_NAME = "npcap"
    NPCAP_INSTALL_PATHS = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap",
    ]

    # Npcap download URL
    NPCAP_DOWNLOAD_URL = "https://npcap.com/"

    def __init__(self):
        self._status_cache = None
        self._cache_time = 0
        self._cache_duration = 5  # Cache for 5 seconds

    def get_status(self) -> Tuple[DriverStatus, Dict[str, Any]]:
        """Get current Npcap status with detailed information"""
        import time

        # Check cache
        if self._status_cache and time.time() - self._cache_time < self._cache_duration:
            return self._status_cache

        status_info = {
            "npcap_installed": False,
            "non_admin_support": False,
            "service_running": False,
            "version": None,
            "install_path": None,
            "error_message": None,
        }

        # Check if Npcap is installed
        install_path = self._get_install_path()
        if install_path:
            status_info["npcap_installed"] = True
            status_info["install_path"] = install_path
            status_info["version"] = self._get_version(install_path)

        # Check if service is running
        status_info["service_running"] = self._is_service_running()

        # Check non-admin support
        if status_info["npcap_installed"]:
            status_info["non_admin_support"] = self._check_non_admin_support()

        # Determine overall status
        if not status_info["npcap_installed"]:
            status = DriverStatus.NOT_INSTALLED
        elif not status_info["non_admin_support"]:
            status = DriverStatus.INSTALLED_NO_NON_ADMIN
        elif not status_info["service_running"]:
            status = DriverStatus.SERVICE_NOT_RUNNING
        elif status_info["non_admin_support"]:
            status = DriverStatus.INSTALLED_WITH_NON_ADMIN
        else:
            status = DriverStatus.UNKNOWN

        # Cache result
        self._status_cache = (status, status_info)
        self._cache_time = time.time()

        return status, status_info

    def _get_install_path(self) -> Optional[str]:
        """Get Npcap installation path"""
        # Check registry first
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, self.NPCAP_REGISTRY_KEY
            ) as key:
                try:
                    install_path, _ = winreg.QueryValueEx(key, "")
                    if os.path.exists(install_path):
                        return install_path
                except FileNotFoundError:
                    pass
        except (OSError, winreg.error):
            pass

        # Check common installation paths
        for path in self.NPCAP_INSTALL_PATHS:
            if os.path.exists(path):
                # Check for key files
                if os.path.exists(os.path.join(path, "Packet.dll")):
                    return path

        return None

    def _get_version(self, install_path: str) -> Optional[str]:
        """Get Npcap version from installation"""
        try:
            # Try to get version from registry
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, self.NPCAP_REGISTRY_KEY
            ) as key:
                try:
                    version, _ = winreg.QueryValueEx(key, "Version")
                    return version
                except FileNotFoundError:
                    pass
        except (OSError, winreg.error):
            pass

        # Try to get version from DLL
        try:
            dll_path = os.path.join(install_path, "Packet.dll")
            if os.path.exists(dll_path):
                # Get file version info
                import win32api

                info = win32api.GetFileVersionInfo(dll_path, "\\")
                ms = info["FileVersionMS"]
                ls = info["FileVersionLS"]
                version = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
                return version
        except:
            pass

        return None

    def _is_service_running(self) -> bool:
        """Check if Npcap service is running"""
        if not WIN32_SERVICE_AVAILABLE:
            # Fallback method using scapy
            try:
                from scapy.all import get_if_list

                get_if_list()  # This will fail if Npcap service isn't running
                return True
            except:
                return False

        try:
            # Open a handle to the service manager
            scm_handle = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_CONNECT
            )
            service_handle = win32service.OpenService(
                scm_handle, self.NPCAP_SERVICE_NAME, win32service.SERVICE_QUERY_STATUS
            )
            status = win32service.QueryServiceStatus(service_handle)
            win32service.CloseServiceHandle(service_handle)
            win32service.CloseServiceHandle(scm_handle)
            return status[1] == win32service.SERVICE_RUNNING
        except Exception:
            return False

    def _check_non_admin_support(self) -> bool:
        """Check if Npcap supports non-admin users"""
        try:
            # Check registry for non-admin support
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, self.NPCAP_REGISTRY_KEY
            ) as key:
                try:
                    non_admin_support, _ = winreg.QueryValueEx(key, "AllowNonAdmin")
                    return non_admin_support == 1
                except FileNotFoundError:
                    pass
        except (OSError, winreg.error):
            pass

        # Check if non-admin group has permissions
        try:
            import win32security

            # Get the Npcap directory security descriptor
            install_path = self._get_install_path()
            if install_path:
                win32security.GetNamedSecurityInfo(
                    install_path,
                    win32security.SE_FILE_OBJECT,
                    win32security.DACL_SECURITY_INFORMATION,
                )

                # Check if "Users" group has read/execute permissions
                # This is a simplified check - in production, you'd want more detailed analysis
                return True
        except:
            pass

        return False

    def is_capture_ready(self) -> bool:
        """Check if packet capture is ready"""
        status, info = self.get_status()
        return (
            status == DriverStatus.INSTALLED_WITH_NON_ADMIN and info["service_running"]
        )

    def get_install_instructions(self) -> Dict[str, str]:
        """Get Npcap installation instructions"""
        return {
            "title": "Npcap Required for Packet Capture",
            "message": """CyberOctet requires Npcap to capture network packets. Npcap is a packet capture library similar to WinPcap but with modern Windows support.

Why Npcap is needed:
• Provides low-level network interface access
• Enables packet capture without Administrator privileges
• Required for professional packet analysis
• Industry standard for network tools

Installation Steps:
1. Download Npcap from the official website
2. Run the installer as Administrator
3. IMPORTANT: Enable "Support non-administrator users to capture packets"
4. Complete installation
5. Restart CyberOctet

After installation, you'll be able to capture packets without running as Administrator.""",
            "download_url": self.NPCAP_DOWNLOAD_URL,
            "non_admin_instruction": 'During installation, make sure to check the box: "Support non-administrator users to capture packets"',
            "restart_required": True,
        }

    def get_reinstall_instructions(self) -> Dict[str, str]:
        """Get Npcap reinstallation instructions for non-admin support"""
        return {
            "title": "Npcap Reinstallation Required",
            "message": """CyberOctet detected Npcap is installed but without non-admin support.

To capture packets without Administrator privileges, Npcap must be reinstalled with the correct configuration.

Reinstallation Steps:
1. Download the latest Npcap installer
2. Run the installer as Administrator
3. Choose "Upgrade" when prompted
4. IMPORTANT: Check "Support non-administrator users to capture packets"
5. Complete installation
6. Restart CyberOctet

This will enable packet capture for all users without requiring Administrator privileges.""",
            "download_url": self.NPCAP_DOWNLOAD_URL,
            "non_admin_instruction": 'During reinstallation, make sure to check: "Support non-administrator users to capture packets"',
            "restart_required": True,
        }

    def get_service_error_instructions(self) -> Dict[str, str]:
        """Get instructions for Npcap service issues"""
        return {
            "title": "Npcap Service Issue",
            "message": """CyberOctet detected that the Npcap service is not running properly.

This can happen when:
• Npcap service failed to start
• Service was disabled
• Windows security policies blocked the service

Solutions:
1. Restart the Npcap service:
   - Open Command Prompt as Administrator
   - Run: net stop npcap
   - Run: net start npcap

2. Reinstall Npcap if service issues persist:
   - Download latest Npcap installer
   - Run as Administrator
   - Choose "Repair" or "Remove and reinstall"

3. Check Windows Event Viewer for detailed error information""",
            "download_url": self.NPCAP_DOWNLOAD_URL,
            "restart_required": True,
        }

    def open_download_page(self):
        """Open Npcap download page in default browser"""
        import webbrowser

        try:
            webbrowser.open(self.NPCAP_DOWNLOAD_URL)
            return True
        except:
            return False

    def restart_service(self) -> bool:
        """Restart Npcap service"""
        # Try using pywin32 if available (no elevation required if process already has it)
        if WIN32_SERVICE_AVAILABLE:
            try:
                import win32serviceutil

                try:
                    win32serviceutil.StopService(self.NPCAP_SERVICE_NAME)
                except Exception:
                    pass
                win32serviceutil.StartService(self.NPCAP_SERVICE_NAME)
                return True
            except Exception:
                # Fall through to non-pywin32 methods
                pass

        # Try using net commands (may require elevation)
        try:
            subprocess.run(
                ["net", "stop", self.NPCAP_SERVICE_NAME],
                capture_output=True,
                text=True,
                check=True,
            )
            subprocess.run(
                ["net", "start", self.NPCAP_SERVICE_NAME],
                capture_output=True,
                text=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            # Attempt an elevated restart using PowerShell Start-Process -Verb RunAs
            try:
                ps_cmd = (
                    'Start-Process powershell -ArgumentList "-NoProfile -Command \\"net stop {svc} ; net start {svc}\\"" -Verb RunAs'
                ).format(svc=self.NPCAP_SERVICE_NAME)
                subprocess.run(["powershell", "-Command", ps_cmd], check=True)
                return True
            except Exception as e:
                print(f"Failed to restart Npcap service with elevation: {e}")
                return False
        except Exception as e:
            print(f"Error restarting Npcap service: {e}")
            return False

    def test_capture(self) -> bool:
        """Test if packet capture works"""
        try:
            from scapy.all import get_if_list

            interfaces = get_if_list()
            return len(interfaces) > 0
        except:
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # Cross-platform interface enumeration with friendly names - Enhanced for Wireshark-like detection
    # ──────────────────────────────────────────────────────────────────────────

    def get_interfaces(self) -> List[Dict[str, str]]:
        """Return available network interfaces with friendly labels.

        Enhanced to match Wireshark's interface detection capabilities:
        1. Enumerate all adapters via psutil (cross-platform, no elevation needed)
        2. Get detailed info from scapy's get_working_ifaces() (has GUID, IP, MAC)
        3. Match psutil interfaces with scapy interfaces by IP/MAC address
        4. Build Npcap device paths from the matched GUIDs
        5. Map to human-readable labels (Wi-Fi / Ethernet / Loopback …)
        6. Include ALL interfaces including disconnected ones
        """
        import psutil
        import socket

        result_list: List[Dict[str, str]] = []
        af_link = getattr(psutil, "AF_LINK", None)
        
        # Try multiple sources for interface detection (like Wireshark)
        
        # Source 1: psutil - get all network interfaces
        try:
            psutil_ifaces = psutil.net_if_addrs()
            psutil_stats = psutil.net_if_stats()
            
            for iface_name, addrs in psutil_ifaces.items():
                # Get IP addresses
                ips = []
                mac = None
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ips.append(addr.address)
                    elif af_link is not None and addr.family == af_link:
                        mac = addr.address
                
                # Get interface status
                is_up = False
                speed = 0
                if iface_name in psutil_stats:
                    stats = psutil_stats[iface_name]
                    is_up = stats.isup
                    speed = stats.speed
                
                # Determine interface type from name
                iface_type = self._detect_interface_type(iface_name, ips, mac)
                
                # Build description like Wireshark
                desc_parts = []
                if ips:
                    desc_parts.append(ips[0])
                if speed > 0:
                    desc_parts.append(f"{speed} Mbps")
                if not is_up:
                    desc_parts.append("disconnected")
                
                description = f"{iface_type} adapter"
                if desc_parts:
                    description += " (" + ", ".join(desc_parts) + ")"
                
                result_list.append({
                    "name": iface_name,  # Use psutil name as the device name
                    "friendly": self._get_friendly_name(iface_name, iface_type),
                    "description": description,
                    "type": iface_type,
                    "ip": ips[0] if ips else "",
                    "mac": mac or "",
                    "status": "up" if is_up else "down",
                    "speed": speed,
                })
        except Exception as e:
            print(f"Warning: psutil interface detection failed: {e}")

        # Source 2: scapy - get Npcap device paths (for actual capture)
        scapy_ifaces = []
        try:
            from scapy.all import get_working_ifaces, get_if_list
            
            # Try get_working_ifaces first (more detailed)
            try:
                working_ifaces = get_working_ifaces()
                for iface in working_ifaces:
                    guid = getattr(iface, 'guid', None)
                    ip = getattr(iface, 'ip', '') or ''
                    mac = getattr(iface, 'mac', '') or ''
                    if guid:
                        guid_str = str(guid)
                        if guid_str.startswith("\\Device\\NPF_"):
                            npcap_path = guid_str
                        else:
                            npcap_path = f"\\Device\\NPF_{guid_str}"
                    else:
                        npcap_path = iface.name if hasattr(iface, 'name') else str(iface)
                    
                    scapy_ifaces.append({
                        'name': getattr(iface, 'name', '') or iface.network_name if hasattr(iface, 'network_name') else str(iface),
                        'guid': guid,
                        'ip': ip,
                        'mac': mac.replace(':', '').upper() if mac else None,
                        'npcap_path': npcap_path,
                    })
            except:
                # Fallback to get_if_list
                for iface in get_if_list():
                    scapy_ifaces.append({
                        'name': iface,
                        'guid': None,
                        'ip': '',
                        'mac': None,
                        'npcap_path': iface,
                    })
        except Exception as e:
            print(f"Warning: scapy interface detection failed: {e}")

        # Source 3 (Windows): enumerate all adapters including hidden/disabled
        # and build Npcap paths directly from adapter GUIDs when available.
        if sys.platform.startswith("win"):
            try:
                import csv
                import io

                ps_cmd = (
                    "Get-NetAdapter -IncludeHidden | "
                    "Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress,InterfaceGuid | "
                    "ConvertTo-Csv -NoTypeInformation"
                )
                ps = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                if ps.returncode == 0 and ps.stdout.strip():
                    reader = csv.DictReader(io.StringIO(ps.stdout))
                    for row in reader:
                        name = (row.get("Name") or "").strip()
                        desc = (row.get("InterfaceDescription") or "").strip()
                        status_text = (row.get("Status") or "").strip()
                        link_speed = (row.get("LinkSpeed") or "").strip()
                        mac = (row.get("MacAddress") or "").strip()
                        guid = (row.get("InterfaceGuid") or "").strip()

                        if not name and not guid:
                            continue

                        if guid:
                            guid_clean = guid.strip("{}")
                            npcap_path = f"\\Device\\NPF_{{{guid_clean}}}"
                        else:
                            npcap_path = name

                        combined_name = f"{name} {desc}".strip() or npcap_path
                        iface_type = self._detect_interface_type(combined_name, [], mac)
                        desc_parts = [part for part in [name, desc, link_speed] if part]
                        if status_text and status_text.lower() != "up":
                            desc_parts.append("disconnected")

                        result_list.append(
                            {
                                "name": npcap_path,
                                "friendly": self._get_friendly_name(combined_name, iface_type),
                                "description": " - ".join(desc_parts) if desc_parts else iface_type,
                                "type": iface_type,
                                "ip": "",
                                "mac": mac,
                                "status": "up" if status_text.lower() == "up" else "down",
                                "speed": 0,
                            }
                        )
            except Exception as e:
                print(f"Warning: Get-NetAdapter enumeration failed: {e}")

        # Merge scapy paths with psutil interfaces
        for item in result_list:
            # Try to find matching scapy interface
            for scapy_iface in scapy_ifaces:
                item_ip = (item.get("ip") or "").strip()
                scapy_ip = (scapy_iface.get("ip") or "").strip()
                item_name = (item.get("name") or "").strip().lower()
                scapy_name = (scapy_iface.get("name") or "").strip().lower()
                scapy_path = (scapy_iface.get("npcap_path") or "").strip().lower()
                item_mac = (item.get("mac") or "").replace(":", "").replace("-", "").upper()
                scapy_mac = (scapy_iface.get("mac") or "").replace(":", "").replace("-", "").upper()

                # Match strictly by IP, MAC, or exact name/path (avoid substring false matches).
                if (item_ip and scapy_ip and item_ip == scapy_ip) or \
                   (item_mac and scapy_mac and item_mac == scapy_mac) or \
                   (item_name and scapy_name and item_name == scapy_name) or \
                   (item_name and scapy_path and item_name == scapy_path):
                    # Update with Npcap path
                    if 'npcap_path' not in item and scapy_iface.get('npcap_path'):
                        item['name'] = scapy_iface['npcap_path']
                    break

        # Add any interfaces from scapy that weren't in psutil
        for scapy_iface in scapy_ifaces:
            found = False
            for item in result_list:
                if item.get('name') == scapy_iface.get('npcap_path'):
                    found = True
                    break
            if not found and scapy_iface.get('npcap_path'):
                iface_type = self._detect_interface_type(scapy_iface.get('name', ''), [], None)
                result_list.append({
                    "name": scapy_iface['npcap_path'],
                    "friendly": self._get_friendly_name(scapy_iface.get('name', ''), iface_type),
                    "description": f"{iface_type} adapter (Npcap)",
                    "type": iface_type,
                    "ip": scapy_iface.get('ip', ''),
                    "mac": scapy_iface.get('mac', ''),
                    "status": "unknown",
                    "speed": 0,
                })

        # Build a device-agnostic interface list:
        # - de-duplicate by raw device path/name
        # - keep active interfaces first
        # - keep friendly labels stable and human-readable
        deduped: Dict[str, Dict[str, str]] = {}
        for item in result_list:
            raw_name = str(item.get("name", "")).strip()
            if not raw_name:
                continue
            if raw_name not in deduped:
                deduped[raw_name] = item
                continue

            # If duplicate raw device exists, prefer the more informative one.
            existing = deduped[raw_name]
            existing_score = (
                (1 if existing.get("status") == "up" else 0)
                + (1 if existing.get("ip") else 0)
                + (1 if existing.get("mac") else 0)
            )
            new_score = (
                (1 if item.get("status") == "up" else 0)
                + (1 if item.get("ip") else 0)
                + (1 if item.get("mac") else 0)
            )
            if new_score > existing_score:
                deduped[raw_name] = item

        cleaned = list(deduped.values())
        if not cleaned:
            # Last-resort fallback: return whatever scapy can enumerate.
            for scapy_iface in scapy_ifaces:
                raw_name = str(scapy_iface.get("npcap_path") or scapy_iface.get("name") or "").strip()
                if not raw_name:
                    continue
                iface_type = self._detect_interface_type(str(scapy_iface.get("name", "")), [], None)
                cleaned.append(
                    {
                        "name": raw_name,
                        "friendly": self._get_friendly_name(str(scapy_iface.get("name", raw_name)), iface_type),
                        "description": f"{iface_type} adapter",
                        "type": iface_type,
                        "ip": str(scapy_iface.get("ip", "")),
                        "mac": str(scapy_iface.get("mac", "")),
                        "status": "unknown",
                        "speed": 0,
                    }
                )

        cleaned.sort(
            key=lambda x: (
                0 if x.get("status") == "up" else 1,
                0 if x.get("ip") else 1,
                str(x.get("friendly", "")).lower(),
            )
        )

        return cleaned

    def _detect_interface_type(self, name: str, ips: List[str], mac: str) -> str:
        """Detect interface type from name, IP, and MAC"""
        name_lower = (name + " " + " ".join(ips)).lower()
        
        # Check for various interface types
        if any(kw in name_lower for kw in ['wi-fi', 'wifi', 'wireless', '802.11', 'wlan', 'airport']):
            return "Wi-Fi"
        elif any(kw in name_lower for kw in ['ethernet', 'lan', 'local area', 'gigabit', 'fast ethernet']):
            return "Ethernet"
        elif any(kw in name_lower for kw in ['loopback', 'loop', 'lo', 'localhost']):
            return "Loopback"
        elif any(kw in name_lower for kw in ['bluetooth', 'bt', 'bnep', 'pan']):
            return "Bluetooth"
        elif any(kw in name_lower for kw in ['virtual', 'vmware', 'vbox', 'hyper-v', 'veth', 'docker']):
            return "Virtual"
        elif any(kw in name_lower for kw in ['vpn', 'vpn tunnel', 'tap', 'tun', 'cisco', 'openvpn', 'wireguard']):
            return "VPN"
        elif any(kw in name_lower for kw in ['usb', 'usbtap']):
            return "USB"
        elif any(kw in name_lower for kw in ['firewire', 'ieee1394']):
            return "FireWire"
        elif any(kw in name_lower for kw in ['6to4', 'teredo', 'ip6tunnel', 'tunnel']):
            return "Tunnel"
        elif any(kw in name_lower for kw in ['ppp', 'dialup', 'modem']):
            return "Dial-up"
        elif mac and mac.startswith('00:50:56'):  # VMware MAC prefix
            return "VMware"
        elif mac and mac.startswith('00:0C:29'):  # VMware MAC prefix
            return "VMware"
        elif mac and mac.startswith('00:1C:42'):  # Parallels MAC prefix
            return "Parallels"
        
        return "Unknown"
    def _get_friendly_name(self, raw_name: str, iface_type: str) -> str:
        """Get friendly display name for an interface."""
        if not raw_name:
            raw_name = iface_type or ""

        # Clean up raw source name before mapping
        name = raw_name.strip()
        import re
        name = re.sub(r"\{[a-fA-F0-9\-]{36}\}", "", name)
        name = name.replace("\\Device\\NPF_", "")
        name = " ".join(name.split())

        # 1) Prefer explicit keyword mapping (ordered and deterministic)
        lower = name.lower()
        for keyword, label in _FRIENDLY_NAME_KEYWORDS:
            if keyword in lower:
                return label

        # 2) Fallback to type-based UI labels
        type_fallbacks = {
            "Wi-Fi": "Wi-Fi",
            "Ethernet": "Ethernet",
            "Loopback": "Loopback",
            "Bluetooth": "Bluetooth",
            "Virtual": "Virtual Adapter",
            "VPN": "VPN",
            "VMware": "VMware Adapter",
        }
        if iface_type in type_fallbacks:
            return type_fallbacks[iface_type]

        # 3) Last resort: cleaned raw name (still human-readable)
        return name if name else "Unknown"

class NpcapDialogManager:
    """Manages Npcap-related dialogs"""

    def __init__(self, parent):
        self.parent = parent
        self.npcap_manager = NpcapManager()

    def show_install_dialog(self):
        """Show Npcap installation dialog"""
        from PySide6.QtWidgets import (
            QMessageBox,
            QPushButton,
            QHBoxLayout,
        )

        instructions = self.npcap_manager.get_install_instructions()

        # Create custom message box
        msg = QMessageBox(self.parent)
        msg.setWindowTitle(instructions["title"])
        msg.setText(instructions["message"])
        msg.setIcon(QMessageBox.Information)

        # Add custom buttons
        download_btn = QPushButton("Download Npcap")
        download_btn.clicked.connect(self.npcap_manager.open_download_page)

        msg.addButton(QMessageBox.Ok)

        # Add custom button to message box
        layout = msg.layout()
        button_layout = QHBoxLayout()
        button_layout.addWidget(download_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        msg.exec()

    def show_reinstall_dialog(self):
        """Show Npcap reinstallation dialog"""
        from PySide6.QtWidgets import QMessageBox, QPushButton

        instructions = self.npcap_manager.get_reinstall_instructions()

        msg = QMessageBox(self.parent)
        msg.setWindowTitle(instructions["title"])
        msg.setText(instructions["message"])
        msg.setIcon(QMessageBox.Warning)

        download_btn = QPushButton("Download Npcap")
        download_btn.clicked.connect(self.npcap_manager.open_download_page)

        msg.addButton(QMessageBox.Ok)

        # Add custom button
        layout = msg.layout()
        button_layout = QHBoxLayout()
        button_layout.addWidget(download_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        msg.exec()

    def show_service_error_dialog(self):
        """Show Npcap service error dialog"""
        from PySide6.QtWidgets import QMessageBox, QPushButton

        instructions = self.npcap_manager.get_service_error_instructions()

        msg = QMessageBox(self.parent)
        msg.setWindowTitle(instructions["title"])
        msg.setText(instructions["message"])
        msg.setIcon(QMessageBox.Critical)

        restart_btn = QPushButton("Restart Service")
        restart_btn.clicked.connect(self._restart_service)

        msg.addButton(QMessageBox.Ok)

        # Add custom button
        layout = msg.layout()
        button_layout = QHBoxLayout()
        button_layout.addWidget(restart_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        msg.exec()

    def _restart_service(self):
        """Restart Npcap service and show result"""
        from PySide6.QtWidgets import QMessageBox

        if self.npcap_manager.restart_service():
            QMessageBox.information(
                self.parent,
                "Service Restarted",
                "Npcap service has been restarted successfully.",
            )
        else:
            QMessageBox.critical(
                self.parent,
                "Service Failed",
                "Failed to restart Npcap service. Please run CyberOctet as Administrator or reinstall Npcap.",
            )

