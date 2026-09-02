"""
Linux / macOS Driver Manager for CyberOctet
Manages libpcap detection and configuration on Linux and macOS.
Uses psutil for cross-platform interface enumeration with friendly names.
"""

import os
import subprocess
from typing import Tuple, Dict, List, Any, Optional

from .driver_manager import DriverManager, DriverStatus

class LinuxManager(DriverManager):
    """Manages libpcap detection and configuration for Linux / macOS."""

    def __init__(self, platform: str = "linux"):
        """
        Args:
            platform: one of 'linux', 'darwin', 'unix'
        """
        self._platform = platform

    # ────────────────────────────────────────────────────────────────────────
    # DriverManager interface
    # ────────────────────────────────────────────────────────────────────────

    def get_status(self) -> Tuple[DriverStatus, Dict[str, Any]]:
        status_info: Dict[str, Any] = {
            "driver_installed": False,
            "non_admin_support": False,
            "service_running": True,   # libpcap has no background service
            "version": None,
            "install_path": None,
            "error_message": None,
        }

        # Check for libpcap / tcpdump
        try:
            result = subprocess.run(
                ["tcpdump", "--version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 or result.stderr:
                status_info["driver_installed"] = True
                status_info["install_path"] = "/usr/sbin/tcpdump"
                # Try to extract version from stderr (tcpdump writes version there)
                version_line = (result.stdout + result.stderr).splitlines()
                if version_line:
                    status_info["version"] = version_line[0]
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            # Fall back: try importing scapy which requires libpcap
            try:
                import scapy.all  # noqa: F401
                status_info["driver_installed"] = True
            except ImportError:
                pass

        # Try to detect libpcap version via ldconfig / pkg-config
        if status_info["driver_installed"] and not status_info["version"]:
            status_info["version"] = self._get_libpcap_version()

        # Non-root access check
        if status_info["driver_installed"]:
            status_info["non_admin_support"] = self._has_capture_permission()

        # Determine overall status
        if not status_info["driver_installed"]:
            status = DriverStatus.NOT_INSTALLED
        elif not status_info["non_admin_support"]:
            status = DriverStatus.INSTALLED_NO_NON_ADMIN
        else:
            status = DriverStatus.INSTALLED_WITH_NON_ADMIN

        return status, status_info

    def is_capture_ready(self) -> bool:
        status, _ = self.get_status()
        return status == DriverStatus.INSTALLED_WITH_NON_ADMIN

    def get_install_instructions(self) -> Dict[str, str]:
        if self._platform == "darwin":
            return {
                "title": "libpcap Required (macOS)",
                "message": (
                    "CyberOctet requires libpcap to capture network packets.\n\n"
                    "On macOS, libpcap is bundled with Xcode Command Line Tools:\n"
                    "  xcode-select --install\n\n"
                    "For non-root capture, grant your terminal Full Disk Access in\n"
                    "System Settings → Privacy & Security → Full Disk Access."
                ),
                "download_url": "https://www.tcpdump.org/",
                "restart_required": False,
            }
        return {
            "title": "libpcap Required (Linux - Run as Root)",
            "message": (
                "CyberOctet requires libpcap to capture network packets.\n\n"
                "Install on Debian/Ubuntu:\n"
                "  sudo apt-get install libpcap-dev tcpdump\n\n"
                "Install on Fedora/RHEL:\n"
                "  sudo dnf install libpcap-devel tcpdump\n\n"
                "CRITICAL: Scapy requires raw socket access to capture packets.\n"
                "You MUST run this application as root on Linux:\n"
                "  sudo python main.py"
            ),
            "download_url": "https://www.tcpdump.org/",
            "restart_required": False,
        }

    def test_capture(self) -> bool:
        try:
            from scapy.all import get_if_list
            return len(get_if_list()) > 0
        except Exception:
            return False

    # ────────────────────────────────────────────────────────────────────────
    # Interface enumeration with friendly names (cross-platform)
    # ────────────────────────────────────────────────────────────────────────
    def get_interfaces(self) -> List[Dict[str, str]]:
        """Return network interfaces with their exact names.

        Uses psutil for cross-platform enumeration, then enriches with
        platform-specific friendly names where available.
        """
        import psutil
        import socket

        result: List[Dict[str, str]] = []
        try:
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()

            for name, addrs in net_if_addrs.items():
                # Use exact interface name for maximum portability.
                desc_parts = [name]
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        desc_parts.append(addr.address)
                        break

                is_up = net_if_stats.get(name) and net_if_stats[name].isup
                if not is_up:
                    desc_parts.append("disconnected")

                result.append(
                    {
                        "name": name,
                        "friendly": name,
                        "description": " - ".join(desc_parts),
                    }
                )
        except Exception:
            # Fallback: scapy-only enumeration
            try:
                from scapy.all import get_if_list

                for name in get_if_list():
                    result.append(
                        {
                            "name": name,
                            "friendly": name,
                            "description": name,
                        }
                    )
            except Exception:
                return []

        # Sort: put active interfaces first
        result.sort(
            key=lambda x: (
                0 if "disconnected" not in x.get("description", "") else 1,
                x.get("friendly", ""),
            )
        )
        return result

    # ────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ────────────────────────────────────────────────────────────────────────

    def _get_libpcap_version(self) -> Optional[str]:
        """Try to discover installed libpcap version."""
        try:
            # pkg-config is the most reliable method
            result = subprocess.run(
                ["pkg-config", "--modversion", "libpcap"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            # Debian/Ubuntu dpkg
            result = subprocess.run(
                ["dpkg", "-s", "libpcap-dev"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    def _has_capture_permission(self) -> bool:
        """Return True if the current user can capture packets without root."""
        # Root always can
        try:
            if os.geteuid() == 0:
                return True
        except AttributeError:
            pass  # Windows – not applicable here

        # On Linux, Scapy uses AF_PACKET raw sockets which strictly require root.
        # Membership in the 'wireshark' group does not grant raw socket access to Python.
        # (It only grants access to run the 'dumpcap' binary).
        # We could theoretically check for CAP_NET_RAW on sys.executable, but for simplicity
        # and security, we just require root on Linux.

        # macOS – check if /dev/bpf* is readable (indicates BPF access)
        if self._platform == "darwin":
            import glob
            bpf_devices = glob.glob("/dev/bpf*")
            for bpf in bpf_devices:
                if os.access(bpf, os.R_OK):
                    return True

        return False

