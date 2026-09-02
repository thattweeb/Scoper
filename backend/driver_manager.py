"""
Driver Manager Base Interface for CyberOctet
Provides OS-agnostic abstraction for packet capture drivers (Npcap on Windows,
libpcap on Linux/macOS). The factory function returns the correct implementation
at runtime based on sys.platform.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Dict, List, Any
from enum import Enum


class DriverStatus(Enum):
    """Driver installation status"""
    NOT_INSTALLED = "not_installed"
    INSTALLED_NO_NON_ADMIN = "installed_no_non_admin"
    INSTALLED_WITH_NON_ADMIN = "installed_with_non_admin"
    SERVICE_NOT_RUNNING = "service_not_running"
    UNKNOWN = "unknown"


class DriverManager(ABC):
    """Abstract base class for OS-specific packet capture driver management.

    Concrete implementations:
    - Windows  → NpcapManager  (backend/npcap_manager.py)
    - Linux    → LinuxManager  (backend/linux_manager.py)
    - macOS    → LinuxManager  (shares libpcap stack, minor wording differences)
    """

    @abstractmethod
    def get_status(self) -> Tuple[DriverStatus, Dict[str, Any]]:
        """Return current driver status plus a details dict."""

    @abstractmethod
    def is_capture_ready(self) -> bool:
        """Return True when packet capture is fully operational."""

    @abstractmethod
    def get_install_instructions(self) -> Dict[str, str]:
        """Return user-facing installation instructions."""

    @abstractmethod
    def test_capture(self) -> bool:
        """Perform a live sanity-check and return True if capture works."""

    @abstractmethod
    def get_interfaces(self) -> List[Dict[str, str]]:
        """Return a list of available network interfaces.

        Each dict contains:
            name        – raw device name used by scapy/pcap (e.g. '\\Device\\NPF_{...}')
            friendly    – human-readable label (e.g. 'Wi-Fi', 'Ethernet')
            description – optional extra detail (adapter model / IP)
        """


def get_driver_manager() -> "DriverManager":
    """Factory: return the appropriate DriverManager for the current platform."""
    import sys
    import logging

    log = logging.getLogger(__name__)

    if sys.platform.startswith("win"):
        from .npcap_manager import NpcapManager
        mgr = NpcapManager()
        log.debug("DriverManager: selected NpcapManager (Windows)")
    elif sys.platform.startswith("linux"):
        from .linux_manager import LinuxManager
        mgr = LinuxManager(platform="linux")
        log.debug("DriverManager: selected LinuxManager (Linux)")
    elif sys.platform == "darwin":
        from .linux_manager import LinuxManager
        mgr = LinuxManager(platform="darwin")
        log.debug("DriverManager: selected LinuxManager (macOS)")
    else:
        from .linux_manager import LinuxManager
        mgr = LinuxManager(platform="unix")
        log.debug("DriverManager: selected LinuxManager (unknown unix platform)")

    return mgr
