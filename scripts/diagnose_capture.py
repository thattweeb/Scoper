#!/usr/bin/env python3
"""
Diagnose packet capture issues for CyberOctet
"""

import sys
import os
from pathlib import Path

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def check_permissions():
    """Check if running with sufficient privileges"""
    print("🔐 Checking Permissions...")
    
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("✅ Running as Administrator")
                return True
            else:
                print("❌ Not running as Administrator")
                print("   Right-click Command Prompt/PowerShell and 'Run as Administrator'")
                return False
        except:
            print("⚠️  Could not check Administrator status")
            return False
    else:  # Linux/Mac
        if os.geteuid() == 0:
            print("✅ Running as root")
            return True
        else:
            print("❌ Not running as root")
            print("   Run with: sudo python diagnose_capture.py")
            return False

def check_dependencies():
    """Check if required dependencies are available"""
    print("\n📦 Checking Dependencies...")
    
    dependencies = {
        'scapy': 'Packet capture and crafting',
        'PySide6': 'GUI framework',
        'matplotlib': 'Charts and graphs',
        'numpy': 'Numerical computations'
    }
    
    all_good = True
    for dep, description in dependencies.items():
        try:
            __import__(dep)
            print(f"✅ {dep} - {description}")
        except ImportError:
            print(f"❌ {dep} - {description} (MISSING)")
            all_good = False
    
    return all_good

def check_network_interfaces():
    """Check available network interfaces"""
    print("\n🌐 Checking Network Interfaces...")
    
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        
        if interfaces:
            print(f"✅ Found {len(interfaces)} network interfaces:")
            for i, iface in enumerate(interfaces, 1):
                print(f"   {i}. {iface}")
            return interfaces
        else:
            print("❌ No network interfaces found")
            return []
    except Exception as e:
        print(f"❌ Error getting interfaces: {e}")
        return []

def test_packet_capture():
    """Test basic packet capture functionality"""
    print("\n🔍 Testing Packet Capture...")
    
    try:
        from scapy.all import sniff, IP, ICMP
        
        print("   Attempting to capture 1 packet (timeout: 5 seconds)...")
        
        # Try to capture one packet
        packets = sniff(count=1, timeout=5, store=True)
        
        if packets:
            print("✅ Packet capture successful!")
            packet = packets[0]
            if IP in packet:
                print(f"   Captured: {packet[IP].src} -> {packet[IP].dst}")
            else:
                print("   Captured packet (non-IP)")
            return True
        else:
            print("⚠️  No packets captured (timeout)")
            print("   This could mean:")
            print("   - No network activity")
            print("   - Interface permissions issue")
            print("   - Firewall blocking")
            return False
    except PermissionError as e:
        print(f"❌ Permission denied: {e}")
        print("   Run as Administrator/root")
        return False
    except Exception as e:
        print(f"❌ Capture error: {e}")
        return False

def test_packet_generation():
    """Test packet generation"""
    print("\n📤 Testing Packet Generation...")
    
    try:
        from scapy.all import IP, ICMP, send
        
        print("   Sending ICMP echo request to 8.8.8.8...")
        packet = IP(dst="8.8.8.8")/ICMP()
        result = send(packet, verbose=False, timeout=2)
        
        if result:
            print("✅ Packet sent successfully")
            return True
        else:
            print("⚠️  Packet sent (no reply)")
            return True
    except Exception as e:
        print(f"❌ Error sending packet: {e}")
        return False

def main():
    """Run diagnostic tests"""
    print("🔧 CyberOctet Packet Capture Diagnostics")
    print("=" * 50)
    
    # Run all checks
    permissions_ok = check_permissions()
    deps_ok = check_dependencies()
    interfaces = check_network_interfaces()
    capture_ok = test_packet_capture()
    generation_ok = test_packet_generation()
    
    # Summary
    print("\n📋 Summary")
    print("=" * 20)
    
    if permissions_ok and deps_ok and interfaces and capture_ok:
        print("✅ All systems operational!")
        print("   CyberOctet should work correctly.")
    else:
        print("⚠️  Issues found:")
        
        if not permissions_ok:
            print("   - Insufficient privileges (run as admin/root)")
        
        if not deps_ok:
            print("   - Missing dependencies (pip install -r requirements.txt)")
        
        if not interfaces:
            print("   - No network interfaces available")
        
        if not capture_ok:
            print("   - Packet capture failed")
            print("   Try: Run as admin/root")
            print("   Try: Disable firewall temporarily")
            print("   Try: Select different network interface")
    
    print("\n💡 Recommendations:")
    print("1. Run CyberOctet as Administrator (Windows) or with sudo (Linux/Mac)")
    print("2. Install Npcap on Windows (https://npcap.com/)")
    print("3. Select the correct network interface in CyberOctet")
    print("4. Generate test traffic using: python test_traffic.py")
    print("5. Check firewall settings")

if __name__ == "__main__":
    main()
