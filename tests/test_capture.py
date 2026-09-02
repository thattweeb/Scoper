#!/usr/bin/env python3
"""
Direct test of packet capture functionality
"""

import sys
from pathlib import Path

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from scapy.all import sniff, get_if_list

def test_interfaces():
    """Test interface detection"""
    print("🌐 Testing Interface Detection...")
    interfaces = get_if_list()
    
    if interfaces:
        print(f"✅ Found {len(interfaces)} interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"   {i}. {iface}")
        return interfaces
    else:
        print("❌ No interfaces found")
        return []

def test_capture(interface):
    """Test packet capture on specific interface"""
    print(f"\n🔍 Testing Capture on: {interface}")
    
    try:
        # Try to capture 3 packets with timeout
        packets = sniff(
            iface=interface,
            count=3,
            timeout=10,
            store=True
        )
        
        if packets:
            print(f"✅ Successfully captured {len(packets)} packets!")
            for i, packet in enumerate(packets, 1):
                print(f"   Packet {i}: {len(packet)} bytes")
                if packet.haslayer('IP'):
                    ip = packet['IP']
                    print(f"      {ip.src} -> {ip.dst}")
            return True
        else:
            print("⚠️  No packets captured (timeout)")
            print("   This could mean:")
            print("   - No network activity on this interface")
            print("   - Interface not connected to network")
            print("   - Firewall blocking packet capture")
            return False
            
    except PermissionError as e:
        print(f"❌ Permission denied: {e}")
        print("   Run as Administrator/root")
        return False
    except Exception as e:
        print(f"❌ Capture error: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 CyberOctet Capture Test")
    print("=" * 40)
    
    # Test interfaces
    interfaces = test_interfaces()
    
    if not interfaces:
        print("\n❌ Cannot proceed without network interfaces")
        return
    
    # Test capture on first interface
    test_interface = interfaces[0]
    success = test_capture(test_interface)
    
    print("\n📋 Test Summary:")
    print("=" * 20)
    
    if success:
        print("✅ Packet capture is working!")
        print("   CyberOctet should capture packets when started.")
    else:
        print("❌ Packet capture failed!")
        print("   Check:")
        print("   - Run as Administrator/root")
        print("   - Select correct interface")
        print("   - Generate network traffic")
        print("   - Check firewall settings")

if __name__ == "__main__":
    main()
