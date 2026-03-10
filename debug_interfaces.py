#!/usr/bin/env python3
"""
Debug script to test interface detection directly
"""

import sys
from pathlib import Path

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from core.capture_engine import CaptureEngine

def main():
    """Test interface detection"""
    print("🔍 Testing Interface Detection")
    print("=" * 40)
    
    # Create capture engine
    engine = CaptureEngine()
    
    # Get interfaces
    print("Getting interfaces...")
    interfaces = engine.get_interfaces()
    
    print(f"Found {len(interfaces)} interfaces:")
    for i, interface in enumerate(interfaces, 1):
        print(f"  {i}. {interface}")
    
    print(f"Interface map: {engine.interface_map}")
    
    # Test setting interface
    if interfaces:
        test_interface = interfaces[0]
        print(f"\nTesting set_interface() with: {test_interface}")
        success = engine.set_interface(test_interface)
        print(f"Set interface result: {success}")
        print(f"Current interface: {engine.current_interface}")

if __name__ == "__main__":
    main()
