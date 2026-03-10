#!/usr/bin/env python3
"""
CyberOctet Startup Script
Run this to start the packet analyzer application
"""

import sys
import os
from pathlib import Path

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def check_dependencies():
    """Check if required dependencies are installed"""
    required_modules = [
        'PySide6',
        'scapy', 
        'matplotlib',
        'numpy'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print("❌ Missing dependencies:")
        for module in missing_modules:
            print(f"   - {module}")
        print("\n📦 Install with: pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies found!")
    return True

def main():
    """Main startup function"""
    print("🚀 Starting CyberOctet Packet Analyzer...")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    print("\n🎯 Starting application...")
    
    try:
        # Import and start the main application
        import main
        main.main()
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        print("\n🐛 Please report this issue with the following details:")
        print(f"   Python version: {sys.version}")
        print(f"   Platform: {sys.platform}")
        print(f"   Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
