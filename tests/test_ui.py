#!/usr/bin/env python3
"""
Minimal UI test to isolate interface dropdown issue
"""

import sys
from pathlib import Path

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton
from PySide6.QtCore import Qt

def main():
    """Test UI components"""
    app = QApplication(sys.argv)
    
    # Create test window
    window = QWidget()
    window.setWindowTitle("Interface Test")
    window.resize(400, 200)
    
    # Layout
    layout = QVBoxLayout(window)
    
    # Test interface combo
    combo_layout = QHBoxLayout()
    combo_layout = QVBoxLayout()
    
    combo_layout.addWidget(QLabel("Interface:"))
    interface_combo = QComboBox()
    combo_layout.addWidget(interface_combo)
    combo_layout.addWidget(QPushButton("Refresh"))
    
    combo_widget = QWidget()
    combo_widget.setLayout(combo_layout)
    combo_layout.addWidget(combo_widget)
    
    layout.addLayout(combo_layout)
    
    # Add test interfaces
    test_interfaces = [
        "Ethernet (NPF_{123})",
        "Wi-Fi (NPF_{456})",
        "Loopback (NPF_Loopback)"
    ]
    
    interface_combo.addItems(test_interfaces)
    interface_combo.setCurrentIndex(0)
    
    print(f"Added {len(test_interfaces)} interfaces to combo box")
    print(f"Combo box count: {interface_combo.count()}")
    print(f"Current index: {interface_combo.currentIndex()}")
    print(f"Current text: {interface_combo.currentText()}")
    
    window.show()
    
    # Start event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
