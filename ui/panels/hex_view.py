"""
Hex and ASCII View Widget for CyberOctet
Displays packet data in hexadecimal and ASCII format with field highlighting
"""

from typing import Optional, List, Tuple
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QFrame,
    QScrollBar, QLabel
)
from PySide6.QtCore import Qt, Signal, QRect, QTimer
from PySide6.QtGui import (
    QFont, QColor, QBrush, QPainter, QTextFormat, QTextCursor,
    QTextCharFormat, QPalette, QTextDocument
)

from core.config import Config
from core.capture_engine import PacketInfo
from core.protocol_decoder.decoder import ProtocolField


class HexViewWidget(QWidget):
    """Widget for displaying hex and ASCII view of packet data"""
    
    field_selected = Signal(int, int)  # offset, length
    
    def __init__(self):
        super().__init__()
        
        self.current_packet: Optional[PacketInfo] = None
        self.highlighted_field: Optional[ProtocolField] = None
        self.bytes_per_line = Config.DISPLAY['hex_bytes_per_line']
        
        self.setup_ui()
        self.setup_style()
        self.setup_connections()
    
    def setup_ui(self):
        """Setup the UI layout"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Controls — offset display only (font controls removed)
        controls_frame = QFrame()
        controls_layout = QHBoxLayout(controls_frame)
        
        controls_layout.addStretch()
        
        self.offset_label = QLabel("Offset: --")
        controls_layout.addWidget(self.offset_label)
        
        layout.addWidget(controls_frame)
        
        # Main hex view area
        hex_frame = QFrame()
        hex_layout = QHBoxLayout(hex_frame)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.setSpacing(0)
        
        # Offset column
        self.offset_text = QTextEdit()
        self.offset_text.setReadOnly(True)
        self.offset_text.setMaximumWidth(80)
        self.offset_text.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        hex_layout.addWidget(self.offset_text)
        
        # Hex column
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        hex_layout.addWidget(self.hex_text)
        
        # ASCII column
        self.ascii_text = QTextEdit()
        self.ascii_text.setReadOnly(True)
        self.ascii_text.setMaximumWidth(200)
        self.ascii_text.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        hex_layout.addWidget(self.ascii_text)
        
        layout.addWidget(hex_frame)
        
        # Synchronize scrollbars
        self.scroll_timer = QTimer()
        self.scroll_timer.timeout.connect(self.synchronize_scrollbars)
        self.scroll_timer.setSingleShot(True)
    
    def setup_style(self):
        """Apply dark cyber theme styling"""
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {Config.COLORS['surface']};
                border: 1px solid {Config.COLORS['border']};
            }}
            
            QTextEdit {{
                background-color: {Config.COLORS['surface']};
                color: {Config.COLORS['text_primary']};
                border: 1px solid {Config.COLORS['border']};
                selection-background-color: {Config.COLORS['selection']};
                font-family: Consolas, 'Courier New', monospace;
                font-size: 10pt;
            }}
            
            QLabel {{
                color: {Config.COLORS['text_secondary']};
                font-family: Consolas, 'Courier New', monospace;
                font-size: 10pt;
            }}
        """)
    
    def setup_connections(self):
        """Setup signal connections"""
        # Connect scroll events
        self.hex_text.verticalScrollBar().valueChanged.connect(self.on_hex_scroll)
        self.ascii_text.verticalScrollBar().valueChanged.connect(self.on_ascii_scroll)
    
    def show_packet_data(self, packet_info: PacketInfo):
        """Display packet data in hex and ASCII format"""
        self.current_packet = packet_info
        
        # Clear previous content
        self.offset_text.clear()
        self.hex_text.clear()
        self.ascii_text.clear()
        
        # Process packet data
        data = packet_info.raw_data
        if not data:
            return
        
        # Generate hex view content
        offset_lines = []
        hex_lines = []
        ascii_lines = []
        
        for i in range(0, len(data), self.bytes_per_line):
            offset = i
            chunk = data[i:i + self.bytes_per_line]
            
            # Offset
            offset_lines.append(f"{offset:08x}")
            
            # Hex bytes
            hex_bytes = []
            for byte in chunk:
                hex_bytes.append(f"{byte:02x}")
            hex_lines.append(" ".join(hex_bytes))
            
            # ASCII representation
            ascii_chars = []
            for byte in chunk:
                if 32 <= byte <= 126:  # Printable ASCII
                    ascii_chars.append(chr(byte))
                else:
                    ascii_chars.append(".")
            ascii_lines.append("".join(ascii_chars))
        
        # Set text content
        self.offset_text.setPlainText("\n".join(offset_lines))
        self.hex_text.setPlainText("\n".join(hex_lines))
        self.ascii_text.setPlainText("\n".join(ascii_lines))
    
    def highlight_field(self, field: ProtocolField):
        """Highlight a specific field in the hex view"""
        self.highlighted_field = field
        
        if not field or not self.current_packet:
            return
        
        # Clear previous highlighting
        self.clear_highlighting()
        
        # Calculate line and position for the field
        start_line = field.offset // self.bytes_per_line
        start_pos = field.offset % self.bytes_per_line
        
        end_offset = field.offset + field.length - 1
        end_line = end_offset // self.bytes_per_line
        end_pos = end_offset % self.bytes_per_line
        
        # Highlight in hex view
        self.highlight_hex_region(start_line, start_pos, end_line, end_pos)
        
        # Highlight in ASCII view
        self.highlight_ascii_region(start_line, start_pos, end_line, end_pos)
        
        # Update offset label
        self.offset_label.setText(f"Offset: 0x{field.offset:04x} ({field.offset})")
    
    def highlight_hex_region(self, start_line: int, start_pos: int, end_line: int, end_pos: int):
        """Highlight a region in the hex view"""
        cursor = self.hex_text.textCursor()
        
        # Move to start position
        cursor.movePosition(QTextCursor.Start)
        for _ in range(start_line):
            cursor.movePosition(QTextCursor.Down)
        
        # Move to start position in line (each byte takes 3 chars: "XX ")
        for _ in range(start_pos):
            cursor.movePosition(QTextCursor.Right)
            cursor.movePosition(QTextCursor.Right)
            cursor.movePosition(QTextCursor.Right)
        
        # Select the region
        if start_line == end_line:
            # Single line selection
            for _ in range(end_pos - start_pos + 1):
                cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)
                cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)
                cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)
        else:
            # Multi-line selection
            # Select to end of first line
            cursor.movePosition(QTextCursor.EndOfLine, QTextCursor.KeepAnchor)
            
            # Select full lines in between
            for _ in range(end_line - start_line - 1):
                cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor)
                cursor.movePosition(QTextCursor.EndOfLine, QTextCursor.KeepAnchor)
            
            # Select to end position in last line
            if end_line > start_line:
                cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor)
                for _ in range(end_pos + 1):
                    cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)
                    cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)
                    cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)
        
        # Apply highlighting format
        format = QTextCharFormat()
        format.setBackground(QColor(Config.COLORS['highlight']))
        format.setForeground(QColor(Config.COLORS['text_primary']))
        cursor.setCharFormat(format)
    
    def highlight_ascii_region(self, start_line: int, start_pos: int, end_line: int, end_pos: int):
        """Highlight a region in the ASCII view"""
        cursor = self.ascii_text.textCursor()
        
        # Move to start position
        cursor.movePosition(QTextCursor.Start)
        for _ in range(start_line):
            cursor.movePosition(QTextCursor.Down)
        
        # Move to start position in line
        for _ in range(start_pos):
            cursor.movePosition(QTextCursor.Right)
        
        # Select the region
        if start_line == end_line:
            # Single line selection
            for _ in range(end_pos - start_pos + 1):
                cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)
        else:
            # Multi-line selection
            cursor.movePosition(QTextCursor.EndOfLine, QTextCursor.KeepAnchor)
            
            for _ in range(end_line - start_line - 1):
                cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor)
                cursor.movePosition(QTextCursor.EndOfLine, QTextCursor.KeepAnchor)
            
            if end_line > start_line:
                cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor)
                for _ in range(end_pos + 1):
                    cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor)
        
        # Apply highlighting format
        format = QTextCharFormat()
        format.setBackground(QColor(Config.COLORS['highlight']))
        format.setForeground(QColor(Config.COLORS['text_primary']))
        cursor.setCharFormat(format)
    
    def clear_highlighting(self):
        """Clear all highlighting"""
        # Reset text to clear formatting
        hex_content = self.hex_text.toPlainText()
        ascii_content = self.ascii_text.toPlainText()
        
        self.hex_text.setPlainText(hex_content)
        self.ascii_text.setPlainText(ascii_content)
    
    def on_hex_scroll(self, value):
        """Handle hex view scroll"""
        self.scroll_timer.start(10)  # Delay to avoid infinite loop
    
    def on_ascii_scroll(self, value):
        """Handle ASCII view scroll"""
        self.scroll_timer.start(10)  # Delay to avoid infinite loop
    
    def synchronize_scrollbars(self):
        """Synchronize scrollbars between hex and ASCII views"""
        # Sync ASCII view to hex view
        hex_scroll = self.hex_text.verticalScrollBar()
        ascii_scroll = self.ascii_text.verticalScrollBar()
        
        if hex_scroll.value() != ascii_scroll.value():
            ascii_scroll.setValue(hex_scroll.value())
    
    def clear(self):
        """Clear the hex view"""
        self.offset_text.clear()
        self.hex_text.clear()
        self.ascii_text.clear()
        self.current_packet = None
        self.highlighted_field = None
        self.offset_label.setText("Offset: --")
    
    def export_hex_dump(self) -> str:
        """Export hex dump as formatted text"""
        if not self.current_packet:
            return ""
        
        lines = []
        data = self.current_packet.raw_data
        
        lines.append(f"Hex Dump - {self.current_packet.src_ip} → {self.current_packet.dst_ip}")
        lines.append("=" * 60)
        lines.append("")
        
        for i in range(0, len(data), self.bytes_per_line):
            offset = i
            chunk = data[i:i + self.bytes_per_line]
            
            # Offset
            offset_str = f"{offset:08x}"
            
            # Hex bytes
            hex_bytes = []
            for byte in chunk:
                hex_bytes.append(f"{byte:02x}")
            hex_str = " ".join(hex_bytes)
            
            # ASCII representation
            ascii_chars = []
            for byte in chunk:
                if 32 <= byte <= 126:
                    ascii_chars.append(chr(byte))
                else:
                    ascii_chars.append(".")
            ascii_str = "".join(ascii_chars)
            
            lines.append(f"{offset_str}  {hex_str:<{self.bytes_per_line * 3 - 1}}  |{ascii_str}|")
        
        return "\n".join(lines)
