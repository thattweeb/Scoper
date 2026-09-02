"""
Packet Table Widget for CyberOctet
Displays captured packets in a table format
"""

from typing import Optional, List
from PySide6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QApplication, QMenu
)
from PySide6.QtCore import Qt, Signal, QPoint
from PySide6.QtGui import QFont, QColor, QBrush, QAction

from core.config import Config
from core.capture_engine import PacketInfo


class PacketTableWidget(QTableWidget):
    """Table widget for displaying captured packets"""
    
    packet_selected = Signal(PacketInfo)
    
    def __init__(self):
        super().__init__()
        
        self.packets: List[PacketInfo] = []
        self._total_packets_seen = 0
        self.setup_ui()
        self.setup_style()
    
    def setup_ui(self):
        """Setup table widget"""
        # Set column headers
        headers = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        # Setup table properties
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        
        # Setup headers
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # No.
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.Stretch)            # Source
        header.setSectionResizeMode(3, QHeaderView.Stretch)            # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Length
        # Info column stretches
        
        # Set row height
        self.verticalHeader().setDefaultSectionSize(20)
        self.verticalHeader().setVisible(False)
        
        # Connect signals
        self.itemSelectionChanged.connect(self.on_selection_changed)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
    
    def setup_style(self):
        """Apply dark cyber theme styling"""
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {Config.COLORS['surface']};
                alternate-background-color: {Config.COLORS['surface_light']};
                gridline-color: {Config.COLORS['grid']};
                color: {Config.COLORS['text_primary']};
                border: 1px solid {Config.COLORS['border']};
                font-family: {Config.DISPLAY['font_family']};
                font-size: {Config.DISPLAY['font_size']}pt;
            }}
            
            QTableWidget::item {{
                padding: 2px;
                border-bottom: 1px solid {Config.COLORS['grid']};
                background-color: {Config.COLORS['surface']};
            }}
            
            QTableWidget::item:alternate {{
                background-color: {Config.COLORS['surface_light']};
            }}
            
            QTableWidget::item:selected {{
                background-color: #1E6FBF !important;
                color: #ffffff !important;
                font-weight: bold;
            }}
            
            QTableWidget::item:selected:active {{
                background-color: #1E6FBF !important;
                color: #ffffff !important;
            }}
            
            QTableWidget::item:hover {{
                background-color: {Config.COLORS['highlight']};
            }}
            
            QHeaderView::section {{
                background-color: {Config.COLORS['surface_light']};
                color: {Config.COLORS['text_secondary']};
                padding: 4px;
                border: 1px solid {Config.COLORS['border']};
                font-weight: bold;
                font-size: {Config.DISPLAY['font_size']}pt;
            }}
            
            QScrollBar:vertical {{
                background-color: {Config.COLORS['surface']};
                width: 12px;
                border: 1px solid {Config.COLORS['border']};
            }}
            
            QScrollBar::handle:vertical {{
                background-color: {Config.COLORS['surface_light']};
                min-height: 20px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background-color: {Config.COLORS['primary']};
            }}
        """)
    
    def add_packet(self, packet_info: PacketInfo):
        """Add a packet to the table"""
        self.add_packets([packet_info])

    def add_packets(self, packet_batch: List[PacketInfo]):
        """Add a batch of packets efficiently."""
        if not packet_batch:
            return

        max_rows = Config.DISPLAY['max_packet_list_items']
        self.setUpdatesEnabled(False)
        try:
            for packet_info in packet_batch:
                self.packets.append(packet_info)
                self._total_packets_seen += 1

                row_position = self.rowCount()
                self.insertRow(row_position)
                self.create_packet_row(row_position, packet_info, self._total_packets_seen)

            # Trim overflow in one pass (avoid per-packet O(n) renumber work).
            overflow = self.rowCount() - max_rows
            if overflow > 0:
                del self.packets[:overflow]
                for _ in range(overflow):
                    self.removeRow(0)

            if Config.DISPLAY['auto_scroll']:
                self.scrollToBottom()
        finally:
            self.setUpdatesEnabled(True)

    def create_packet_row(self, row: int, packet_info: PacketInfo, packet_num: int = None):
        """Create table row for packet"""
        # Packet number (use provided number or calculate from row)
        num = packet_num if packet_num is not None else (row + 1)
        num_item = self.create_table_item(str(num))
        num_item.setBackground(QBrush(QColor(Config.COLORS['surface_light'])))
        self.setItem(row, 0, num_item)
        
        # Timestamp
        time_str = self.format_timestamp(packet_info.timestamp)
        self.setItem(row, 1, self.create_table_item(time_str))
        
        # Source
        source_str = self.format_source(packet_info)
        self.setItem(row, 2, self.create_table_item(source_str, packet_info.protocol))
        
        # Destination
        dest_str = self.format_destination(packet_info)
        self.setItem(row, 3, self.create_table_item(dest_str, packet_info.protocol))
        
        # Protocol
        protocol_item = self.create_table_item(packet_info.protocol.upper())
        protocol_item.setForeground(self.get_protocol_color(packet_info.protocol))
        self.setItem(row, 4, protocol_item)
        
        # Length
        self.setItem(row, 5, self.create_table_item(str(packet_info.length)))
        
        # Info
        info_str = self.format_packet_info(packet_info)
        self.setItem(row, 6, self.create_table_item(info_str))
    
    def create_table_item(self, text: str, protocol: str = "") -> QTableWidgetItem:
        """Create a styled table item"""
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)
        
        # Set font
        font = QFont(Config.DISPLAY['font_family'], Config.DISPLAY['font_size'])
        item.setFont(font)
        
        return item
    
    def format_timestamp(self, timestamp: float) -> str:
        """Format timestamp for display"""
        from datetime import datetime
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime("%H:%M:%S.%f")[:-3]  # Show milliseconds
    
    def format_source(self, packet_info: PacketInfo) -> str:
        """Format source address - IP only"""
        return packet_info.src_ip or "N/A"
    
    def format_destination(self, packet_info: PacketInfo) -> str:
        """Format destination address - IP only"""
        return packet_info.dst_ip or "N/A"
    
    def format_packet_info(self, packet_info: PacketInfo) -> str:
        """Format packet info column with ports and flags"""
        info_parts = []
        
        if packet_info.protocol == 'tcp':
            if packet_info.src_port or packet_info.dst_port:
                info_parts.append(f"TCP {packet_info.src_port or '0'} → {packet_info.dst_port or '0'}")
            if packet_info.flags:
                info_parts.append(f"[{packet_info.flags}]")
        
        elif packet_info.protocol == 'udp':
            if packet_info.src_port or packet_info.dst_port:
                info_parts.append(f"UDP {packet_info.src_port or '0'} → {packet_info.dst_port or '0'}")
        
        elif packet_info.protocol == 'dns':
            if packet_info.src_port or packet_info.dst_port:
                info_parts.append(f"DNS {packet_info.src_port or '0'} → {packet_info.dst_port or '0'}")
        
        elif packet_info.protocol == 'arp':
            info_parts.append("ARP Request/Reply")
        
        elif packet_info.protocol == 'icmp':
            info_parts.append("ICMP Echo")
        
        return " ".join(info_parts) if info_parts else packet_info.protocol.upper()
    
    def get_protocol_color(self, protocol: str) -> QBrush:
        """Get color for protocol highlighting"""
        colors = {
            'tcp': QColor(Config.COLORS['primary']),
            'udp': QColor(Config.COLORS['secondary']),
            'icmp': QColor(Config.COLORS['warning']),
            'arp': QColor(Config.COLORS['accent']),
            'dns': QColor(Config.COLORS['secondary']),
            'http': QColor(Config.COLORS['primary']),
            'https': QColor(Config.COLORS['primary']),
            'ftp': QColor(Config.COLORS['secondary']),
            'smtp': QColor(Config.COLORS['secondary']),
            'tls': QColor(Config.COLORS['warning']),
            'ssl': QColor(Config.COLORS['warning']),
        }
        
        color = colors.get(protocol.lower(), QColor(Config.COLORS['text_primary']))
        return QBrush(color)
    
    def on_selection_changed(self):
        """Handle row selection change with full row highlighting"""
        # Get the currently selected row
        selected_range = self.selectedRanges()
        
        # Highlight entire selected row
        for row in range(self.rowCount()):
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    is_selected = False
                    for range_obj in selected_range:
                        if range_obj.topRow() <= row <= range_obj.bottomRow():
                            is_selected = True
                            break
                    
                    if is_selected:
                        item.setBackground(QBrush(QColor("#1E6FBF")))
                        item.setForeground(QBrush(QColor("#ffffff")))
                    else:
                        # Apply alternating row colors and restore default foreground
                        if row % 2 == 0:
                            item.setBackground(QBrush(QColor(Config.COLORS['surface'])))
                        else:
                            item.setBackground(QBrush(QColor(Config.COLORS['surface_light'])))
                        item.setForeground(QBrush(QColor(Config.COLORS['text_primary'])))
        
        # Get selected packet and emit signal
        current_row = self.currentRow()
        if 0 <= current_row < len(self.packets):
            packet_info = self.packets[current_row]
            self.packet_selected.emit(packet_info)
    
    def show_context_menu(self, position: QPoint):
        """Show context menu for packet"""
        item = self.itemAt(position)
        if not item:
            return
        
        menu = QMenu(self)
        
        # Add context menu actions
        follow_action = QAction("Follow Stream", self)
        follow_action.triggered.connect(self.follow_stream)
        menu.addAction(follow_action)
        
        menu.addSeparator()
        
        copy_action = QAction("Copy Packet", self)
        copy_action.triggered.connect(self.copy_packet)
        menu.addAction(copy_action)
        
        export_action = QAction("Export Selected", self)
        export_action.triggered.connect(self.export_packet)
        menu.addAction(export_action)
        
        menu.exec_(self.mapToGlobal(position))
    
    def follow_stream(self):
        """Follow TCP/UDP stream"""
        # TODO: Implement stream following
        pass
    
    def copy_packet(self):
        """Copy packet data to clipboard"""
        # TODO: Implement packet copying
        pass
    
    def export_packet(self):
        """Export selected packet"""
        # TODO: Implement packet export
        pass
    
    def get_selected_packet(self) -> Optional[PacketInfo]:
        """Get currently selected packet"""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.packets):
            return self.packets[current_row]
        return None
    
    def clear(self):
        """Clear all packets from table"""
        self.setRowCount(0)
        self.packets.clear()
        self._total_packets_seen = 0
    
    def filter_packets(self, filter_func=None):
        """Show/hide rows based on a predicate function.
        
        Args:
            filter_func: callable(PacketInfo) -> bool, or None to show all.
        """
        self.setUpdatesEnabled(False)
        try:
            for row, pkt in enumerate(self.packets):
                if filter_func is None:
                    self.setRowHidden(row, False)
                else:
                    hidden = not filter_func(pkt)
                    self.setRowHidden(row, hidden)
        finally:
            self.setUpdatesEnabled(True)
