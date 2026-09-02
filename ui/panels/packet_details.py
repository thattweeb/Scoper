from typing import Optional, List
from PySide6.QtWidgets import (
    QTreeWidget, QTreeWidgetItem, QAbstractItemView, QScrollArea,
    QWidget, QVBoxLayout, QFrame, QLabel, QHeaderView
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor, QBrush

from core.config import Config
from core.capture_engine import PacketInfo
from core.protocol_decoder.decoder import ProtocolDecoder, ProtocolLayer, ProtocolField


class PacketDetailsWidget(QScrollArea):
    """Widget for displaying detailed packet information"""
    
    def __init__(self):
        super().__init__()
        
        self.protocol_decoder = ProtocolDecoder()
        self.current_packet: Optional[PacketInfo] = None
        self.current_layers: List[ProtocolLayer] = []
        
        self.setup_ui()
        self.setup_style()
    
    def setup_ui(self):
        """Setup the UI"""
        # Create scroll area content
        self.content_widget = QWidget()
        self.setWidget(self.content_widget)
        self.setWidgetResizable(True)
        
        # Main layout
        self.layout = QVBoxLayout(self.content_widget)
        self.layout.setContentsMargins(5, 5, 5, 5)
        self.layout.setSpacing(5)
        
        # Create tree widget for protocol layers
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Field", "Value", "Description"])
        self.tree_widget.setAlternatingRowColors(True)
        self.tree_widget.setRootIsDecorated(True)
        self.tree_widget.setItemsExpandable(True)
        self.tree_widget.setExpandsOnDoubleClick(True)
        self.tree_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree_widget.setUniformRowHeights(True)
        
        # Setup tree widget columns
        header = self.tree_widget.header()
        header.setStretchLastSection(True)
        # ResizeToContents can be expensive during live panel resizing.
        header.setSectionResizeMode(0, QHeaderView.Interactive)       # Field
        header.resizeSection(0, 210)
        header.setSectionResizeMode(1, QHeaderView.Stretch)           # Value
        header.setSectionResizeMode(2, QHeaderView.Stretch)           # Description
        
        self.layout.addWidget(self.tree_widget)
        
        # Connect signals
        self.tree_widget.itemSelectionChanged.connect(self.on_field_selected)
    
    def setup_style(self):
        """Apply dark cyber theme styling"""
        self.setStyleSheet(f"""
            QScrollArea {{
                background-color: {Config.COLORS['surface']};
                border: 1px solid {Config.COLORS['border']};
            }}
            
            QTreeWidget {{
                background-color: {Config.COLORS['surface']};
                alternate-background-color: {Config.COLORS['surface_light']};
                gridline-color: {Config.COLORS['grid']};
                color: {Config.COLORS['text_primary']};
                border: none;
                font-family: {Config.DISPLAY['font_family']};
                font-size: {Config.DISPLAY['font_size']}pt;
            }}
            
            QTreeWidget::item {{
                padding: 2px;
                border-bottom: 1px solid {Config.COLORS['grid']};
            }}
            
            QTreeWidget::item:selected {{
                background-color: {Config.COLORS['selection']};
                color: {Config.COLORS['text_primary']};
            }}
            
            QTreeWidget::item:hover {{
                background-color: {Config.COLORS['highlight']};
            }}
            
            QTreeWidget::branch {{
                background-color: transparent;
            }}
            
            QTreeWidget::branch:has-children:!has-siblings:closed,
            QTreeWidget::branch:closed:has-children:has-siblings {{
                border-image: none;
                image: url(:/icons/collapsed.png);
            }}
            
            QTreeWidget::branch:open:has-children:!has-siblings,
            QTreeWidget::branch:open:has-children:has-siblings {{
                border-image: none;
                image: url(:/icons/expanded.png);
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
    
    def show_packet_details(self, packet_info: PacketInfo):
        """Display detailed information for a packet"""
        self.current_packet = packet_info
        
        # Decode packet
        self.current_layers = self.protocol_decoder.decode_packet(
            packet_info.raw_data, packet_info
        )
        
        # Clear existing items
        self.tree_widget.clear()
        
        # Add protocol layers
        for layer in self.current_layers:
            self.add_protocol_layer(layer)
        
        # Expand first layer by default
        if self.tree_widget.topLevelItemCount() > 0:
            first_item = self.tree_widget.topLevelItem(0)
            first_item.setExpanded(True)
    
    def add_protocol_layer(self, layer: ProtocolLayer):
        """Add a protocol layer to the tree"""
        # Create layer item
        layer_item = QTreeWidgetItem(self.tree_widget)
        layer_item.setText(0, layer.name)
        layer_item.setText(1, f"({len(layer.fields)} fields)")
        layer_item.setText(2, layer.description)
        
        # Style layer item
        font = QFont(Config.DISPLAY['font_family'], Config.DISPLAY['font_size'], QFont.Bold)
        layer_item.setFont(0, font)
        layer_item.setForeground(0, self.get_layer_color(layer.name))
        
        # Add fields
        for field in layer.fields:
            field_item = QTreeWidgetItem(layer_item)
            field_item.setText(0, field.name)
            field_item.setText(1, str(field.value))
            field_item.setText(2, field.description)
            
            # Store field data for hex view synchronization
            field_item.setData(0, Qt.UserRole, field)
            
            # Style field based on type
            self.style_field_item(field_item, field)
    
    def style_field_item(self, item: QTreeWidgetItem, field: ProtocolField):
        """Style a field item based on its properties"""
        # Color coding for important fields
        important_fields = ['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 
                          'Protocol', 'Flags', 'Sequence Number', 'Acknowledgment Number']
        
        if field.name in important_fields:
            item.setForeground(0, QBrush(QColor(Config.COLORS['primary'])))
            font = item.font(0)
            font.setBold(True)
            item.setFont(0, font)
        
        # Special formatting for different field types
        if 'MAC' in field.name:
            item.setForeground(1, QBrush(QColor(Config.COLORS['secondary'])))
        elif 'IP' in field.name:
            item.setForeground(1, QBrush(QColor(Config.COLORS['primary'])))
        elif 'Port' in field.name:
            item.setForeground(1, QBrush(QColor(Config.COLORS['accent'])))
        elif 'Checksum' in field.name or 'CRC' in field.name:
            item.setForeground(1, QBrush(QColor(Config.COLORS['warning'])))
    
    def get_layer_color(self, layer_name: str) -> QColor:
        """Get color for protocol layer"""
        colors = {
            'Ethernet II': QColor(Config.COLORS['primary']),
            'ARP': QColor(Config.COLORS['accent']),
            'IPv4': QColor(Config.COLORS['secondary']),
            'IPv6': QColor(Config.COLORS['secondary']),
            'TCP': QColor(Config.COLORS['primary']),
            'UDP': QColor(Config.COLORS['secondary']),
            'ICMP': QColor(Config.COLORS['warning']),
            'DNS': QColor(Config.COLORS['secondary']),
            'DHCP': QColor(Config.COLORS['accent']),
            'HTTP': QColor(Config.COLORS['primary']),
            'TLS': QColor(Config.COLORS['warning']),
            'SSL': QColor(Config.COLORS['warning']),
        }
        
        return colors.get(layer_name, QColor(Config.COLORS['text_primary']))
    
    def on_field_selected(self):
        """Handle field selection for hex view synchronization"""
        current_item = self.tree_widget.currentItem()
        if not current_item:
            return
        
        # Get field data
        field_data = current_item.data(0, Qt.UserRole)
        if field_data and isinstance(field_data, ProtocolField):
            # Emit signal for hex view synchronization
            # This would be connected to the hex view widget
            pass
    
    def get_selected_field(self) -> Optional[ProtocolField]:
        """Get currently selected field"""
        current_item = self.tree_widget.currentItem()
        if current_item:
            return current_item.data(0, Qt.UserRole)
        return None
    
    def expand_all(self):
        """Expand all protocol layers"""
        self.tree_widget.expandAll()
    
    def collapse_all(self):
        """Collapse all protocol layers"""
        self.tree_widget.collapseAll()
    
    def clear(self):
        """Clear packet details"""
        self.tree_widget.clear()
        self.current_packet = None
        self.current_layers = []
    
    def export_details(self) -> str:
        """Export packet details as text"""
        if not self.current_layers:
            return ""
        
        output = []
        output.append(f"Packet Details - {self.current_packet.src_ip} → {self.current_packet.dst_ip}")
        output.append("=" * 60)
        output.append("")
        
        for layer in self.current_layers:
            output.append(f"{layer.name} - {layer.description}")
            output.append("-" * len(layer.name))
            
            for field in layer.fields:
                output.append(f"  {field.name}: {field.value}")
                if field.description:
                    output.append(f"    {field.description}")
            
            output.append("")
        
        return "\n".join(output)
