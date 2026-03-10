"""
Real-time Monitoring Dashboard for CyberOctet
Displays live traffic statistics and charts
"""

from typing import Dict, List, Optional
import time
from collections import deque

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QSizePolicy
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QPainter, QColor, QPen, QBrush, QPolygonF
from PySide6.QtCore import QPointF, QRectF

import matplotlib.pyplot as plt
import matplotlib
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np

from core.config import Config
from core.capture_engine import CaptureStats


class TrafficChart(FigureCanvas):
    """Custom traffic chart widget"""
    
    def __init__(self, title: str, max_points: int = 60):
        self.fig = Figure(figsize=(6, 2), dpi=100, facecolor=Config.COLORS['surface'])
        super().__init__(self.fig)
        
        self.title = title
        self.max_points = max_points
        self.data = deque(maxlen=max_points)
        self.timestamps = deque(maxlen=max_points)
        
        # Setup plot
        self.ax = self.fig.add_subplot(111)
        self.setup_plot()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_plot)
        self.update_timer.start(250)  # Smoother plot refresh
    
    def setup_plot(self):
        """Setup plot appearance"""
        self.ax.set_title(self.title, color=Config.COLORS['text_primary'], fontsize=9, fontweight='bold')
        self.ax.set_xlabel('Time (s)', color=Config.COLORS['text_secondary'], fontsize=7)
        self.ax.set_ylabel('Packets/sec', color=Config.COLORS['text_secondary'], fontsize=7)
        
        # Dark theme
        self.ax.set_facecolor(Config.COLORS['surface'])
        self.fig.patch.set_facecolor(Config.COLORS['surface'])
        self.ax.tick_params(colors=Config.COLORS['text_muted'], labelsize=7)
        self.ax.spines['bottom'].set_color(Config.COLORS['grid'])
        self.ax.spines['top'].set_color(Config.COLORS['grid'])
        self.ax.spines['left'].set_color(Config.COLORS['grid'])
        self.ax.spines['right'].set_color(Config.COLORS['grid'])
        self.ax.grid(True, alpha=0.2, color=Config.COLORS['grid'], linestyle='--')
        
        # Initialize line
        self.line, = self.ax.plot([], [], color=Config.COLORS['primary'], linewidth=2, marker='o', markersize=3)
        
        self.fig.tight_layout(pad=0.5)
    
    def add_data_point(self, value: float):
        """Add a new data point"""
        self.data.append(value)
        self.timestamps.append(time.time())
    
    def update_plot(self):
        """Update the plot with new data"""
        if len(self.data) > 0 and len(self.timestamps) > 0:
            # Convert timestamps to relative seconds
            base_time = self.timestamps[0]
            x_data = [(t - base_time) for t in self.timestamps]
            y_data = list(self.data)

            self.line.set_data(x_data, y_data)

            # Update axes limits
            if len(x_data) > 1:
                self.ax.set_xlim(x_data[0] - 1, x_data[-1] + 1)
                max_y = max(y_data) if y_data else 1
                self.ax.set_ylim(0, max_y * 1.2 if max_y > 0 else 1)
            else:
                self.ax.set_xlim(-1, 2)
                self.ax.set_ylim(0, max(y_data) * 1.2 if max(y_data) > 0 else 1)
        else:
            # Explicitly clear previous line so refresh/reset is visible.
            self.line.set_data([], [])
            self.ax.set_xlim(-1, 2)
            self.ax.set_ylim(0, 1)

        try:
            self.draw_idle()
        except Exception as e:
            print(f"Error drawing chart: {e}")


class ProtocolDistributionChart(FigureCanvas):
    """Protocol distribution pie chart"""
    
    def __init__(self):
        self.fig = Figure(figsize=(3, 2), dpi=100, facecolor=Config.COLORS['surface'])
        super().__init__(self.fig)
        
        self.protocol_counts = {}
        
        # Setup plot
        self.ax = self.fig.add_subplot(111)
        self.setup_plot()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    
    def setup_plot(self):
        """Setup pie chart appearance"""
        self.ax.set_title('Protocol Distribution', color=Config.COLORS['text_primary'], 
                         fontsize=9, fontweight='bold')
        
        # Dark theme
        self.ax.set_facecolor(Config.COLORS['surface'])
        self.fig.patch.set_facecolor(Config.COLORS['surface'])
        
        self.fig.tight_layout(pad=0.5)
    
    def update_protocol_data(self, protocol_counts: Dict[str, int]):
        """Update protocol distribution data"""
        self.protocol_counts = protocol_counts.copy()
        
        if self.protocol_counts:
            # Prepare data
            labels = list(self.protocol_counts.keys())
            sizes = list(self.protocol_counts.values())
            
            # Define colors for common protocols
            colors = []
            for protocol in labels:
                if protocol.lower() in ['tcp']:
                    colors.append(Config.COLORS['primary'])
                elif protocol.lower() in ['udp', 'dns', 'mdns']:
                    colors.append(Config.COLORS['secondary'])
                elif protocol.lower() in ['icmp']:
                    colors.append(Config.COLORS['warning'])
                elif protocol.lower() in ['arp']:
                    colors.append(Config.COLORS['accent'])
                else:
                    colors.append(Config.COLORS['surface_light'])
            
            # Clear and redraw
            self.ax.clear()
            self.ax.set_facecolor(Config.COLORS['surface'])
            self.ax.set_title('Protocol Distribution', color=Config.COLORS['text_primary'], 
                             fontsize=9, fontweight='bold')
            
            try:
                # Create pie chart with smaller text
                wedges, texts, autotexts = self.ax.pie(sizes, labels=labels, colors=colors, 
                                                       autopct='%1.0f%%', startangle=90)
                
                # Style text
                for text in texts:
                    text.set_color(Config.COLORS['text_secondary'])
                    text.set_fontsize(7)
                
                for autotext in autotexts:
                    autotext.set_color(Config.COLORS['text_primary'])
                    autotext.set_fontsize(6)
                    autotext.set_fontweight('bold')
                
                self.draw_idle()
            except Exception as e:
                print(f"Error drawing pie chart: {e}")


class StatsWidget(QFrame):
    """Widget for displaying statistics"""
    
    def __init__(self, title: str, value: str, color: str = None):
        super().__init__()
        self.title = title
        self.value = value
        self.color = color or Config.COLORS['primary']
        
        self.setup_ui()
        self.setup_style()
    
    def setup_ui(self):
        """Setup UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        layout.setSpacing(0)
        
        self.title_label = QLabel(self.title)
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setMaximumHeight(14)
        layout.addWidget(self.title_label)
        
        self.value_label = QLabel(self.value)
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setMaximumHeight(20)
        layout.addWidget(self.value_label)
    
    def setup_style(self):
        """Apply styling"""
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {Config.COLORS['surface_light']};
                border: 1px solid {Config.COLORS['border']};
                border-radius: 3px;
            }}
            
            QLabel {{
                color: {Config.COLORS['text_secondary']};
                font-family: {Config.DISPLAY['font_family']};
                font-size: 8pt;
            }}
        """)
        
        # Style value label
        self.value_label.setStyleSheet(f"""
            QLabel {{
                color: {self.color};
                font-size: 12pt;
                font-weight: bold;
            }}
        """)
    
    def update_value(self, new_value: str):
        """Update the displayed value"""
        self.value_label.setText(new_value)


class MonitoringDashboard(QWidget):
    """Main monitoring dashboard widget"""
    
    def __init__(self):
        super().__init__()
        
        self.current_stats: Optional[CaptureStats] = None
        self.traffic_history = deque(maxlen=60)  # Last 60 seconds
        
        self.setup_ui()
        self.setup_style()
    
    def setup_ui(self):
        """Setup the dashboard UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)
        
        # Top row - Statistics
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(3)
        
        self.pps_widget = StatsWidget("PPS", "0", Config.COLORS['primary'])
        stats_layout.addWidget(self.pps_widget)
        
        self.bytes_widget = StatsWidget("Bytes/s", "0", Config.COLORS['secondary'])
        stats_layout.addWidget(self.bytes_widget)
        
        self.packets_widget = StatsWidget("Total", "0", Config.COLORS['accent'])
        stats_layout.addWidget(self.packets_widget)
        
        self.duration_widget = StatsWidget("Duration", "00:00:00", Config.COLORS['warning'])
        stats_layout.addWidget(self.duration_widget)
        
        stats_layout.addStretch()
        layout.addLayout(stats_layout, 0)
        
        # Bottom row - Charts
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(3)
        
        # Traffic over time chart
        self.traffic_chart = TrafficChart("Traffic Over Time")
        charts_layout.addWidget(self.traffic_chart, 2)
        
        # Protocol distribution chart
        self.protocol_chart = ProtocolDistributionChart()
        charts_layout.addWidget(self.protocol_chart, 1)
        
        layout.addLayout(charts_layout, 1)
        self.setLayout(layout)
    
    def setup_style(self):
        """Apply dark cyber theme styling"""
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {Config.COLORS['surface']};
                color: {Config.COLORS['text_primary']};
            }}
        """)
    
    def update_stats(self, stats: CaptureStats):
        """Update dashboard with new statistics"""
        self.current_stats = stats
        
        # Update statistics widgets
        self.pps_widget.update_value(f"{stats.pps:.1f}")
        self.bytes_widget.update_value(self.format_bytes(stats.bps))
        self.packets_widget.update_value(str(stats.packets_captured))
        
        if stats.start_time:
            duration = int(time.time() - stats.start_time)
            hours = duration // 3600
            minutes = (duration % 3600) // 60
            seconds = duration % 60
            self.duration_widget.update_value(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        # Update traffic chart
        self.traffic_chart.add_data_point(stats.pps)
        
        # Update protocol distribution
        self.protocol_chart.update_protocol_data(stats.protocol_counts)
        
        # Store in history
        self.traffic_history.append(stats.pps)
    
    def format_bytes(self, bytes_per_sec: float) -> str:
        """Format bytes per second with appropriate units"""
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.1f} B/s"
        elif bytes_per_sec < 1024 * 1024:
            return f"{bytes_per_sec / 1024:.1f} KB/s"
        elif bytes_per_sec < 1024 * 1024 * 1024:
            return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"
        else:
            return f"{bytes_per_sec / (1024 * 1024 * 1024):.1f} GB/s"
    
    def clear_dashboard(self):
        """Clear all dashboard data"""
        self.pps_widget.update_value("0")
        self.bytes_widget.update_value("0")
        self.packets_widget.update_value("0")
        self.duration_widget.update_value("00:00:00")
        
        # Clear charts
        self.traffic_chart.data.clear()
        self.traffic_chart.timestamps.clear()
        self.traffic_chart.update_plot()
        
        self.protocol_chart.ax.clear()
        self.protocol_chart.setup_plot()
        self.protocol_chart.draw()
        
        self.traffic_history.clear()
        self.current_stats = None

