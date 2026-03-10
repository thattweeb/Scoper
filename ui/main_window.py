"""
Main Application Window for CyberOctet Packet Analyzer
Professional dark-themed cybersecurity interface

Enhancements:
- Robust error handling and graceful degradation
- Efficient packet batch processing
- Wi-Fi interface detection and grouping
- Keyboard shortcuts for common operations
- Context menus
- Modern responsive UI
"""

import logging
import sys
import os
from typing import Optional, List, Dict
from collections import deque
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QToolBar,
    QStatusBar,
    QTextEdit,
    QLabel,
    QFrame,
    QTabWidget,
    QComboBox,
    QLineEdit,
    QPushButton,
    QDialog,
    QDialogButtonBox,
    QMessageBox,
    QListWidget,
    QListWidgetItem,
    QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction, QKeySequence

from core.config import Config
from core.capture_engine import CaptureEngine, PacketInfo
from backend.driver_manager import get_driver_manager, DriverStatus
from ui.panels.packet_table import PacketTableWidget
from ui.panels.packet_details import PacketDetailsWidget
from ui.panels.hex_view import HexViewWidget
from ui.panels.monitoring_dashboard import MonitoringDashboard
from ui.panels.ai_copilot import AICopilotWidget
from ui.style.cyber_theme import CyberTheme

class MainWindow(QMainWindow):
    """Main application window with enhanced features"""

    # Signals for robust communication
    error_occurred = Signal(str, str)  # error_type, error_message
    status_update = Signal(str)  # status message
    
    def __init__(self):
        super().__init__()

        # Initialize capture engine
        self.capture_engine = CaptureEngine()
        self.current_packet: Optional[PacketInfo] = None

        # Initialize driver manager (platform-aware: Npcap on Windows, libpcap on Linux/macOS)
        self.driver_manager = get_driver_manager()
        self.npcap_dialog_manager = None

        # Error tracking for robustness
        self._error_log: List[Dict] = []
        self._max_errors_displayed = 10
        
        # UI update throttling
        self._last_ui_update = 0
        self._ui_update_interval = 100  # ms
        
        # Setup UI components
        self.theme = CyberTheme()
        self.theme.apply_theme(self)

        self.setup_ui()
        self.setup_menu_bar()
        self.setup_toolbar()
        self.setup_status_bar()
        self.setup_connections()
        self.setup_keyboard_shortcuts()

        # Select appropriate interface on startup
        self.refresh_interfaces()

        # Setup update timers
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(250)  # Smoother stats/graph updates
        self._last_filter_text = ""
        self._last_filter_validation = (True, "")
        self._filter_auto_apply_enabled = True
        self._filter_apply_timer = QTimer(self)
        self._filter_apply_timer.setSingleShot(True)
        self._filter_apply_timer.timeout.connect(self.apply_filter)

        # Batch UI packet rendering for high-throughput stability.
        self._pending_ui_packets = deque()
        self._max_ui_batch_size = 200
        self._ui_flush_timer = QTimer(self)
        self._ui_flush_timer.timeout.connect(self._flush_pending_packets)
        self._ui_flush_timer.start(100)

        # Check Npcap status on startup
        self.check_npcap_status()
        
        # Connect error handling
        self.error_occurred.connect(self._handle_error)
        
        logger = logging.getLogger(__name__)
        logger.info("MainWindow initialized successfully")

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for common operations"""
        # Start/Stop capture
        self.start_capture_action = QAction("Start Capture", self)
        self.start_capture_action.setShortcut(QKeySequence("F5"))
        self.start_capture_action.triggered.connect(self.start_capture)
        self.addAction(self.start_capture_action)
        
        self.stop_capture_action = QAction("Stop Capture", self)
        self.stop_capture_action.setShortcut(QKeySequence("F6"))
        self.stop_capture_action.triggered.connect(self.stop_capture)
        self.addAction(self.stop_capture_action)
        
        # Clear packets
        self.clear_action = QAction("Clear Packets", self)
        self.clear_action.setShortcut(QKeySequence("Ctrl+L"))
        self.clear_action.triggered.connect(self.clear_packets)
        self.addAction(self.clear_action)
        
        # Open capture
        self.open_action = QAction("Open Capture", self)
        self.open_action.setShortcut(QKeySequence("Ctrl+O"))
        self.open_action.triggered.connect(self.open_capture)
        self.addAction(self.open_action)
        
        # Save capture
        self.save_action = QAction("Save Capture", self)
        self.save_action.setShortcut(QKeySequence("Ctrl+S"))
        self.save_action.triggered.connect(self.save_capture)
        self.addAction(self.save_action)
        
        # AI Copilot
        self.ai_action = QAction("AI Assistant", self)
        self.ai_action.setShortcut(QKeySequence("F7"))
        self.ai_action.triggered.connect(self.focus_ai_tab)
        self.addAction(self.ai_action)
        
        # Refresh interfaces
        self.refresh_action = QAction("Refresh Interfaces", self)
        self.refresh_action.setShortcut(QKeySequence("F2"))
        self.refresh_action.triggered.connect(self.refresh_interfaces)
        self.addAction(self.refresh_action)

        # Refresh application (soft reload)
        self.refresh_app_action = QAction("Refresh Application", self)
        self.refresh_app_action.setShortcut(QKeySequence("Ctrl+R"))
        self.refresh_app_action.triggered.connect(self.refresh_application)
        self.addAction(self.refresh_app_action)
        
        # Filter focus
        self.filter_focus_action = QAction("Focus Filter", self)
        self.filter_focus_action.setShortcut(QKeySequence("Ctrl+F"))
        self.filter_focus_action.triggered.connect(lambda: self.filter_edit.setFocus())
        self.addAction(self.filter_focus_action)

    def setup_ui(self):
        """Setup main UI layout with responsive design"""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)

        # Create main splitter (horizontal) with responsive proportions
        main_splitter = QSplitter(Qt.Horizontal)
        self.main_splitter = main_splitter
        main_splitter.setStretchFactor(0, 3)  # Left panel gets more space
        main_splitter.setStretchFactor(1, 2)  # Right panel gets less
        main_splitter.setHandleWidth(4)
        # Smoother drag: show handle glide first, then apply resize.
        main_splitter.setOpaqueResize(False)
        main_splitter.setChildrenCollapsible(False)
        main_layout.addWidget(main_splitter)

        # Left panel - Packet table and controls
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)

        # Capture controls
        controls_frame = self.create_capture_controls()
        left_layout.addWidget(controls_frame)

        # Packet table - use remaining space
        self.packet_table = PacketTableWidget()
        left_layout.addWidget(self.packet_table, 1)  # Stretch factor 1

        left_panel.setLayout(left_layout)
        main_splitter.addWidget(left_panel)

        # Right panel - Packet details and tabs
        right_panel = self.create_right_panel()
        main_splitter.addWidget(right_panel)

        # Set splitter proportions - responsive
        main_splitter.setSizes([600, 400])
        main_splitter.setMinimumHeight(300)

        # Bottom panel - Monitoring dashboard
        bottom_panel = self.create_bottom_panel()
        main_layout.addWidget(bottom_panel, 0)  # No stretch

        # Set minimum window size
        self.setMinimumSize(900, 600)

    def create_capture_controls(self) -> QFrame:
        """Create capture control panel"""
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel)
        frame.setMaximumHeight(145)

        layout = QVBoxLayout(frame)

        # Interface selection
        interface_layout = QHBoxLayout()
        interface_layout.addWidget(QLabel("Interface:"))

        self.interface_combo = QComboBox()
        # Keep long adapter names readable in the control itself.
        self.interface_combo.setMinimumWidth(190)
        self.interface_combo.setMaxVisibleItems(4)
        self.interface_combo.setMinimumContentsLength(14)
        self.interface_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        try:
            self.interface_combo.setSizeAdjustPolicy(
                QComboBox.AdjustToMinimumContentsLengthWithIcon
            )
        except Exception:
            # Fallback for binding/version differences.
            pass
        popup_view = self.interface_combo.view()
        if popup_view is not None:
            popup_view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        interface_layout.addWidget(self.interface_combo)

        refresh_buttons_layout = QVBoxLayout()
        refresh_buttons_layout.setContentsMargins(0, 0, 0, 0)
        refresh_buttons_layout.setSpacing(4)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        refresh_buttons_layout.addWidget(refresh_btn)

        interface_layout.addLayout(refresh_buttons_layout)

        interface_layout.addStretch()
        layout.addLayout(interface_layout)

        # Filter and capture controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(
            "Display filter (e.g., dns, tcp and port 443, host 192.168.1.1)"
        )
        filter_layout.addWidget(self.filter_edit)

        # Apply filter button
        self.apply_filter_btn = QPushButton("Apply Filter")
        self.apply_filter_btn.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.apply_filter_btn)

        # Add filter helper button
        filter_help_btn = QPushButton("?")
        filter_help_btn.setMaximumWidth(25)
        filter_help_btn.setToolTip(
            "Display filter cheatsheet:\n"
            "  dns  tcp  udp  icmp  arp  http\n"
            "  port 53   src port 1234   dst port 80\n"
            "  host 1.2.3.4   src host 10.0.0.1\n"
            "  ip.src == 1.2.3.4   ip.dst == 8.8.8.8\n"
            "  tcp.port == 443\n"
            "  net 192.168.0.0/24\n"
            "  not tcp   tcp and port 443\n"
            "  (tcp or udp) and port 53\n"
            "Click for full reference →"
        )
        filter_help_btn.clicked.connect(self.show_filter_help)
        filter_layout.addWidget(filter_help_btn)

        # Filter status label (green/red inline indicator)
        self.filter_status_label = QLabel("")
        self.filter_status_label.setMinimumWidth(180)
        filter_layout.addWidget(self.filter_status_label)

        layout.addLayout(filter_layout)

        # Connect Enter key in filter field to apply
        self.filter_edit.returnPressed.connect(self.apply_filter)
        self.filter_edit.textChanged.connect(self._on_filter_text_changed)

        # Capture buttons
        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        button_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_packets)
        button_layout.addWidget(self.clear_btn)

        button_layout.addStretch()

        # Packets per second indicator
        self.pps_label = QLabel("PPS: 0")
        self.pps_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        button_layout.addWidget(self.pps_label)

        layout.addLayout(button_layout)

        return frame

    def create_right_panel(self) -> QWidget:
        """Create right panel with packet details"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Tab widget for different views
        self.detail_tabs = QTabWidget()

        # Packet details tab
        self.packet_details = PacketDetailsWidget()
        self.detail_tabs.addTab(self.packet_details, "Packet Details")

        # Hex view tab
        self.hex_view = HexViewWidget()
        self.detail_tabs.addTab(self.hex_view, "Hex/ASCII")

        # Metadata tab
        self.metadata_widget = QTextEdit()
        self.metadata_widget.setReadOnly(True)
        self.detail_tabs.addTab(self.metadata_widget, "Metadata")

        # AI Assistant tab (embedded — replaces the old floating panel)
        self.ai_copilot = AICopilotWidget()
        self.detail_tabs.addTab(self.ai_copilot, "🤖 AI Assistant")

        layout.addWidget(self.detail_tabs)
        panel.setLayout(layout)

        return panel

    def create_bottom_panel(self) -> QWidget:
        """Create bottom monitoring panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Create monitoring dashboard
        self.monitoring_dashboard = MonitoringDashboard()
        layout.addWidget(self.monitoring_dashboard)

        # Set maximum height for bottom panel - increased to allow charts to render
        panel.setMaximumHeight(320)
        panel.setMinimumHeight(200)
        panel.setLayout(layout)

        return panel

    def setup_menu_bar(self):
        """Setup menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        open_action = QAction("Open Capture...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_capture)
        file_menu.addAction(open_action)

        save_action = QAction("Save Capture...", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_capture)
        file_menu.addAction(save_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Capture menu
        capture_menu = menubar.addMenu("Capture")

        start_action = QAction("Start Capture", self)
        start_action.setShortcut("F5")
        start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(start_action)

        stop_action = QAction("Stop Capture", self)
        stop_action.setShortcut("F6")
        stop_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(stop_action)

        capture_menu.addSeparator()

        refresh_interfaces_action = QAction("Refresh Interfaces", self)
        refresh_interfaces_action.setShortcut("F2")
        refresh_interfaces_action.triggered.connect(self.refresh_interfaces)
        capture_menu.addAction(refresh_interfaces_action)

        refresh_app_action = QAction("Refresh Application", self)
        refresh_app_action.setShortcut("Ctrl+R")
        refresh_app_action.triggered.connect(self.refresh_application)
        capture_menu.addAction(refresh_app_action)

        capture_menu.addSeparator()

        interfaces_action = QAction("Interfaces...", self)
        interfaces_action.triggered.connect(self.show_interfaces)
        capture_menu.addAction(interfaces_action)

        # Analyze menu
        analyze_menu = menubar.addMenu("Analyze")

        decode_action = QAction("Decode As...", self)
        analyze_menu.addAction(decode_action)

        follow_action = QAction("Follow Stream", self)
        follow_action.triggered.connect(self.follow_stream)
        analyze_menu.addAction(follow_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        ai_copilot_action = QAction("AI Assistant", self)
        ai_copilot_action.setShortcut("F7")
        ai_copilot_action.triggered.connect(self.focus_ai_tab)
        tools_menu.addAction(ai_copilot_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def setup_toolbar(self):
        """Setup toolbar"""
        toolbar = QToolBar()
        self.addToolBar(toolbar)

        open_action = QAction("Open", self)
        open_action.triggered.connect(self.open_capture)
        toolbar.addAction(open_action)

        save_action = QAction("Save", self)
        save_action.triggered.connect(self.save_capture)
        toolbar.addAction(save_action)

        refresh_app_action = QAction("Refresh App", self)
        refresh_app_action.triggered.connect(self.refresh_application)
        toolbar.addAction(refresh_app_action)

    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Status labels
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)

        self.packet_count_label = QLabel("Packets: 0")
        self.status_bar.addPermanentWidget(self.packet_count_label)

        self.capture_time_label = QLabel("Duration: 00:00:00")
        self.status_bar.addPermanentWidget(self.capture_time_label)

    def setup_connections(self):
        """Setup signal connections"""
        # Packet table selection
        self.packet_table.packet_selected.connect(self.on_packet_selected)

        # Create a wrapper for packet callback that's thread-safe
        from PySide6.QtCore import QObject
        
        class PacketSignalBridge(QObject):
            packet_captured = Signal(object)  # PacketInfo
            stats_updated = Signal(object)    # CaptureStats
        
        self.signal_bridge = PacketSignalBridge()
        self.signal_bridge.packet_captured.connect(self._on_packet_captured_safe)
        self.signal_bridge.stats_updated.connect(self._on_stats_updated_safe)
        
        # Set callbacks that will emit signals
        self.capture_engine.set_packet_callback(self.signal_bridge.packet_captured.emit)
        self.capture_engine.set_stats_callback(self.signal_bridge.stats_updated.emit)

    def refresh_interfaces(self):
        """Refresh available network interfaces with loading indicator"""
        # Refresh monitoring visuals too (user-requested behavior).
        self.monitoring_dashboard.clear_dashboard()
        self.pps_label.setText("PPS: 0")
        self.capture_time_label.setText("Duration: 00:00:00")

        # Show loading state
        self.status_label.setText("Loading interfaces...")
        self.interface_combo.setEnabled(False)
        
        # Use QTimer to allow UI to update before loading
        QTimer.singleShot(50, self._do_refresh_interfaces)
    
    def _do_refresh_interfaces(self):
        """Actually refresh interfaces (called after UI updates)"""
        try:
            interfaces = self.capture_engine.get_interfaces()
            capturable = set(getattr(self.capture_engine, "capturable_interfaces", set()))
            capturable_list = [x for x in interfaces if x in capturable]
            other_list = [x for x in interfaces if x not in capturable]
            ordered_interfaces = capturable_list + other_list
            print(
                f"DEBUG: Main window refresh_interfaces() called with {len(interfaces)} interfaces"
            )
            print(f"DEBUG: Interfaces from capture engine: {interfaces}")

            # Populate combo with friendly names and set tooltip/data to actual device id
            self.interface_combo.clear()
            for friendly in ordered_interfaces:
                actual = self.capture_engine.interface_map.get(friendly, friendly)
                self.interface_combo.addItem(friendly)
                idx = self.interface_combo.findText(friendly)
                # Set tooltip so hovering shows real device id
                self.interface_combo.setItemData(idx, actual, Qt.ToolTipRole)
                # Also store actual device id in UserRole for quick lookup
                self.interface_combo.setItemData(idx, actual, Qt.UserRole)

            # Add non-selectable separator before non-capturable entries.
            if capturable_list and other_list:
                separator_text = "---- Other Interfaces ----"
                self.interface_combo.insertItem(len(capturable_list), separator_text)
                self.interface_combo.setItemData(len(capturable_list), None, Qt.UserRole)
                model = self.interface_combo.model()
                try:
                    sep_item = model.item(len(capturable_list))
                    if sep_item is not None:
                        sep_item.setFlags(Qt.NoItemFlags)
                except Exception:
                    pass

            # Ensure full interface names are visible without truncation.
            self._adjust_interface_combo_width()

            print(
                f"DEBUG: Interface combo items set to: {self.interface_combo.count()} items"
            )

            # Try to select a non-loopback interface by default
            selected_interface = None
            for i, interface in enumerate(capturable_list):
                print(f"DEBUG: Checking interface {i}: '{interface}'")
                # Skip loopback interface
                if "Loopback" not in interface and "Device-" not in interface:
                    selected_interface = interface
                    print(f"DEBUG: Selected default interface: '{selected_interface}'")
                    break

            # Set selected interface if found
            if selected_interface:
                index = self.interface_combo.findText(selected_interface)
                if index >= 0:
                    self.interface_combo.setCurrentIndex(index)
                    print(f"DEBUG: Set interface combo to index {index}")
                    # Map and set the actual device in capture engine
                    actual_device = self.interface_combo.itemData(index, Qt.UserRole)
                    if actual_device:
                        self.capture_engine.set_interface(actual_device)
                        print(f"DEBUG: Mapped '{selected_interface}' to '{actual_device}'")
                    else:
                        self.capture_engine.set_interface(selected_interface)
                        print(
                            f"DEBUG: No mapping found, setting interface directly: '{selected_interface}'"
                        )

            if capturable_list and not self.capture_engine.current_interface:
                # Fallback to first non-loopback interface
                for i, interface in enumerate(capturable_list):
                    if "Loopback" not in interface and "Device-" not in interface:
                        fallback_interface = interface
                        print(
                            f"DEBUG: Using fallback interface {i}: '{fallback_interface}'"
                        )
                        # Set both friendly name and try to get actual device
                        index = self.interface_combo.findText(fallback_interface)
                        if index >= 0:
                            actual_device = self.interface_combo.itemData(
                                index, Qt.UserRole
                            )
                            if actual_device:
                                print(
                                    f"DEBUG: Mapped fallback '{fallback_interface}' to '{actual_device}'"
                                )
                                self.capture_engine.set_interface(actual_device)
                            else:
                                self.capture_engine.set_interface(fallback_interface)
                                print(
                                    f"DEBUG: No mapping for fallback, setting directly: '{fallback_interface}'"
                                )
                        break

            print(f"DEBUG: Final interface combo count: {self.interface_combo.count()}")
            
            # Update status
            if self.interface_combo.count() > 0:
                self.status_label.setText(f"Ready - {self.interface_combo.count()} interfaces found")
            else:
                self.status_label.setText("No interfaces found")
                
        except Exception as e:
            print(f"Error refreshing interfaces: {e}")
            self.status_label.setText(f"Error: {str(e)}")
        finally:
            # Re-enable interface combo
            self.interface_combo.setEnabled(True)

    def refresh_application(self):
        """Soft-refresh the application state without restarting the process."""
        try:
            if self.capture_engine.is_capturing:
                self.capture_engine.stop_capture()

            # Reset volatile UI/capture state.
            self.clear_packets()
            self.capture_engine.set_filter("")
            self.filter_edit.clear()
            self.filter_status_label.setText("")
            self._last_filter_text = ""
            self._last_filter_validation = (True, "")

            # Reload runtime state.
            self.refresh_interfaces()
            self.check_npcap_status()
            self.status_label.setText("Application refreshed")
        except Exception as e:
            self.status_label.setText(f"Refresh failed: {e}")

    def _adjust_interface_combo_width(self):
        """Resize interface dropdown and popup width with compact bounds."""
        try:
            if not hasattr(self, "interface_combo") or self.interface_combo is None:
                return

            count = self.interface_combo.count()
            if count <= 0:
                return

            # Keep compact width by default; scale moderately with window size.
            window_width = max(400, self.width())
            control_width = min(max(int(window_width * 0.30), 190), 320)
            popup_width = min(max(control_width + 20, 230), 360)

            self.interface_combo.setMinimumWidth(control_width)
            self.interface_combo.setMaximumWidth(control_width)

            popup_view = self.interface_combo.view()
            if popup_view is not None:
                popup_view.setMinimumWidth(popup_width)
                popup_view.setMaximumWidth(popup_width)
                popup_view.setTextElideMode(Qt.ElideRight)
                popup_view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
                row_height = popup_view.sizeHintForRow(0)
                if row_height <= 0:
                    row_height = 24
                popup_view.setMaximumHeight((row_height * 4) + 8)
        except Exception as e:
            # Never let sizing logic impact application stability.
            print(f"Warning: failed to adjust interface dropdown width: {e}")

    def resizeEvent(self, event):
        """Keep interface dropdown responsive when window size changes."""
        super().resizeEvent(event)
        self._adjust_interface_combo_width()

    def check_npcap_status(self):
        """Check driver status and show appropriate UI guidance (cross-platform)."""
        status, info = self.driver_manager.get_status()

        print(f"Driver Status: {status}")
        print(f"   Driver installed: {info.get('driver_installed', info.get('npcap_installed', False))}")
        print(f"   Non-admin support: {info.get('non_admin_support', False)}")
        print(f"   Service running: {info.get('service_running', True)}")

        # Determine the driver name for user-facing messages
        driver_name = "Npcap" if sys.platform.startswith("win") else "libpcap"

        if status == DriverStatus.NOT_INSTALLED:
            self.show_npcap_warning(
                f"{driver_name} Required",
                f"CyberOctet requires {driver_name} for packet capture. "
                + ("Please install Npcap with non-admin support." if sys.platform.startswith("win")
                   else "Run: sudo apt install libpcap-dev tcpdump (Ubuntu/Debian)"),
                "install",
            )
        elif status == DriverStatus.INSTALLED_NO_NON_ADMIN:
            self.show_npcap_warning(
                f"{driver_name} Permission Issue",
                ("Npcap is installed but without non-admin support. Please reinstall with correct configuration."
                 if sys.platform.startswith("win")
                 else "libpcap is installed but capture requires root or the wireshark group. "
                      "Run: sudo usermod -aG wireshark $USER"),
                "reinstall",
            )
        elif status == DriverStatus.SERVICE_NOT_RUNNING:
            self.show_npcap_warning(
                "Npcap Service Issue",
                "Npcap service is not running. Please restart: net start npcap",
                "service",
            )
        elif status == DriverStatus.INSTALLED_WITH_NON_ADMIN:
            if not info.get("service_running", True):
                self.show_npcap_warning(
                    "Npcap Service Issue",
                    "Npcap service is not running. Please restart the service.",
                    "service",
                )
            else:
                self.clear_npcap_warning()
                print(f"{driver_name} is properly configured for capture")
        else:
            self.show_npcap_warning(
                f"{driver_name} Status Unknown",
                f"Unable to determine {driver_name} status. Please check installation.",
                "unknown",
            )

    def show_npcap_warning(self, title: str, message: str, warning_type: str):
        """Show Npcap warning banner"""
        self.clear_npcap_warning()

        warning_widget = QWidget()
        warning_widget.setStyleSheet(
            """
            QWidget {
                background-color: #ff6600;
                color: white;
                padding: 8px;
                border: 1px solid #ff4444;
                border-radius: 4px;
                font-weight: bold;
                margin: 2px;
            }
        """
        )

        banner_layout = QHBoxLayout(warning_widget)
        banner_layout.setContentsMargins(8, 4, 8, 4)
        banner_layout.setSpacing(8)

        warning_label = QLabel(f"Warning: {title}: {message}")
        warning_label.setWordWrap(True)
        banner_layout.addWidget(warning_label, 1)

        if warning_type in {"install", "reinstall", "service", "unknown"}:
            fix_btn = QPushButton("Fix Setup")
            fix_btn.setStyleSheet(
                "QPushButton { background-color: #1e1e1e; color: white; border: 1px solid white; padding: 4px 10px; }"
                "QPushButton:hover { background-color: #2a2a2a; }"
            )
            fix_btn.clicked.connect(lambda: self.show_npcap_dialog(warning_type))
            banner_layout.addWidget(fix_btn)

        self.npcap_warning = warning_widget

        # Insert warning at the top of the main layout
        main_layout = self.centralWidget().layout()
        main_layout.insertWidget(0, self.npcap_warning)

        # Disable capture controls
        self.start_btn.setEnabled(False)
        self.interface_combo.setEnabled(False)

        # Update status
        self.status_label.setText(f"Npcap Issue: {title}")

    def clear_npcap_warning(self):
        """Clear Npcap warning banner"""
        if hasattr(self, "npcap_warning"):
            self.npcap_warning.setParent(None)
            self.npcap_warning.deleteLater()
            self.npcap_warning = None

        # Enable capture controls
        self.start_btn.setEnabled(True)
        self.interface_combo.setEnabled(True)

    def show_npcap_dialog(self, dialog_type: str):
        """Show appropriate driver installation dialog (Windows only)."""
        if not sys.platform.startswith("win"):
            # On Linux/macOS show a plain message box with install instructions
            from PySide6.QtWidgets import QMessageBox
            instructions = self.driver_manager.get_install_instructions()
            msg = QMessageBox(self)
            msg.setWindowTitle(instructions.get("title", "Driver Setup"))
            msg.setText(instructions.get("message", ""))
            msg.setIcon(QMessageBox.Information)
            msg.exec()
            return

        if not self.npcap_dialog_manager:
            from backend.npcap_manager import NpcapDialogManager
            self.npcap_dialog_manager = NpcapDialogManager(self)

        if dialog_type == "install":
            self.npcap_dialog_manager.show_install_dialog()
        elif dialog_type == "reinstall":
            self.npcap_dialog_manager.show_reinstall_dialog()
        elif dialog_type == "service":
            self.npcap_dialog_manager.show_service_error_dialog()
    def apply_filter(self):
        """Validate and apply display filter to already-captured packets."""
        from core.packet_filter import PacketFilter

        filter_text = self.filter_edit.text().strip()

        if not filter_text:
            # No filter — show everything
            self.filter_status_label.setText("")
            self.filter_status_label.setStyleSheet("")
            self._active_filter_text = ""
            self.packet_table.filter_packets(None)
            self._last_filter_text = ""
            self._last_filter_validation = (True, "")
            return

        # Validate syntax (pure-Python, never BPF)
        valid, error = PacketFilter.validate(filter_text)
        self._last_filter_text = filter_text
        self._last_filter_validation = (valid, error)

        if valid:
            self._active_filter_text = filter_text
            self.filter_status_label.setText("✓ Filter active")
            self.filter_status_label.setStyleSheet(
                "color: #00ff88; font-weight: bold; background: transparent;"
            )
            # Apply filter to currently displayed packets
            self.packet_table.filter_packets(
                lambda pkt, f=filter_text: PacketFilter.match(pkt, f)
            )
        else:
            self._active_filter_text = ""
            self.filter_status_label.setText(f"✗ {error}")
            self.filter_status_label.setStyleSheet(
                "color: #ff4444; font-weight: bold; background: transparent;"
            )

    def _on_filter_text_changed(self, _text: str):
        """Mark cached filter validation stale after edits."""
        self.filter_status_label.setText("")
        if self._filter_auto_apply_enabled:
            # Auto-apply after user pauses typing.
            self._filter_apply_timer.start(350)

    def start_capture(self):
        """Start packet capture"""
        if not self.interface_combo.currentText():
            self.status_label.setText("No interface selected")
            return

        selected_label = self.interface_combo.currentText()
        capturable = set(getattr(self.capture_engine, "capturable_interfaces", set()))
        if selected_label not in capturable:
            self.status_label.setText("Selected interface is not capturable")
            return

        # Get the actual device name from UserRole data (set during refresh_interfaces)
        current_index = self.interface_combo.currentIndex()
        actual_device = self.interface_combo.itemData(current_index, Qt.UserRole)
        
        # Use actual device if available, otherwise fall back to friendly name
        if actual_device:
            interface = actual_device
        else:
            # Fallback: use the friendly name as-is
            interface = self.interface_combo.currentText()

        # Set capture parameters
        ok = self.capture_engine.set_interface(interface)
        if not ok:
            self.status_label.setText(f"Unknown interface: {interface}")
            return
        # Filter is now display-only (post-capture) — no BPF filter is passed to scapy.
        # Capture all packets; filtering runs on the already-captured list via apply_filter().

        # Check Npcap status (handled by warning banner if not ready)
        if not self.capture_engine.is_capture_ready():
            self.status_label.setText("Npcap not ready for capture")
            return

        # Start capture
        if self.capture_engine.start_capture():
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.interface_combo.setEnabled(False)
            # Show friendly name in status bar
            friendly_name = self.interface_combo.currentText()
            self.status_label.setText(f"Capturing on {friendly_name}...")
        else:
            self.status_label.setText("Failed to start capture")

    def stop_capture(self):
        """Stop packet capture"""
        self.capture_engine.stop_capture()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.status_label.setText("Capture stopped")
        self.filter_status_label.setText("")

    def show_filter_help(self):
        """Show comprehensive filter syntax reference dialog."""
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser, QPushButton

        dlg = QDialog(self)
        dlg.setWindowTitle("Display Filter Reference")
        dlg.setMinimumSize(600, 560)
        dlg.setStyleSheet("""
            QDialog   { background-color: #0a0a0a; color: #e0e0e0; }
            QTextBrowser {
                background-color: #111111;
                border: 1px solid #333333;
                color: #e0e0e0;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 10pt;
                padding: 8px;
            }
            QPushButton {
                background-color: #00ff88;
                color: #0a0a0a;
                border: none;
                padding: 6px 20px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #00aaff; color: #ffffff; }
        """)

        layout = QVBoxLayout(dlg)

        browser = QTextBrowser()
        browser.setOpenExternalLinks(False)
        browser.setHtml("""
<style>
  body   { background:#111; color:#e0e0e0;
            font-family:Consolas,'Courier New',monospace; font-size:10pt; margin:8px; }
  h2     { color:#00ff88; border-bottom:1px solid #333; padding-bottom:4px; }
  h3     { color:#00aaff; margin-top:12px; margin-bottom:4px; }
  table  { width:100%; border-collapse:collapse; margin-bottom:8px; }
  th     { background:#1a1a1a; color:#00ff88; padding:4px 8px;
            text-align:left; border:1px solid #333; }
  td     { padding:4px 8px; border:1px solid #222;
            vertical-align:top; }
  td.expr{ color:#00ff88; white-space:nowrap; }
  td.desc{ color:#aaaaaa; }
  .note  { background:#0d2b1a; border-left:3px solid #00ff88;
            padding:6px 10px; margin:8px 0; color:#cccccc; }
</style>

<h2>&#128270; Display Filter Reference</h2>
<p class="note">Filters run on <b>already-captured</b> packets. They are applied immediately
when you click <b>Apply Filter</b> or press <b>Enter</b>.
Boolean logic: <b>and &nbsp; or &nbsp; not</b>. Parentheses for grouping.</p>

<h3>Protocol Names (bare)</h3>
<table>
  <tr><th>Expression</th><th>Matches</th></tr>
  <tr><td class="expr">tcp</td>        <td class="desc">TCP packets</td></tr>
  <tr><td class="expr">udp</td>        <td class="desc">UDP packets (includes DNS, DHCP, mDNS)</td></tr>
  <tr><td class="expr">dns</td>        <td class="desc">DNS traffic (protocol=dns OR port 53)</td></tr>
  <tr><td class="expr">icmp</td>       <td class="desc">ICMP echo / ping</td></tr>
  <tr><td class="expr">arp</td>        <td class="desc">ARP requests &amp; replies</td></tr>
  <tr><td class="expr">http</td>       <td class="desc">HTTP (protocol=http OR TCP port 80/8080)</td></tr>
  <tr><td class="expr">tls</td>        <td class="desc">TLS / SSL packets</td></tr>
</table>

<h3>Port Matching</h3>
<table>
  <tr><th>Expression</th><th>Matches</th></tr>
  <tr><td class="expr">port 53</td>           <td class="desc">Src OR dst port = 53</td></tr>
  <tr><td class="expr">src port 1234</td>     <td class="desc">Source port = 1234</td></tr>
  <tr><td class="expr">dst port 80</td>       <td class="desc">Destination port = 80</td></tr>
  <tr><td class="expr">tcp.port == 443</td>   <td class="desc">TCP src or dst port = 443</td></tr>
  <tr><td class="expr">not port 22</td>       <td class="desc">Exclude SSH</td></tr>
</table>

<h3>IP / Host Matching</h3>
<table>
  <tr><th>Expression</th><th>Matches</th></tr>
  <tr><td class="expr">host 8.8.8.8</td>            <td class="desc">Src OR dst IP = 8.8.8.8</td></tr>
  <tr><td class="expr">ip 8.8.8.8</td>              <td class="desc">Same as host</td></tr>
  <tr><td class="expr">src host 192.168.1.5</td>    <td class="desc">Source IP only</td></tr>
  <tr><td class="expr">dst host 10.0.0.1</td>       <td class="desc">Destination IP only</td></tr>
  <tr><td class="expr">ip.src == 192.168.1.1</td>   <td class="desc">Wireshark-style field equality</td></tr>
  <tr><td class="expr">ip.dst == 8.8.4.4</td>       <td class="desc">Destination IP equals</td></tr>
  <tr><td class="expr">net 192.168.0.0/24</td>      <td class="desc">Src OR dst in CIDR subnet</td></tr>
</table>

<h3>Boolean &amp; Grouping</h3>
<table>
  <tr><th>Expression</th><th>Matches</th></tr>
  <tr><td class="expr">tcp and port 443</td>             <td class="desc">HTTPS traffic</td></tr>
  <tr><td class="expr">udp or icmp</td>                  <td class="desc">UDP or ICMP packets</td></tr>
  <tr><td class="expr">not tcp</td>                      <td class="desc">Everything except TCP</td></tr>
  <tr><td class="expr">not tcp and not arp</td>          <td class="desc">Exclude TCP and ARP</td></tr>
  <tr><td class="expr">(tcp or udp) and port 53</td>     <td class="desc">DNS over TCP or UDP</td></tr>
  <tr><td class="expr">host 10.0.0.1 and tcp</td>       <td class="desc">TCP to/from specific host</td></tr>
  <tr><td class="expr">net 10.0.0.0/8 and not port 22</td><td class="desc">All 10.x.x.x except SSH</td></tr>
</table>

<p class="note"><b>Tip:</b> Clear the filter field and press Enter (or click Apply) to show all packets again.</p>
""")
        layout.addWidget(browser)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn)

        dlg.exec()

    def clear_packets(self):
        """Clear captured packets"""
        self.capture_engine.clear_packets()
        self._pending_ui_packets.clear()
        self.packet_table.clear()
        self.packet_details.clear()
        self.hex_view.clear()
        self.monitoring_dashboard.clear_dashboard()
        self.current_packet = None
        self.packet_count_label.setText("Packets: 0")
        self.pps_label.setText("PPS: 0")
        self.capture_time_label.setText("Duration: 00:00:00")
        self.filter_status_label.setText("")
        self.ai_copilot.clear_conversation()

    def _on_packet_captured_safe(self, packet_info: PacketInfo):
        """Handle new captured packet (thread-safe slot)"""
        self._pending_ui_packets.append(packet_info)

    def _flush_pending_packets(self):
        """Flush pending packets to UI in bounded batches."""
        if not self._pending_ui_packets:
            return

        batch: List[PacketInfo] = []
        for _ in range(min(self._max_ui_batch_size, len(self._pending_ui_packets))):
            batch.append(self._pending_ui_packets.popleft())

        self.packet_table.add_packets(batch)
        self.packet_count_label.setText(
            f"Packets: {self.capture_engine.stats.packets_captured}"
        )
        # Re-apply active display filter so new packets are immediately filtered
        active_filter = getattr(self, "_active_filter_text", "")
        if active_filter:
            from core.packet_filter import PacketFilter
            self.packet_table.filter_packets(
                lambda pkt, f=active_filter: PacketFilter.match(pkt, f)
            )

    def on_packet_selected(self, packet_info: PacketInfo):
        """Handle packet selection"""
        self.current_packet = packet_info
        self.packet_details.show_packet_details(packet_info)
        self.hex_view.show_packet_data(packet_info)
        self.update_metadata(packet_info)

        # Pass full context to AI Assistant tab
        try:
            layers = self.packet_details.protocol_decoder.decode(packet_info)
        except Exception:
            layers = []
        self.ai_copilot.set_packet_context(packet_info, layers)
        recent_for_ai = self.capture_engine.get_captured_packets()[-2000:]
        self.ai_copilot.set_all_packets(recent_for_ai)

    def _on_stats_updated_safe(self, stats):
        """Handle statistics update (thread-safe slot)"""
        if stats:
            self.pps_label.setText(f"PPS: {stats.pps:.1f}")
            # Update monitoring dashboard
            self.monitoring_dashboard.update_stats(stats)

    def update_stats(self):
        """Update periodic statistics"""
        if self.capture_engine.is_capturing:
            stats = self.capture_engine.get_stats()
            if stats.start_time:
                import time

                # Update duration label
                duration = int(time.time() - stats.start_time)
                hours = duration // 3600
                minutes = (duration % 3600) // 60
                seconds = duration % 60
                self.capture_time_label.setText(
                    f"Duration: {hours:02d}:{minutes:02d}:{seconds:02d}"
                )
                
                # Update PPS and monitoring dashboard
                self.pps_label.setText(f"PPS: {stats.pps:.1f}")
                self.monitoring_dashboard.update_stats(stats)
                self.packet_count_label.setText(f"Packets: {stats.packets_captured}")

    def update_metadata(self, packet_info: PacketInfo):
        """Update metadata display"""
        metadata = f"""Packet Information:
================
Timestamp: {packet_info.timestamp}
Length: {packet_info.length} bytes
Interface: {packet_info.interface}
Protocol: {packet_info.protocol}

Network Layer:
==============
Source IP: {packet_info.src_ip}
Destination IP: {packet_info.dst_ip}

Transport Layer:
================
"""
        if packet_info.src_port:
            metadata += f"Source Port: {packet_info.src_port}\n"
        if packet_info.dst_port:
            metadata += f"Destination Port: {packet_info.dst_port}\n"
        if packet_info.flags:
            metadata += f"TCP Flags: {packet_info.flags}\n"
        if packet_info.seq_num:
            metadata += f"Sequence Number: {packet_info.seq_num}\n"
        if packet_info.ack_num:
            metadata += f"Acknowledgment: {packet_info.ack_num}\n"

        self.metadata_widget.setText(metadata)

    def open_capture(self):
        """Open capture file"""
        # TODO: Implement file opening
        self.status_label.setText("Open capture - TODO")

    def save_capture(self):
        """Save capture file"""
        from PySide6.QtWidgets import QFileDialog, QMessageBox
        
        if not self.capture_engine.captured_packets:
            QMessageBox.warning(self, "No Packets", "No packets to save. Start a capture first.")
            return
        
        # File dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Capture File",
            "",
            "PCAP Files (*.pcap);;PCAPNG Files (*.pcapng);;All Files (*.*)"
        )
        
        if not file_path:
            return
        
        # Ensure file has an extension
        if not os.path.splitext(file_path)[1]:
            file_path += '.pcap'
        
        # Determine format from extension
        _, ext = os.path.splitext(file_path)
        format_type = 'pcapng' if ext.lower() == '.pcapng' else 'pcap'
        
        try:
            # Convert PacketInfo to Scapy packets and save
            from scapy.all import wrpcap, Ether, PcapWriter
            
            scapy_packets = []
            for packet_info in self.capture_engine.captured_packets:
                try:
                    scapy_packet = Ether(packet_info.raw_data)
                    scapy_packets.append(scapy_packet)
                except Exception as e:
                    print(f"Error converting packet: {e}")
                    continue
            
            if not scapy_packets:
                QMessageBox.critical(self, "Error", "No valid packets to save.")
                return
            
            # Save to user-selected location
            if format_type == 'pcapng':
                writer = PcapWriter(file_path, linktype=1, sync=True)
                for packet in scapy_packets:
                    writer.write(packet)
                writer.close()
            else:
                wrpcap(file_path, scapy_packets)
            
            # Verify file was actually created
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                file_size = os.path.getsize(file_path)
                QMessageBox.information(
                    self, "Success",
                    f"Capture saved successfully!\n\n"
                    f"File: {os.path.basename(file_path)}\n"
                    f"Location: {os.path.dirname(file_path)}\n"
                    f"Packets: {len(scapy_packets)}\n"
                    f"Size: {file_size:,} bytes"
                )
                self.status_label.setText(f"Saved {len(scapy_packets)} packets to {os.path.basename(file_path)}")
            else:
                QMessageBox.critical(
                    self, "Error",
                    "File was not created. Check write permissions and disk space."
                )
                
        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to save capture file:\n{str(e)}"
            )
            print(f"Save error: {e}")

    def follow_stream(self):
        """Follow TCP/UDP stream"""
        if self.current_packet:
            # TODO: Implement stream following
            self.status_label.setText("Follow stream - TODO")
    def show_interfaces(self):
        """Show interface details dialog."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Network Interfaces")
        dialog.setMinimumSize(500, 400)
        dialog.setStyleSheet(f"""
            QDialog {{
                background-color: {Config.COLORS['background']};
                color: {Config.COLORS['text_primary']};
            }}
            QListWidget {{
                background-color: {Config.COLORS['surface']};
                color: {Config.COLORS['text_primary']};
                border: 1px solid {Config.COLORS['border']};
            }}
            QLabel {{
                color: {Config.COLORS['text_secondary']};
                background: transparent;
            }}
        """)

        layout = QVBoxLayout(dialog)
        title = QLabel("Available Network Interfaces")
        title.setStyleSheet(
            f"font-size: 14pt; font-weight: bold; color: {Config.COLORS['primary']};"
        )
        layout.addWidget(title)

        try:
            interfaces = self.driver_manager.get_interfaces()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get interfaces: {str(e)}")
            return

        buckets = {
            "Wi-Fi Interfaces": [],
            "Ethernet Interfaces": [],
            "Loopback": [],
            "Other Interfaces": [],
        }

        for iface in interfaces:
            name = iface.get("friendly", iface.get("name", "Unknown"))
            desc = iface.get("description", "")
            raw_name = iface.get("name", "")
            text = f"{name} {desc}".lower()
            if any(kw in text for kw in ["wi-fi", "wifi", "wireless", "802.11", "wlan"]):
                buckets["Wi-Fi Interfaces"].append((name, desc, raw_name))
            elif any(kw in text for kw in ["ethernet", "lan", "realtek", "intel"]):
                buckets["Ethernet Interfaces"].append((name, desc, raw_name))
            elif "loopback" in text:
                buckets["Loopback"].append((name, desc, raw_name))
            else:
                buckets["Other Interfaces"].append((name, desc, raw_name))

        list_widget = QListWidget()
        section_styles = {
            "Wi-Fi Interfaces": Config.COLORS['secondary'],
            "Ethernet Interfaces": Config.COLORS['primary'],
            "Loopback": Config.COLORS['accent'],
            "Other Interfaces": Config.COLORS['text_muted'],
        }

        for section in ["Wi-Fi Interfaces", "Ethernet Interfaces", "Loopback", "Other Interfaces"]:
            rows = buckets[section]
            if not rows:
                continue
            header = QLabel(section)
            header.setStyleSheet(
                f"font-weight: bold; color: {section_styles[section]};"
            )
            layout.addWidget(header)
            for name, desc, raw in rows:
                item = QListWidgetItem(f"  {name}")
                if desc:
                    item.setToolTip(desc)
                item.setData(Qt.UserRole, raw)
                list_widget.addItem(item)

        layout.addWidget(list_widget)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)

        dialog.exec()

    def _handle_error(self, error_type: str, error_message: str):
        """Handle errors from signals"""
        # Log error
        self._error_log.append({
            'type': error_type,
            'message': error_message,
            'timestamp': __import__('time').time()
        })
        
        # Keep only recent errors
        if len(self._error_log) > self._max_errors_displayed:
            self._error_log = self._error_log[-self._max_errors_displayed:]
        
        # Show non-critical errors in status bar
        if error_type != 'critical':
            self.status_label.setText(f"Error: {error_message}")

    def focus_ai_tab(self):
        """Switch to the AI Assistant tab"""
        for i in range(self.detail_tabs.count()):
            if "AI" in self.detail_tabs.tabText(i):
                self.detail_tabs.setCurrentIndex(i)
                break

    def show_about(self):
        """Show about dialog"""
        # TODO: Implement about dialog
        self.status_label.setText(
            f"{Config.APP_NAME} v{Config.VERSION} - Professional Packet Analyzer"
        )

    def closeEvent(self, event):
        """Handle application close"""
        # Stop capture if running
        if self.capture_engine.is_capturing:
            self.capture_engine.stop_capture()

        event.accept()

