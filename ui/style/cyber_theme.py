"""
Cyber Theme for CyberOctet Packet Analyzer
Professional dark theme with cyber aesthetics
"""

from PySide6.QtWidgets import QApplication, QWidget
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor

from core.config import Config


class CyberTheme:
    """Cyber-themed dark style for the application"""
    
    def __init__(self):
        self.colors = Config.COLORS
    
    def apply_theme(self, widget: QWidget):
        """Apply the cyber theme to a widget and its children"""
        # Set application palette
        palette = QPalette()
        
        # Base colors
        palette.setColor(QPalette.Window, QColor(self.colors['background']))
        palette.setColor(QPalette.WindowText, QColor(self.colors['text_primary']))
        palette.setColor(QPalette.Base, QColor(self.colors['surface']))
        palette.setColor(QPalette.AlternateBase, QColor(self.colors['surface_light']))
        palette.setColor(QPalette.ToolTipBase, QColor(self.colors['surface_light']))
        palette.setColor(QPalette.ToolTipText, QColor(self.colors['text_primary']))
        palette.setColor(QPalette.Text, QColor(self.colors['text_primary']))
        palette.setColor(QPalette.Button, QColor(self.colors['surface_light']))
        palette.setColor(QPalette.ButtonText, QColor(self.colors['text_primary']))
        palette.setColor(QPalette.BrightText, QColor(self.colors['primary']))
        
        # Highlight colors
        palette.setColor(QPalette.Highlight, QColor(self.colors['selection']))
        palette.setColor(QPalette.HighlightedText, QColor(self.colors['text_primary']))
        
        # Apply palette
        widget.setPalette(palette)
        
        # Apply global stylesheet
        stylesheet = self.get_global_stylesheet()
        widget.setStyleSheet(stylesheet)
    
    def get_global_stylesheet(self) -> str:
        """Get the global stylesheet for the application"""
        return f"""
        /* Global Styles */
        QWidget {{
            background-color: {self.colors['background']};
            color: {self.colors['text_primary']};
            font-family: {Config.DISPLAY['font_family']};
            font-size: {Config.DISPLAY['font_size']}pt;
            outline: none;
        }}
        
        /* Main Window */
        QMainWindow {{
            background-color: {self.colors['background']};
            border: 1px solid {self.colors['border']};
        }}
        
        /* Menu Bar */
        QMenuBar {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_secondary']};
            border-bottom: 1px solid {self.colors['border']};
            padding: 2px;
        }}
        
        QMenuBar::item {{
            background-color: transparent;
            padding: 4px 8px;
            border-radius: 3px;
        }}
        
        QMenuBar::item:selected {{
            background-color: {self.colors['selection']};
            color: {self.colors['text_primary']};
        }}
        
        QMenu {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            padding: 2px;
        }}
        
        QMenu::item {{
            padding: 4px 16px;
            border-radius: 3px;
        }}
        
        QMenu::item:selected {{
            background-color: {self.colors['selection']};
            color: {self.colors['text_primary']};
        }}
        
        /* Tool Bar */
        QToolBar {{
            background-color: {self.colors['surface']};
            border: 1px solid {self.colors['border']};
            spacing: 2px;
            padding: 2px;
        }}
        
        QToolButton {{
            background-color: {self.colors['surface_light']};
            color: {self.colors['text_secondary']};
            border: 1px solid {self.colors['border']};
            padding: 4px;
            border-radius: 3px;
            min-width: 20px;
        }}
        
        QToolButton:hover {{
            background-color: {self.colors['primary']};
            color: {self.colors['surface']};
        }}
        
        QToolButton:pressed {{
            background-color: {self.colors['accent']};
        }}
        
        /* Status Bar */
        QStatusBar {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_secondary']};
            border-top: 1px solid {self.colors['border']};
            padding: 2px;
        }}
        
        QStatusBar::item {{
            border: none;
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {self.colors['primary']};
            color: {self.colors['surface']};
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: bold;
        }}
        
        QPushButton:hover {{
            background-color: {self.colors['secondary']};
        }}
        
        QPushButton:pressed {{
            background-color: {self.colors['accent']};
        }}
        
        QPushButton:disabled {{
            background-color: {self.colors['surface_light']};
            color: {self.colors['text_muted']};
        }}
        
        /* Line Edit */
        QLineEdit {{
            background-color: {self.colors['surface_light']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            padding: 4px 6px;
            border-radius: 3px;
        }}
        
        QLineEdit:focus {{
            border: 1px solid {self.colors['primary']};
        }}
        
        /* Combo Box */
        QComboBox {{
            background-color: {self.colors['surface_light']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            padding: 4px 6px;
            border-radius: 3px;
            min-width: 80px;
        }}
        
        QComboBox::drop-down {{
            border: none;
            width: 20px;
        }}
        
        QComboBox::down-arrow {{
            image: none;
            border-left: 4px solid transparent;
            border-right: 4px solid transparent;
            border-top: 4px solid {self.colors['text_secondary']};
        }}
        
        QComboBox QAbstractItemView {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            selection-background-color: {self.colors['selection']};
        }}
        
        /* Check Box */
        QCheckBox {{
            color: {self.colors['text_primary']};
            spacing: 5px;
        }}
        
        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            background-color: {self.colors['surface_light']};
            border: 1px solid {self.colors['border']};
            border-radius: 2px;
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {self.colors['primary']};
            image: none;
        }}
        
        QCheckBox::indicator:checked:hover {{
            background-color: {self.colors['secondary']};
        }}
        
        /* Spin Box */
        QSpinBox {{
            background-color: {self.colors['surface_light']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            padding: 4px 6px;
            border-radius: 3px;
        }}
        
        QSpinBox::up-button, QSpinBox::down-button {{
            background-color: {self.colors['surface']};
            border: 1px solid {self.colors['border']};
            width: 16px;
        }}
        
        QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
            background-color: {self.colors['primary']};
        }}
        
        /* Progress Bar */
        QProgressBar {{
            background-color: {self.colors['surface_light']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            border-radius: 3px;
            text-align: center;
        }}
        
        QProgressBar::chunk {{
            background-color: {self.colors['primary']};
            border-radius: 2px;
        }}
        
        /* Group Box */
        QGroupBox {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_secondary']};
            border: 1px solid {self.colors['border']};
            border-radius: 4px;
            margin-top: 8px;
            padding-top: 8px;
            font-weight: bold;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 8px;
            padding: 0 4px 0 4px;
        }}
        
        /* Tab Widget */
        QTabWidget::pane {{
            border: 1px solid {self.colors['border']};
            background-color: {self.colors['surface']};
        }}
        
        QTabBar::tab {{
            background-color: {self.colors['surface_light']};
            color: {self.colors['text_secondary']};
            border: 1px solid {self.colors['border']};
            padding: 6px 12px;
            margin-right: 2px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {self.colors['primary']};
            color: {self.colors['surface']};
        }}
        
        QTabBar::tab:hover {{
            background-color: {self.colors['selection']};
        }}
        
        /* Splitter */
        QSplitter::handle {{
            background-color: {self.colors['border']};
        }}
        
        QSplitter::handle:horizontal {{
            width: 2px;
        }}
        
        QSplitter::handle:vertical {{
            height: 2px;
        }}
        
        QSplitter::handle:hover {{
            background-color: {self.colors['primary']};
        }}
        
        /* Scroll Bar */
        QScrollBar:vertical {{
            background-color: {self.colors['surface']};
            width: 12px;
            border: 1px solid {self.colors['border']};
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {self.colors['surface_light']};
            min-height: 20px;
            border-radius: 6px;
            margin: 2px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {self.colors['primary']};
        }}
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        
        QScrollBar:horizontal {{
            background-color: {self.colors['surface']};
            height: 12px;
            border: 1px solid {self.colors['border']};
            border-radius: 6px;
        }}
        
        QScrollBar::handle:horizontal {{
            background-color: {self.colors['surface_light']};
            min-width: 20px;
            border-radius: 6px;
            margin: 2px;
        }}
        
        QScrollBar::handle:horizontal:hover {{
            background-color: {self.colors['primary']};
        }}
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}
        
        /* Tool Tip */
        QToolTip {{
            background-color: {self.colors['surface_light']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['primary']};
            padding: 4px;
            border-radius: 3px;
        }}
        
        /* Frame */
        QFrame {{
            background-color: {self.colors['surface']};
            border: 1px solid {self.colors['border']};
        }}
        
        QFrame[frameShape="0"] {{
            border: none;
        }}
        
        /* Label */
        QLabel {{
            color: {self.colors['text_secondary']};
            background-color: transparent;
        }}
        
        /* Text Edit */
        QTextEdit {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            selection-background-color: {self.colors['selection']};
        }}
        
        /* Dialog */
        QDialog {{
            background-color: {self.colors['background']};
            color: {self.colors['text_primary']};
        }}
        
        /* Message Box */
        QMessageBox {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_primary']};
        }}
        
        QMessageBox QPushButton {{
            background-color: {self.colors['primary']};
            color: {self.colors['surface']};
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 80px;
        }}
        """
