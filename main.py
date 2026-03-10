#!/usr/bin/env python3
"""
CyberOctet - Professional Network Packet Analyzer
A modern, dark-themed packet analysis tool for cybersecurity professionals.
"""

import importlib
import subprocess
import sys
from pathlib import Path

# Add project root to import path.
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# module name -> install name
_RUNTIME_REQUIREMENTS = {
    "PySide6": "PySide6",
    "scapy": "scapy",
    "matplotlib": "matplotlib",
    "numpy": "numpy",
    "psutil": "psutil",
}


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _show_startup_error(message: str) -> None:
    """Best-effort startup error dialog without assuming Qt is available."""
    if sys.platform.startswith("win"):
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, message, "Scoper Startup Error", 0x10)
            return
        except Exception:
            pass
    print(message)


def _ensure_python_dependencies() -> bool:
    """Auto-install missing Python dependencies for source runs."""
    if _is_frozen():
        return True

    missing = []
    for module_name, package_name in _RUNTIME_REQUIREMENTS.items():
        try:
            importlib.import_module(module_name)
        except Exception:
            missing.append(package_name)

    if not missing:
        return True

    try:
        run_kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "stdin": subprocess.DEVNULL,
        }
        if sys.platform.startswith("win"):
            run_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", *missing],
            check=False,
            **run_kwargs,
        )
        if result.returncode != 0:
            raise RuntimeError(f"pip exited with code {result.returncode}")
        return True
    except Exception as exc:
        _show_startup_error(
            "Failed to install required Python packages automatically.\n"
            f"Missing: {', '.join(missing)}\n"
            f"Error: {exc}"
        )
        return False


def main():
    """Main entry point for CyberOctet packet analyzer."""
    if not _ensure_python_dependencies():
        return 1

    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QPainter, QPixmap
    from PySide6.QtWidgets import QApplication, QSplashScreen

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("scoper")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("CyberOctet Labs")

    splash_img = QPixmap(460, 180)
    splash_img.fill(QColor("#101114"))
    painter = QPainter(splash_img)
    painter.setPen(QColor("#00ff88"))
    painter.drawText(24, 98, "scoper is loading...")
    painter.end()
    splash = QSplashScreen(splash_img)
    splash.setWindowFlag(Qt.WindowStaysOnTopHint, True)
    splash.show()
    app.processEvents()

    from ui.main_window import MainWindow

    main_window = MainWindow()
    main_window.show()
    splash.finish(main_window)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
