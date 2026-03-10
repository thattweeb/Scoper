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

    from PySide6.QtCore import Qt, QRectF
    from PySide6.QtGui import (
        QColor, QFont, QFontMetrics, QLinearGradient, QPainter,
        QPainterPath, QPixmap,
    )
    from PySide6.QtWidgets import QApplication, QSplashScreen

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Scoper")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("CyberOctet Labs")

    # ── Splash dimensions ─────────────────────────────────────────────────
    W, H = 520, 260

    def _render_splash(progress: int, status_text: str) -> QPixmap:
        """Render a fresh splash pixmap for each progress step."""
        pix = QPixmap(W, H)
        pix.fill(QColor("#0a0a0a"))
        p = QPainter(pix)
        p.setRenderHint(QPainter.Antialiasing)

        # Background gradient
        grad = QLinearGradient(0, 0, W, H)
        grad.setColorAt(0.0, QColor("#0d1117"))
        grad.setColorAt(1.0, QColor("#0a0a0a"))
        p.fillRect(0, 0, W, H, grad)

        # Subtle grid lines for cyber feel
        p.setPen(QColor("#1a1a2e"))
        for x in range(0, W, 30):
            p.drawLine(x, 0, x, H)
        for y in range(0, H, 30):
            p.drawLine(0, y, W, y)

        # Border glow
        p.setPen(QColor("#00ff8840"))
        p.drawRect(1, 1, W - 2, H - 2)
        p.setPen(QColor("#00ff8820"))
        p.drawRect(3, 3, W - 6, H - 6)

        # App name — large
        font_title = QFont("Consolas", 34, QFont.Bold)
        p.setFont(font_title)
        p.setPen(QColor("#00ff88"))
        p.drawText(QRectF(0, 28, W, 60), Qt.AlignHCenter, "SCOPER")

        # Tagline
        font_tag = QFont("Consolas", 9)
        p.setFont(font_tag)
        p.setPen(QColor("#00aaff"))
        p.drawText(QRectF(0, 82, W, 24), Qt.AlignHCenter,
                   "Network Packet Analyzer  ·  CyberOctet Labs")

        # Separator line
        p.setPen(QColor("#00ff8840"))
        p.drawLine(40, 116, W - 40, 116)

        # Progress bar track
        bar_x, bar_y = 40, 140
        bar_w, bar_h = W - 80, 12
        p.setBrush(QColor("#1a1a1a"))
        p.setPen(QColor("#333333"))
        radius = bar_h / 2
        p.drawRoundedRect(QRectF(bar_x, bar_y, bar_w, bar_h), radius, radius)

        # Progress bar fill
        fill_w = int(bar_w * progress / 100)
        if fill_w > 0:
            bar_grad = QLinearGradient(bar_x, 0, bar_x + bar_w, 0)
            bar_grad.setColorAt(0.0, QColor("#00cc66"))
            bar_grad.setColorAt(0.5, QColor("#00ff88"))
            bar_grad.setColorAt(1.0, QColor("#00aaff"))
            p.setBrush(bar_grad)
            p.setPen(Qt.NoPen)
            clip_rect = QRectF(bar_x, bar_y, fill_w, bar_h)
            path = QPainterPath()
            path.addRoundedRect(QRectF(bar_x, bar_y, bar_w, bar_h), radius, radius)
            p.setClipPath(path)
            p.fillRect(clip_rect, bar_grad)
            p.setClipping(False)

        # Percent label
        font_pct = QFont("Consolas", 8)
        p.setFont(font_pct)
        p.setPen(QColor("#00ff88"))
        p.drawText(QRectF(bar_x + bar_w + 8, bar_y - 2, 36, bar_h + 4),
                   Qt.AlignLeft | Qt.AlignVCenter, f"{progress}%")

        # Status text
        font_status = QFont("Consolas", 9)
        p.setFont(font_status)
        p.setPen(QColor("#888888"))
        p.drawText(QRectF(0, 164, W, 24), Qt.AlignHCenter, status_text)

        # Version
        font_ver = QFont("Consolas", 7)
        p.setFont(font_ver)
        p.setPen(QColor("#444444"))
        p.drawText(QRectF(0, H - 22, W, 18), Qt.AlignHCenter, "v1.0.0")

        p.end()
        return pix

    # ── Create and show splash ────────────────────────────────────────────
    splash = QSplashScreen(_render_splash(0, "Initializing…"))
    splash.setWindowFlag(Qt.WindowStaysOnTopHint, True)
    splash.show()
    app.processEvents()

    def _update(pct: int, msg: str):
        splash.setPixmap(_render_splash(pct, msg))
        splash.show()
        app.processEvents()

    # ── Staged loading with progress ──────────────────────────────────────
    _update(10, "Checking dependencies…")
    app.processEvents()

    _update(30, "Loading UI components…")
    from ui.main_window import MainWindow  # noqa: E402 — intentional deferred import

    _update(55, "Detecting network interfaces…")
    app.processEvents()

    _update(75, "Initializing capture engine…")
    main_window = MainWindow()

    _update(90, "Starting AI assistant…")
    app.processEvents()

    _update(100, "Ready!")
    app.processEvents()

    main_window.show()
    splash.finish(main_window)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
