"""
AI Assistant Panel for CyberOctet
Chat-style interface with LLM-powered packet analysis
"""

import os
import time
import json
from typing import Optional, List, Dict, Any
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QFrame, QScrollArea, QSplitter,
    QGroupBox, QProgressBar, QComboBox, QDialog, QFormLayout,
    QDialogButtonBox, QMessageBox
)
from PySide6.QtCore import Qt, Signal, QTimer, QThread, QSize
from PySide6.QtGui import QFont, QTextCursor, QColor, QIcon

from core.config import Config
from core.capture_engine import PacketInfo
from core.protocol_decoder.decoder import ProtocolDecoder, ProtocolLayer


# ──────────────────────────────────────────────────────────────────────────
# System prompt used for every AI request
# ──────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an expert network analyst and packet forensics assistant embedded in a packet capture tool.
The user will provide raw packet data, decoded fields, or ask questions about network traffic.
Your job is to:
1. Clearly explain what the packet is doing in plain language
2. Identify the protocol stack (e.g., Ethernet > IP > TCP > HTTP)
3. Flag any anomalies, suspicious patterns, or security concerns
4. When asked to "follow the stream", reconstruct and summarize the application-layer conversation
5. Answer technical questions about packet fields, flags, checksums, and protocol behavior
Be concise but thorough. Use bullet points for multi-part explanations.\
"""


# ──────────────────────────────────────────────────────────────────────────
# Background worker thread for AI calls
# ──────────────────────────────────────────────────────────────────────────

class AIWorkerThread(QThread):
    """Background thread for AI API calls — never blocks the UI."""

    response_ready = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, query: str, context: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.query = query
        self.context = context

    def run(self):
        try:
            # Try to use the AICopilot engine from ai/copilot.py
            copilot = self.context.get("copilot")
            packet_info = self.context.get("packet_info")
            protocol_layers = self.context.get("protocol_layers", [])

            if copilot and packet_info:
                response = copilot.analyze_packet(packet_info, protocol_layers, self.query)
                self.response_ready.emit(response.response)
            elif copilot:
                # Free-form question without packet context
                # Use the LLM directly if available
                provider = copilot._provider
                from ai.copilot import StaticRulesProvider
                if not isinstance(provider, StaticRulesProvider):
                    result = provider.complete(SYSTEM_PROMPT, self.query)
                    if result:
                        self.response_ready.emit(result)
                        return
                self.response_ready.emit(
                    "Please select a packet first, or set up an API key in "
                    "Settings (⚙) to ask general questions."
                )
            else:
                self.response_ready.emit(
                    "AI engine not initialized. Open Settings (⚙) to configure your API key."
                )
        except Exception as exc:
            self.error_occurred.emit(str(exc))


# ──────────────────────────────────────────────────────────────────────────
# Settings dialog
# ──────────────────────────────────────────────────────────────────────────

class AISettingsDialog(QDialog):
    """Settings dialog for API key, provider, and model selection."""

    def __init__(self, parent=None, current_provider="openai", current_model="gpt-4o",
                 current_key=""):
        super().__init__(parent)
        self.setWindowTitle("AI Assistant Settings")
        self.setMinimumWidth(420)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {Config.COLORS['background']};
                color: {Config.COLORS['text_primary']};
            }}
            QLabel {{
                color: {Config.COLORS['text_secondary']};
                background: transparent;
            }}
            QLineEdit, QComboBox {{
                background-color: {Config.COLORS['surface_light']};
                color: {Config.COLORS['text_primary']};
                border: 1px solid {Config.COLORS['border']};
                padding: 5px;
            }}
            QPushButton {{
                background-color: {Config.COLORS['primary']};
                color: {Config.COLORS['surface']};
                border: none;
                padding: 6px 14px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {Config.COLORS['secondary']};
            }}
        """)

        layout = QFormLayout(self)

        # Provider
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["OpenAI", "Anthropic"])
        idx = 0 if current_provider.lower() == "openai" else 1
        self.provider_combo.setCurrentIndex(idx)
        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        layout.addRow("Provider:", self.provider_combo)

        # Model
        self.model_combo = QComboBox()
        self._populate_models()
        if current_model:
            mi = self.model_combo.findText(current_model)
            if mi >= 0:
                self.model_combo.setCurrentIndex(mi)
        layout.addRow("Model:", self.model_combo)

        # API key
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_key_edit.setPlaceholderText("Paste your API key here")
        if current_key:
            self.api_key_edit.setText(current_key)
        layout.addRow("API Key:", self.api_key_edit)

        # Info
        info = QLabel("Key is stored locally in your OS credential store (keyring) or config file.")
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {Config.COLORS['text_muted']}; font-size: 8pt;")
        layout.addRow(info)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _on_provider_changed(self, _idx):
        self._populate_models()

    def _populate_models(self):
        self.model_combo.clear()
        if self.provider_combo.currentText() == "OpenAI":
            self.model_combo.addItems(["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"])
        else:
            self.model_combo.addItems([
                "claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022",
                "claude-3-haiku-20240307",
            ])

    def get_settings(self) -> Dict[str, str]:
        return {
            "provider": self.provider_combo.currentText().lower(),
            "model": self.model_combo.currentText(),
            "api_key": self.api_key_edit.text().strip(),
        }


# ──────────────────────────────────────────────────────────────────────────
# Chat bubble helper
# ──────────────────────────────────────────────────────────────────────────

def _make_bubble_html(sender: str, message: str, is_user: bool) -> str:
    """Return styled HTML for a single chat bubble."""
    bg = "#0d2b1a" if is_user else "#1a1a1a"
    align = "right" if is_user else "left"
    name_color = "#00ff88" if not is_user else "#00aaff"
    border_color = "#00ff8840" if not is_user else "#00aaff40"

    # Escape HTML in message, then convert newlines and markdown-bold
    import html as _html
    safe = _html.escape(message)
    safe = safe.replace("\n", "<br>")
    # Simple bold: **text** → <b>text</b>
    import re
    safe = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", safe)
    # Bullet points
    safe = re.sub(r"^- ", "• ", safe, flags=re.MULTILINE)
    safe = re.sub(r"^• ", "&nbsp;&nbsp;• ", safe, flags=re.MULTILINE)

    return (
        f'<div style="text-align:{align}; margin:4px 0;">'
        f'<div style="display:inline-block; background:{bg}; border:1px solid {border_color}; '
        f'border-radius:10px; padding:8px 12px; max-width:85%; text-align:left;">'
        f'<span style="color:{name_color}; font-weight:bold; font-size:8pt;">{sender}</span><br>'
        f'<span style="color:#e0e0e0; font-family:Consolas,\'Courier New\',monospace; font-size:9pt;">'
        f'{safe}</span></div></div>'
    )


# ──────────────────────────────────────────────────────────────────────────
# Main widget
# ──────────────────────────────────────────────────────────────────────────

class AICopilotWidget(QWidget):
    """AI Assistant tab — chat-bubble interface with LLM integration."""

    def __init__(self):
        super().__init__()

        self.current_packet: Optional[PacketInfo] = None
        self.current_layers: List[ProtocolLayer] = []
        self.protocol_decoder = ProtocolDecoder()
        self.ai_thread: Optional[AIWorkerThread] = None

        # AI engine (from ai/copilot.py)
        self._copilot = None
        self._init_copilot()

        # Stored settings
        self._provider_name = "openai"
        self._model_name = "gpt-4o"
        self._api_key = ""
        self._load_settings()

        # Captured packets reference (set by MainWindow)
        self.all_packets: List[PacketInfo] = []

        self.setup_ui()
        self.setup_style()

    # ── AI engine init ────────────────────────────────────────────────────

    def _init_copilot(self):
        try:
            from ai.copilot import AICopilot
            self._copilot = AICopilot()
        except Exception as exc:
            print(f"[AIAssistant] Could not init AICopilot: {exc}")
            self._copilot = None

    def _load_settings(self):
        """Load saved settings from config file."""
        config_path = os.path.join(os.path.expanduser("~"), ".cyberoctet_ai.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    data = json.load(f)
                self._provider_name = data.get("provider", "openai")
                self._model_name = data.get("model", "gpt-4o")
                self._api_key = data.get("api_key", "")
                if self._api_key:
                    self._apply_key_to_copilot()
            except Exception:
                pass

    def _save_settings(self):
        """Save settings to config file."""
        config_path = os.path.join(os.path.expanduser("~"), ".cyberoctet_ai.json")
        try:
            with open(config_path, "w") as f:
                json.dump({
                    "provider": self._provider_name,
                    "model": self._model_name,
                    "api_key": self._api_key,
                }, f)
        except Exception as exc:
            print(f"[AIAssistant] Failed to save settings: {exc}")

    def _apply_key_to_copilot(self):
        """Apply the current API key + model to the copilot engine."""
        if not self._copilot:
            self._init_copilot()
        if not self._copilot:
            return

        try:
            if self._provider_name == "openai" and self._api_key:
                os.environ["OPENAI_API_KEY"] = self._api_key
                from ai.copilot import OpenAIAssistant
                provider = OpenAIAssistant(model=self._model_name)
                if provider.is_available:
                    self._copilot.configure_provider(provider)
            elif self._provider_name == "anthropic" and self._api_key:
                os.environ["ANTHROPIC_API_KEY"] = self._api_key
                try:
                    from ai.copilot_anthropic import AnthropicProvider
                    provider = AnthropicProvider(model=self._model_name,
                                                 api_key=self._api_key)
                    if provider.is_available:
                        self._copilot.configure_provider(provider)
                except ImportError:
                    # Anthropic provider module not available — use inline
                    self._init_anthropic_inline()
        except Exception as exc:
            print(f"[AIAssistant] Failed to apply key: {exc}")

    def _init_anthropic_inline(self):
        """Create a simple Anthropic provider inline if the module isn't installed."""
        try:
            import anthropic
            from ai.copilot import LLMProvider

            class _AnthropicInline(LLMProvider):
                def __init__(self, model, api_key):
                    self._model = model
                    self._client = anthropic.Anthropic(api_key=api_key)

                @property
                def name(self):
                    return f"Anthropic ({self._model})"

                @property
                def is_available(self):
                    return True

                def complete(self, system_prompt, user_message):
                    try:
                        resp = self._client.messages.create(
                            model=self._model,
                            max_tokens=1024,
                            system=system_prompt,
                            messages=[{"role": "user", "content": user_message}],
                        )
                        return resp.content[0].text
                    except Exception as e:
                        print(f"Anthropic error: {e}")
                        return None

            provider = _AnthropicInline(self._model_name, self._api_key)
            if self._copilot:
                self._copilot.configure_provider(provider)
        except ImportError:
            print("[AIAssistant] anthropic package not installed. pip install anthropic")

    # ── UI setup ──────────────────────────────────────────────────────────

    def setup_ui(self):
        """Setup the AI Assistant chat UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # ── Header ──
        header_frame = QFrame()
        header_layout = QHBoxLayout(header_frame)

        title_label = QLabel("🤖 AI Assistant")
        title_label.setStyleSheet(f"""
            QLabel {{
                color: {Config.COLORS['primary']};
                font-size: 12pt;
                font-weight: bold;
                background: transparent;
            }}
        """)
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Provider status
        self.provider_label = QLabel("")
        self.provider_label.setStyleSheet(
            f"color: {Config.COLORS['text_muted']}; font-size: 8pt; background: transparent;"
        )
        self._update_provider_label()
        header_layout.addWidget(self.provider_label)

        # Settings gear button
        self.settings_btn = QPushButton("⚙")
        self.settings_btn.setMaximumSize(QSize(28, 28))
        self.settings_btn.setToolTip("AI Settings — API key, model, provider")
        self.settings_btn.clicked.connect(self.open_settings)
        header_layout.addWidget(self.settings_btn)

        layout.addWidget(header_frame)

        # ── Chat history ──
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet(f"""
            QTextEdit {{
                background-color: #0a0a0a;
                border: 1px solid {Config.COLORS['border']};
                color: {Config.COLORS['text_primary']};
                font-family: Consolas, 'Courier New', monospace;
                font-size: 9pt;
            }}
        """)
        layout.addWidget(self.chat_area, 1)  # stretch

        # ── Thinking indicator ──
        self.thinking_label = QLabel("")
        self.thinking_label.setStyleSheet(
            f"color: {Config.COLORS['primary']}; font-style: italic; "
            f"background: transparent; padding: 2px 4px;"
        )
        self.thinking_label.setVisible(False)
        layout.addWidget(self.thinking_label)

        # ── Quick actions ──
        quick_frame = QFrame()
        quick_layout = QHBoxLayout(quick_frame)
        quick_layout.setContentsMargins(2, 2, 2, 2)

        self.explain_btn = QPushButton("💡 Explain Selected Packet")
        self.explain_btn.clicked.connect(self._on_explain_clicked)
        quick_layout.addWidget(self.explain_btn)

        self.follow_btn = QPushButton("🔗 Follow Stream")
        self.follow_btn.clicked.connect(self._on_follow_stream_clicked)
        quick_layout.addWidget(self.follow_btn)

        self.suspicious_btn = QPushButton("⚠ Check Suspicious")
        self.suspicious_btn.clicked.connect(
            lambda: self._send_prefilled("Is this traffic suspicious? Analyze for anomalies.")
        )
        quick_layout.addWidget(self.suspicious_btn)

        layout.addWidget(quick_frame)

        # ── Input bar ──
        input_layout = QHBoxLayout()

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Ask about the selected packet…")
        self.input_field.returnPressed.connect(self.send_query)
        input_layout.addWidget(self.input_field)

        self.send_btn = QPushButton("Ask")
        self.send_btn.clicked.connect(self.send_query)
        input_layout.addWidget(self.send_btn)

        layout.addLayout(input_layout)

        # Welcome message
        self._append_bubble(
            "AI Assistant",
            "Hello! Select a packet and ask me anything, or click a quick action above.\n"
            "Set up your API key via ⚙ for full LLM-powered analysis.",
            is_user=False,
        )

    def setup_style(self):
        """Apply dark cyber theme styling."""
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {Config.COLORS['surface']};
                color: {Config.COLORS['text_primary']};
                font-family: Consolas, 'Courier New', monospace;
            }}
            QFrame {{
                background-color: {Config.COLORS['surface_light']};
                border: 1px solid {Config.COLORS['border']};
                border-radius: 5px;
            }}
            QLineEdit {{
                background-color: {Config.COLORS['surface_light']};
                border: 1px solid {Config.COLORS['border']};
                color: {Config.COLORS['text_primary']};
                padding: 6px;
                font-size: 9pt;
            }}
            QPushButton {{
                background-color: {Config.COLORS['primary']};
                color: {Config.COLORS['surface']};
                border: none;
                padding: 5px 10px;
                font-weight: bold;
                font-size: 8pt;
            }}
            QPushButton:hover {{
                background-color: {Config.COLORS['secondary']};
            }}
            QPushButton:pressed {{
                background-color: {Config.COLORS['accent']};
            }}
        """)

    # ── Public API ────────────────────────────────────────────────────────

    def set_packet_context(self, packet_info: PacketInfo,
                           protocol_layers: List[ProtocolLayer]):
        """Called by MainWindow when a packet is selected."""
        self.current_packet = packet_info
        self.current_layers = protocol_layers

    def set_all_packets(self, packets: List[PacketInfo]):
        """Store reference to the full captured packets list."""
        self.all_packets = packets

    # ── Chat actions ──────────────────────────────────────────────────────

    def send_query(self):
        """Send the user's typed query to the AI."""
        query = self.input_field.text().strip()
        if not query:
            return
        self.input_field.clear()
        self._do_send(query)

    def _send_prefilled(self, text: str):
        """Send a pre-built query (from quick-action buttons)."""
        self._do_send(text)

    def _on_explain_clicked(self):
        if not self.current_packet:
            self._append_bubble("System", "⚠ No packet selected. Click a row in the packet list first.", False)
            return
        pkt = self.current_packet
        context_lines = [
            f"Protocol: {pkt.protocol.upper()}",
            f"Source: {pkt.src_ip}" + (f":{pkt.src_port}" if pkt.src_port else ""),
            f"Destination: {pkt.dst_ip}" + (f":{pkt.dst_port}" if pkt.dst_port else ""),
            f"Length: {pkt.length} bytes",
        ]
        if pkt.flags:
            context_lines.append(f"TCP Flags: {pkt.flags}")
        if pkt.raw_data:
            hex_preview = pkt.raw_data[:64].hex(" ")
            context_lines.append(f"Hex (first 64 bytes): {hex_preview}")
        prompt = "Explain this packet in detail:\n" + "\n".join(context_lines)
        self._do_send(prompt)

    def _on_follow_stream_clicked(self):
        if not self.current_packet:
            self._append_bubble("System", "⚠ No packet selected.", False)
            return
        pkt = self.current_packet
        if not pkt.src_ip or not pkt.dst_ip:
            self._append_bubble("System", "⚠ Selected packet has no IP info for stream following.", False)
            return

        # Collect matching packets
        stream_pkts = []
        for p in self.all_packets:
            if self._same_stream(pkt, p):
                stream_pkts.append(p)

        if len(stream_pkts) <= 1:
            self._append_bubble("System", "Only 1 packet matches this stream. Need more captured data.", False)
            return

        # Build context
        lines = [f"Follow and summarize the full stream of this connection."]
        lines.append(f"Stream: {pkt.src_ip}:{pkt.src_port} ↔ {pkt.dst_ip}:{pkt.dst_port}")
        lines.append(f"Total packets in stream: {len(stream_pkts)}\n")

        for i, sp in enumerate(stream_pkts[:50]):  # Limit to 50 packets
            direction = "→" if sp.src_ip == pkt.src_ip else "←"
            line = (f"[{i+1}] {direction} {sp.src_ip}:{sp.src_port} → "
                    f"{sp.dst_ip}:{sp.dst_port} | {sp.protocol.upper()} "
                    f"| {sp.length}B")
            if sp.flags:
                line += f" | Flags: {sp.flags}"
            lines.append(line)

        self._do_send("\n".join(lines))

    @staticmethod
    def _same_stream(a: PacketInfo, b: PacketInfo) -> bool:
        """Check if two packets belong to the same TCP/UDP stream."""
        if not all([a.src_ip, a.dst_ip, b.src_ip, b.dst_ip]):
            return False
        ips_a = frozenset([a.src_ip, a.dst_ip])
        ips_b = frozenset([b.src_ip, b.dst_ip])
        if ips_a != ips_b:
            return False
        ports_a = frozenset([a.src_port, a.dst_port])
        ports_b = frozenset([b.src_port, b.dst_port])
        return ports_a == ports_b

    def _do_send(self, query: str):
        """Core send logic — adds user bubble, starts AI worker."""
        self._append_bubble("You", query, is_user=True)
        self._show_thinking(True)

        context = {
            "copilot": self._copilot,
            "packet_info": self.current_packet,
            "protocol_layers": self.current_layers,
        }

        self.ai_thread = AIWorkerThread(query, context)
        self.ai_thread.response_ready.connect(self._on_response)
        self.ai_thread.error_occurred.connect(self._on_error)
        self.ai_thread.start()

    def _on_response(self, text: str):
        self._show_thinking(False)
        self._append_bubble("AI Assistant", text, is_user=False)

    def _on_error(self, error: str):
        self._show_thinking(False)
        self._append_bubble("System", f"❌ Error: {error}", is_user=False)

    # ── Settings ──────────────────────────────────────────────────────────

    def open_settings(self):
        dlg = AISettingsDialog(
            self,
            current_provider=self._provider_name,
            current_model=self._model_name,
            current_key=self._api_key,
        )
        if dlg.exec() == QDialog.Accepted:
            settings = dlg.get_settings()
            self._provider_name = settings["provider"]
            self._model_name = settings["model"]
            self._api_key = settings["api_key"]
            self._save_settings()
            self._apply_key_to_copilot()
            self._update_provider_label()
            self._append_bubble(
                "System",
                f"Settings updated — Provider: {self._provider_name.title()}, "
                f"Model: {self._model_name}",
                is_user=False,
            )

    def _update_provider_label(self):
        if self._copilot:
            name = self._copilot.active_provider_name
            self.provider_label.setText(f"Provider: {name}")
        else:
            self.provider_label.setText("Provider: not configured")

    # ── UI helpers ────────────────────────────────────────────────────────

    def _append_bubble(self, sender: str, message: str, is_user: bool):
        html = _make_bubble_html(sender, message, is_user)
        cursor = self.chat_area.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(html + "<br>")
        self.chat_area.ensureCursorVisible()

    def _show_thinking(self, show: bool):
        if show:
            self.thinking_label.setText("⏳ Thinking…")
            self.thinking_label.setVisible(True)
            self.send_btn.setEnabled(False)
        else:
            self.thinking_label.setVisible(False)
            self.send_btn.setEnabled(True)

    def clear_conversation(self):
        """Clear the conversation."""
        self.chat_area.clear()
        self._append_bubble(
            "AI Assistant",
            "Conversation cleared. Select a packet and ask away!",
            is_user=False,
        )

    def closeEvent(self, event):
        if self.ai_thread and self.ai_thread.isRunning():
            self.ai_thread.terminate()
            self.ai_thread.wait()
        event.accept()
