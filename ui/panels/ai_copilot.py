"""
AI Assistant Panel for CyberOctet
Chat-style interface with BYOK (Bring Your Own Key) support.

Supported providers:
  1. GPT (OpenAI)     — api.openai.com
  2. Claude (Anthropic) — api.anthropic.com
  3. Gemini (Google)  — generativelanguage.googleapis.com
  4. Groq (Free)      — api.groq.com  (OpenAI-compatible)
  5. Ollama (Local)   — localhost:11434  (no key required)
"""

import html as _html
import json
import os
import re
import urllib.error
import urllib.request
from typing import List, Optional, Dict, Any

from PySide6.QtCore import Qt, Signal, QThread, QSize
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QFrame, QComboBox,
)

from core.config import Config
from core.capture_engine import PacketInfo
from core.protocol_decoder.decoder import ProtocolDecoder, ProtocolLayer


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a network security expert assistant embedded inside a packet analyzer "
    "tool similar to Wireshark. Help the user understand captured network traffic, "
    "protocols, anomalies, and potential security issues. Be concise, technical, and precise."
)

# Provider registry: internal_id → (display label, needs_key, default_model)
_PROVIDERS = [
    ("openai",    "GPT (OpenAI)",      True,  "gpt-4o"),
    ("anthropic", "Claude (Anthropic)", True,  "claude-opus-4-5"),
    ("gemini",    "Gemini (Google)",   True,  "gemini-2.0-flash"),
    ("groq", "Groq (Free)", True, "llama-3.3-70b-versatile"),
    ("ollama",    "Ollama (Local)",    False, "llama3"),
]

_OPENAI_URL      = "https://api.openai.com/v1/chat/completions"
_ANTHROPIC_URL   = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VER   = "2023-06-01"
_GROQ_URL        = "https://api.groq.com/openai/v1/chat/completions"
_OLLAMA_URL      = "http://localhost:11434/api/chat"


# ─────────────────────────────────────────────────────────────────────────────
# Background AI worker thread
# ─────────────────────────────────────────────────────────────────────────────

class AIWorkerThread(QThread):
    """Runs the API call in a background thread so the UI stays responsive."""

    response_ready = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, messages: List[Dict], provider: str, api_key: str, parent=None):
        super().__init__(parent)
        self.messages = messages   # list of {"role": ..., "content": ...}
        self.provider = provider   # one of the provider ids above
        self.api_key  = api_key

    # ── HTTP helper ───────────────────────────────────────────────────────────

    @staticmethod
    def _http_post(url: str, headers: Dict, body: Dict) -> Dict:
        data = json.dumps(body).encode("utf-8")
        req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    # ── Provider-specific callers ─────────────────────────────────────────────

    def _call_openai(self) -> str:
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        body = {
            "model":    "gpt-4o",
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + self.messages,
        }
        result = self._http_post(_OPENAI_URL, headers, body)
        return result["choices"][0]["message"]["content"]

    def _call_anthropic(self) -> str:
        headers = {
            "Content-Type":      "application/json",
            "x-api-key":         self.api_key,
            "anthropic-version": _ANTHROPIC_VER,
        }
        body = {
            "model":      "claude-opus-4-5",
            "max_tokens": 1024,
            "system":     SYSTEM_PROMPT,
            "messages":   self.messages,
        }
        result = self._http_post(_ANTHROPIC_URL, headers, body)
        return result["content"][0]["text"]

    def _call_gemini(self) -> str:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.0-flash:generateContent?key={self.api_key}"
        )
        # Build a single user turn that includes all history
        # Gemini v1beta expects alternating user/model roles
        contents = []
        for msg in self.messages:
            role = "model" if msg["role"] == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})
        body = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": contents,
        }
        # No Authorization header — key is in the URL
        headers = {"Content-Type": "application/json"}
        result = self._http_post(url, headers, body)
        return result["candidates"][0]["content"]["parts"][0]["text"]

    def _call_groq(self) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Ai-Packet/1.0"
        }

        body = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + self.messages,
            "max_tokens": 800,
            "temperature": 0.2
        }

        result = self._http_post(_GROQ_URL, headers, body)
        return result["choices"][0]["message"]["content"]

    def _call_ollama(self) -> str:
        body = {
            "model":    "llama3",
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + self.messages,
            "stream":   False,
        }
        headers = {"Content-Type": "application/json"}
        result = self._http_post(_OLLAMA_URL, headers, body)
        return result["message"]["content"]

    # ── run ───────────────────────────────────────────────────────────────────

    def run(self):
        provider_needs_key = next(
            (needs for pid, _, needs, _ in _PROVIDERS if pid == self.provider), True
        )
        if provider_needs_key and not self.api_key:
            self.error_occurred.emit(
                "No API key configured. Enter your key in the panel above and click Save."
            )
            return
        try:
            dispatch = {
                "openai":    self._call_openai,
                "anthropic": self._call_anthropic,
                "gemini":    self._call_gemini,
                "groq":      self._call_groq,
                "ollama":    self._call_ollama,
            }
            fn = dispatch.get(self.provider)
            if fn is None:
                self.error_occurred.emit(f"Unknown provider: {self.provider}")
                return
            text = fn()
            self.response_ready.emit(text)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode()
                detail = json.loads(body).get("error", {}).get("message", body)
            except Exception:
                detail = str(exc)
            self.error_occurred.emit(f"API error {exc.code}: {detail}")
        except Exception as exc:
            self.error_occurred.emit(str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Chat bubble helper
# ─────────────────────────────────────────────────────────────────────────────

def _make_bubble_html(sender: str, message: str, is_user: bool) -> str:
    if is_user:
        bg, align, name_color, border_color = "#0d2b45", "right", "#00aaff", "#00aaff40"
    else:
        bg, align, name_color, border_color = "#1a1a1a", "left",  "#00ff88", "#00ff8840"

    safe = _html.escape(message)
    safe = safe.replace("\n", "<br>")
    safe = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", safe)
    safe = re.sub(r"^- ", "• ", safe, flags=re.MULTILINE)

    return (
        f'<div style="text-align:{align}; margin:4px 0;">'
        f'<div style="display:inline-block; background:{bg}; border:1px solid {border_color}; '
        f'border-radius:10px; padding:8px 12px; max-width:85%; text-align:left;">'
        f'<span style="color:{name_color}; font-weight:bold; font-size:8pt;">{sender}</span><br>'
        f'<span style="color:#e0e0e0; font-family:Consolas,\'Courier New\',monospace; font-size:9pt;">'
        f'{safe}</span></div></div>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main widget
# ─────────────────────────────────────────────────────────────────────────────

class AICopilotWidget(QWidget):
    """AI Assistant tab — 5-provider BYOK panel + chat bubble interface."""

    def __init__(self):
        super().__init__()

        self.current_packet: Optional[PacketInfo]  = None
        self.current_layers: List[ProtocolLayer]   = []
        self.protocol_decoder                      = ProtocolDecoder()
        self.ai_thread: Optional[AIWorkerThread]   = None
        self.all_packets: List[PacketInfo]         = []

        # Chat history as list of {"role", "content"}
        self._chat_history: List[Dict] = []

        # Per-provider key storage  {"openai": "sk-...", "anthropic": "...", ...}
        self._keys: Dict[str, str] = {pid: "" for pid, *_ in _PROVIDERS}
        self._provider = "openai"
        self._load_settings()

        self.setup_ui()
        self.setup_style()
        self._on_provider_changed()   # sync UI to loaded settings

    # ── persistence ───────────────────────────────────────────────────────────

    def _settings_path(self) -> str:
        return os.path.join(os.path.expanduser("~"), ".cyberoctet_ai.json")

    def _load_settings(self):
        try:
            if os.path.exists(self._settings_path()):
                with open(self._settings_path()) as f:
                    data = json.load(f)
                self._provider = data.get("provider", "openai")
                # Support old single-key format and new dict format
                if "keys" in data:
                    for pid, key in data["keys"].items():
                        if pid in self._keys:
                            self._keys[pid] = key
                elif "api_key" in data:
                    old_provider = data.get("provider", "openai")
                    self._keys[old_provider] = data.get("api_key", "")
        except Exception:
            pass

    def _save_settings(self):
        try:
            with open(self._settings_path(), "w") as f:
                json.dump({"provider": self._provider, "keys": self._keys}, f)
        except Exception as exc:
            print(f"[AIAssistant] Failed to save settings: {exc}")

    # ── UI setup ──────────────────────────────────────────────────────────────

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # ── 1. BYOK panel ─────────────────────────────────────────────────────
        byok_frame = QFrame()
        byok_frame.setObjectName("byokFrame")
        byok_layout = QHBoxLayout(byok_frame)
        byok_layout.setContentsMargins(8, 6, 8, 6)
        byok_layout.setSpacing(6)

        # Provider dropdown
        self.provider_combo = QComboBox()
        for pid, label, *_ in _PROVIDERS:
            self.provider_combo.addItem(label, pid)
        idx = self.provider_combo.findData(self._provider)
        if idx >= 0:
            self.provider_combo.setCurrentIndex(idx)
        self.provider_combo.setMaximumWidth(160)
        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        byok_layout.addWidget(self.provider_combo)

        # Password-style API key field
        self.key_field = QLineEdit()
        self.key_field.setEchoMode(QLineEdit.Password)
        self.key_field.setPlaceholderText("Paste your API key here…")
        byok_layout.addWidget(self.key_field, 1)

        # "No key needed" placeholder label (shown for Ollama)
        self.no_key_label = QLabel("No key needed — Ollama must be running locally")
        self.no_key_label.setStyleSheet(
            "color: #666666; font-size: 8pt; background: transparent;"
        )
        self.no_key_label.setVisible(False)
        byok_layout.addWidget(self.no_key_label, 1)

        # Save button
        self.save_key_btn = QPushButton("Save")
        self.save_key_btn.setMaximumWidth(52)
        self.save_key_btn.clicked.connect(self._on_save_key)
        byok_layout.addWidget(self.save_key_btn)

        # Status dot
        self.key_status_label = QLabel("● No key")
        self.key_status_label.setAlignment(Qt.AlignVCenter)
        byok_layout.addWidget(self.key_status_label)

        layout.addWidget(byok_frame)

        # ── 2. Chat history ───────────────────────────────────────────────────
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
        layout.addWidget(self.chat_area, 1)

        # ── 3. Thinking indicator ─────────────────────────────────────────────
        self.thinking_label = QLabel("")
        self.thinking_label.setStyleSheet(
            f"color: {Config.COLORS['primary']}; font-style: italic; "
            f"background: transparent; padding: 2px 4px;"
        )
        self.thinking_label.setVisible(False)
        layout.addWidget(self.thinking_label)

        # ── 4. Quick action buttons ───────────────────────────────────────────
        quick_frame = QFrame()
        quick_layout = QHBoxLayout(quick_frame)
        quick_layout.setContentsMargins(2, 2, 2, 2)

        explain_btn = QPushButton("💡 Explain Packet")
        explain_btn.clicked.connect(self._on_explain_clicked)
        quick_layout.addWidget(explain_btn)

        follow_btn = QPushButton("🔗 Follow Stream")
        follow_btn.clicked.connect(self._on_follow_stream_clicked)
        quick_layout.addWidget(follow_btn)

        suspicious_btn = QPushButton("⚠ Check Suspicious")
        suspicious_btn.clicked.connect(
            lambda: self._do_send("Is this traffic suspicious? Analyze for anomalies.")
        )
        quick_layout.addWidget(suspicious_btn)

        layout.addWidget(quick_frame)

        # ── 5. Input bar ──────────────────────────────────────────────────────
        input_layout = QHBoxLayout()

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Ask about the selected packet…")
        self.input_field.returnPressed.connect(self.send_query)
        input_layout.addWidget(self.input_field)

        self.send_btn = QPushButton("Ask")
        self.send_btn.clicked.connect(self.send_query)
        input_layout.addWidget(self.send_btn)

        self.clear_btn = QPushButton("Clear Chat")
        self.clear_btn.clicked.connect(self.clear_conversation)
        input_layout.addWidget(self.clear_btn)

        layout.addLayout(input_layout)

        # Welcome message
        self._append_bubble(
            "AI Assistant",
            "Hello! Select a provider and enter your API key above, then select a packet and ask.\n"
            "Ollama (Local) works without a key if Ollama is running on port 11434.",
            is_user=False,
        )

    def setup_style(self):
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
            QFrame#byokFrame {{
                background-color: #151515;
                border: 1px solid {Config.COLORS['border']};
                border-radius: 6px;
            }}
            QLineEdit {{
                background-color: {Config.COLORS['surface_light']};
                border: 1px solid {Config.COLORS['border']};
                color: {Config.COLORS['text_primary']};
                padding: 5px;
                font-size: 9pt;
            }}
            QComboBox {{
                background-color: {Config.COLORS['surface_light']};
                border: 1px solid {Config.COLORS['border']};
                color: {Config.COLORS['text_primary']};
                padding: 4px;
                font-size: 9pt;
            }}
            QPushButton {{
                background-color: {Config.COLORS['primary']};
                color: #0a0a0a;
                border: none;
                padding: 5px 10px;
                font-weight: bold;
                font-size: 8pt;
            }}
            QPushButton:hover {{
                background-color: {Config.COLORS['secondary']};
                color: #ffffff;
            }}
            QPushButton:pressed {{
                background-color: {Config.COLORS['accent']};
                color: #ffffff;
            }}
        """)

    # ── Provider selection logic ───────────────────────────────────────────────

    def _current_provider_id(self) -> str:
        return self.provider_combo.currentData() or "openai"

    def _on_provider_changed(self):
        """Called whenever the provider dropdown changes. Syncs key field + status."""
        pid = self._current_provider_id()
        needs_key = next((nk for p, _, nk, _ in _PROVIDERS if p == pid), True)

        if needs_key:
            # Show key field + save button
            self.key_field.setVisible(True)
            self.save_key_btn.setVisible(True)
            self.no_key_label.setVisible(False)
            # Load saved key for this provider
            self.key_field.setText(self._keys.get(pid, ""))
            self._update_key_status(pid)
        else:
            # Ollama — hide key field
            self.key_field.setVisible(False)
            self.save_key_btn.setVisible(False)
            self.no_key_label.setVisible(True)
            self.key_status_label.setText("● Ready")
            self.key_status_label.setStyleSheet(
                "color: #00ff88; font-weight: bold; background: transparent;"
            )

    def _update_key_status(self, pid: str = None):
        if pid is None:
            pid = self._current_provider_id()
        if hasattr(self, "key_status_label"):
            has_key = bool(self._keys.get(pid, ""))
            if has_key:
                self.key_status_label.setText("● Connected")
                self.key_status_label.setStyleSheet(
                    "color: #00ff88; font-weight: bold; background: transparent;"
                )
            else:
                self.key_status_label.setText("● No key")
                self.key_status_label.setStyleSheet(
                    "color: #ff4444; font-weight: bold; background: transparent;"
                )

    # ── Key save ──────────────────────────────────────────────────────────────

    def _on_save_key(self):
        pid = self._current_provider_id()
        key = self.key_field.text().strip()
        self._keys[pid] = key
        self._provider = pid
        self._save_settings()
        self._update_key_status(pid)
        provider_label = self.provider_combo.currentText()
        self._append_bubble(
            "System",
            f"✓ API key saved for {provider_label}.",
            is_user=False,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def set_packet_context(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer]):
        self.current_packet = packet_info
        self.current_layers = protocol_layers

    def set_all_packets(self, packets: List[PacketInfo]):
        self.all_packets = packets

    # ── Chat actions ──────────────────────────────────────────────────────────

    def send_query(self):
        query = self.input_field.text().strip()
        if not query:
            return
        self.input_field.clear()
        self._do_send(query)

    def _on_explain_clicked(self):
        if not self.current_packet:
            self._append_bubble("System", "⚠ No packet selected. Click a row first.", False)
            return
        pkt = self.current_packet
        lines = [
            f"Protocol: {pkt.protocol.upper()}",
            f"Source: {pkt.src_ip}" + (f":{pkt.src_port}" if pkt.src_port else ""),
            f"Destination: {pkt.dst_ip}" + (f":{pkt.dst_port}" if pkt.dst_port else ""),
            f"Length: {pkt.length} bytes",
        ]
        if pkt.flags:
            lines.append(f"TCP Flags: {pkt.flags}")
        if pkt.raw_data:
            lines.append(f"Hex (first 64 bytes): {pkt.raw_data[:64].hex(' ')}")
        self._do_send("Explain this packet in detail:\n" + "\n".join(lines))

    def _on_follow_stream_clicked(self):
        if not self.current_packet:
            self._append_bubble("System", "⚠ No packet selected.", False)
            return
        pkt = self.current_packet
        if not pkt.src_ip or not pkt.dst_ip:
            self._append_bubble("System", "⚠ Packet has no IP info for stream following.", False)
            return
        stream_pkts = [p for p in self.all_packets if self._same_stream(pkt, p)]
        if len(stream_pkts) <= 1:
            self._append_bubble("System", "Only 1 packet in stream. Capture more traffic first.", False)
            return
        lines = [
            "Follow and summarize this connection stream.",
            f"Stream: {pkt.src_ip}:{pkt.src_port} ↔ {pkt.dst_ip}:{pkt.dst_port}",
            f"Total packets: {len(stream_pkts)}\n",
        ]
        for i, sp in enumerate(stream_pkts[:50]):
            direction = "→" if sp.src_ip == pkt.src_ip else "←"
            line = (f"[{i+1}] {direction} {sp.src_ip}:{sp.src_port} → "
                    f"{sp.dst_ip}:{sp.dst_port} | {sp.protocol.upper()} | {sp.length}B")
            if sp.flags:
                line += f" | Flags: {sp.flags}"
            lines.append(line)
        self._do_send("\n".join(lines))

    @staticmethod
    def _same_stream(a: PacketInfo, b: PacketInfo) -> bool:
        if not all([a.src_ip, a.dst_ip, b.src_ip, b.dst_ip]):
            return False
        return (frozenset([a.src_ip, a.dst_ip]) == frozenset([b.src_ip, b.dst_ip]) and
                frozenset([a.src_port, a.dst_port]) == frozenset([b.src_port, b.dst_port]))

    def _do_send(self, query: str):
        """Core send: prepend packet context, add user bubble, start worker."""
        # Auto-prepend selected packet context
        full_query = query
        if self.current_packet:
            pkt = self.current_packet
            sp = f":{pkt.src_port}" if pkt.src_port else ""
            dp = f":{pkt.dst_port}" if pkt.dst_port else ""
            info = getattr(pkt, "info", "") or pkt.protocol.upper()
            context_line = (
                f"Selected packet: {pkt.protocol.upper()} | "
                f"{pkt.src_ip}{sp} → {pkt.dst_ip}{dp} | {info}"
            )
            full_query = f"[Context: {context_line}]\n\n{query}"

        self._append_bubble("You", query, is_user=True)
        self._show_thinking(True)

        self._chat_history.append({"role": "user", "content": full_query})
        if len(self._chat_history) > 20:
            self._chat_history = self._chat_history[-20:]

        pid = self._current_provider_id()
        api_key = self._keys.get(pid, "")

        self.ai_thread = AIWorkerThread(list(self._chat_history), pid, api_key)
        self.ai_thread.response_ready.connect(self._on_response)
        self.ai_thread.error_occurred.connect(self._on_error)
        self.ai_thread.start()

    def _on_response(self, text: str):
        self._show_thinking(False)
        self._chat_history.append({"role": "assistant", "content": text})
        self._append_bubble("AI Assistant", text, is_user=False)

    def _on_error(self, error: str):
        self._show_thinking(False)
        self._append_bubble("System", f"❌ Error: {error}", is_user=False)

    # ── UI helpers ─────────────────────────────────────────────────────────────

    def _append_bubble(self, sender: str, message: str, is_user: bool):
        html = _make_bubble_html(sender, message, is_user)
        cursor = self.chat_area.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(html + "<br>")
        self.chat_area.ensureCursorVisible()

    def _show_thinking(self, show: bool):
        if show:
            self.thinking_label.setText("⏳ AI is thinking…")
            self.thinking_label.setVisible(True)
            self.send_btn.setEnabled(False)
            self.input_field.setEnabled(False)
        else:
            self.thinking_label.setVisible(False)
            self.send_btn.setEnabled(True)
            self.input_field.setEnabled(True)

    def clear_conversation(self):
        self._chat_history.clear()
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
