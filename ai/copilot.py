"""
AI Copilot Engine for CyberOctet
Intelligent packet analysis and security insights.

Provider architecture:
- LLMProvider (ABC)       – abstract interface all providers implement
- OpenAIAssistant          – calls OpenAI ChatCompletion (needs OPENAI_API_KEY env var)
- StaticRulesProvider      – local rule-based analysis, always available (fallback)
- AICopilot                – facade that delegates to the active provider
"""

import json
import os
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from core.config import Config
from core.capture_engine import PacketInfo
from core.protocol_decoder.decoder import ProtocolLayer

log = logging.getLogger(__name__)


# ───────────────────────────────────────────────────────────────────────────
# LLM Provider Interface
# ───────────────────────────────────────────────────────────────────────────

class LLMProvider(ABC):
    """Abstract interface for all language-model backends.

    AICopilot delegates to whichever provider is currently active.  Any
    new backend (Gemini, Anthropic, local Ollama, …) just needs to
    implement this three-method contract.
    """

    @abstractmethod
    def complete(self, system_prompt: str, user_message: str) -> Optional[str]:
        """Generate a completion.  Return None on failure so the caller can
        fall back to the next provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name, shown in the UI status bar."""

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Return True when the provider can accept requests right now."""


# ───────────────────────────────────────────────────────────────────────────
# OpenAI Backend
# ───────────────────────────────────────────────────────────────────────────

class OpenAIAssistant(LLMProvider):
    """OpenAI ChatCompletion backend.

    Reads the API key from the ``OPENAI_API_KEY`` environment variable.
    Falls back gracefully (returns None) on network errors or if the
    ``openai`` package is not installed.

    Args:
        model:       OpenAI model to use (default: 'gpt-4o-mini').
        max_tokens:  Maximum tokens in the completion response.
        temperature: Sampling temperature (0 = deterministic).
    """

    _SYSTEM_PREFIX = (
        "You are CyberOctet's AI security analyst. The user is a network "
        "engineer or security professional looking at live packet captures. "
        "Be concise, technical, and helpful. Use markdown formatting."
    )

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        max_tokens: int = 800,
        temperature: float = 0.3,
    ):
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._api_key = os.environ.get("OPENAI_API_KEY", "")
        self._client = None
        self._init_client()

    def _init_client(self):
        """Lazily initialise the openai client."""
        if not self._api_key:
            return
        try:
            import openai  # noqa: F401
            self._client = openai.OpenAI(api_key=self._api_key)
            log.debug("OpenAIAssistant: client initialised (model=%s)", self._model)
        except ImportError:
            log.warning(
                "OpenAIAssistant: 'openai' package not installed. "
                "Install with: pip install openai>=1.0.0"
            )
        except Exception as exc:
            log.warning("OpenAIAssistant: failed to create client: %s", exc)

    @property
    def name(self) -> str:
        return f"OpenAI ({self._model})"

    @property
    def is_available(self) -> bool:
        return bool(self._api_key and self._client is not None)

    def complete(self, system_prompt: str, user_message: str) -> Optional[str]:
        """Call OpenAI ChatCompletion and return the response text, or None."""
        if not self.is_available:
            return None
        full_system = f"{self._SYSTEM_PREFIX}\n\n{system_prompt}"
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": full_system},
                    {"role": "user",   "content": user_message},
                ],
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )
            return response.choices[0].message.content
        except Exception as exc:
            log.warning("OpenAIAssistant: completion error: %s", exc)
            return None


# ───────────────────────────────────────────────────────────────────────────
# Static-Rules Fallback
# ───────────────────────────────────────────────────────────────────────────

class StaticRulesProvider(LLMProvider):
    """Local rule-based analysis engine – no API key, always available.

    This wraps the original knowledge-base logic so it satisfies the
    LLMProvider interface and can act as a guaranteed fallback when no
    LLM backend is configured.
    """

    @property
    def name(self) -> str:
        return "Static Rules (offline)"

    @property
    def is_available(self) -> bool:
        return True

    def complete(self, system_prompt: str, user_message: str) -> Optional[str]:
        """Return a canned expert response based on the query keywords.

        The actual full logic lives inside AICopilot._run_static_rules();
        this method is called indirectly via AICopilot.analyze_packet().
        We return a sentinel here so the copilot knows to switch to the
        internal path.
        """
        # The copilot checks isinstance(provider, StaticRulesProvider) and
        # calls _run_static_rules() directly, so this method is a no-op path.
        return None


# ───────────────────────────────────────────────────────────────────────────
# Response data-class
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class AIResponse:
    """AI response structure"""
    query: str
    response: str
    confidence: float
    timestamp: float
    context_used: List[str]
    provider_name: str = "unknown"


class AICopilot:
    """AI Copilot facade – delegates analysis to the active LLMProvider.

    Provider selection at startup:
    1. Try OpenAIAssistant (needs OPENAI_API_KEY env var + openai package)
    2. Fall back to StaticRulesProvider (always available, no internet needed)

    Call configure_provider() at any time to switch providers.
    """

    def __init__(self, provider: Optional[LLMProvider] = None):
        # Select provider
        if provider is not None:
            self._provider = provider
        else:
            openai_p = OpenAIAssistant()
            if openai_p.is_available:
                self._provider: LLMProvider = openai_p
                log.info("AICopilot: using %s", openai_p.name)
            else:
                self._provider = StaticRulesProvider()
                log.info("AICopilot: falling back to StaticRulesProvider")

        self.conversation_history: List[AIResponse] = []
        self.max_history = 100

        # Knowledge base (used by StaticRulesProvider path)
        self.protocol_knowledge  = self._load_protocol_knowledge()
        self.security_patterns   = self._load_security_patterns()
        self.analysis_templates  = self._load_analysis_templates()

        # Statistics
        self.total_queries  = 0
        self.response_times: List[float] = []

    def configure_provider(self, provider: LLMProvider) -> None:
        """Switch to a different LLMProvider at runtime."""
        self._provider = provider
        log.info("AICopilot: provider switched to %s", provider.name)

    @property
    def active_provider_name(self) -> str:
        """Name of the currently active provider (for UI status bar)."""
        return self._provider.name
    
    def _load_protocol_knowledge(self) -> Dict:
        """Load protocol knowledge base"""
        return {
            'tcp': {
                'description': 'Transmission Control Protocol - Reliable, connection-oriented transport',
                'characteristics': ['Three-way handshake', 'Sequence numbers', 'Flow control', 'Reliable delivery'],
                'common_ports': [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
                'security_considerations': ['SYN floods', 'Port scanning', 'Connection hijacking'],
                'analysis_tips': ['Check TCP flags for connection state', 'Monitor sequence numbers', 'Watch for unusual port combinations']
            },
            'udp': {
                'description': 'User Datagram Protocol - Fast, connectionless transport',
                'characteristics': ['No connection setup', 'Best-effort delivery', 'Low overhead', 'No flow control'],
                'common_ports': [53, 67, 68, 69, 123, 161, 162, 500, 514, 520],
                'security_considerations': ['UDP floods', 'Amplification attacks', 'DNS reflection'],
                'analysis_tips': ['Monitor packet sizes', 'Check for unusual port usage', 'Watch for amplification patterns']
            },
            'icmp': {
                'description': 'Internet Control Message Protocol - Network diagnostics and error reporting',
                'characteristics': ['Error reporting', 'Network diagnostics', 'No ports', 'Control messages'],
                'common_types': [0, 3, 4, 5, 8, 11, 12],
                'security_considerations': ['ICMP tunnels', 'Smurf attacks', 'Network reconnaissance'],
                'analysis_tips': ['Check ICMP types and codes', 'Monitor ping sweeps', 'Watch for covert channels']
            },
            'dns': {
                'description': 'Domain Name System - Translates domain names to IP addresses',
                'characteristics': ['UDP/TCP transport', 'Hierarchical naming', 'Caching', 'Record types'],
                'common_ports': [53],
                'security_considerations': ['DNS amplification', 'Cache poisoning', 'DNS tunneling'],
                'analysis_tips': ['Monitor query patterns', 'Check for unusual domains', 'Watch for DNS tunneling']
            },
            'http': {
                'description': 'Hypertext Transfer Protocol - Web communication',
                'characteristics': ['TCP transport', 'Request/response model', 'Stateless', 'Headers and body'],
                'common_ports': [80, 8080, 8000, 3000],
                'security_considerations': ['SQL injection', 'XSS attacks', 'Data exfiltration'],
                'analysis_tips': ['Check HTTP methods', 'Monitor headers', 'Watch for unusual user agents']
            },
            'https': {
                'description': 'HTTP Secure - Encrypted web communication',
                'characteristics': ['TLS encryption', 'Certificate validation', 'TCP transport', 'Encrypted payload'],
                'common_ports': [443, 8443],
                'security_considerations': ['Certificate issues', 'TLS vulnerabilities', 'Man-in-the-middle'],
                'analysis_tips': ['Check TLS versions', 'Monitor certificate chains', 'Watch for cipher suite issues']
            }
        }
    
    def _load_security_patterns(self) -> Dict:
        """Load security pattern knowledge"""
        return {
            'port_scan': {
                'indicators': ['SYN packets to multiple ports', 'RST responses', 'Sequential port scanning'],
                'description': 'Systematic scanning of network ports to discover services',
                'severity': 'medium',
                'mitigation': ['Firewall rules', 'Port knocking', 'Intrusion detection']
            },
            'syn_flood': {
                'indicators': ['High volume of SYN packets', 'No ACK responses', 'Targeted ports'],
                'description': 'Overwhelming target with SYN packets to exhaust resources',
                'severity': 'critical',
                'mitigation': ['SYN cookies', 'Rate limiting', 'Connection throttling']
            },
            'dns_amplification': {
                'indicators': ['Small DNS queries', 'Large DNS responses', 'Spoofed source IPs'],
                'description': 'Using DNS servers to amplify traffic to a target',
                'severity': 'high',
                'mitigation': ['DNS response rate limiting', 'BCP 38', 'Traffic filtering']
            },
            'data_exfiltration': {
                'indicators': ['Unusual outbound traffic', 'Large data transfers', 'Encrypted tunnels'],
                'description': 'Unauthorized transfer of sensitive data',
                'severity': 'high',
                'mitigation': ['Data loss prevention', 'Traffic monitoring', 'Encryption policies']
            }
        }
    
    def _load_analysis_templates(self) -> Dict:
        """Load analysis response templates"""
        return {
            'packet_explanation': """
📦 **Packet Analysis**

**Basic Information:**
- Source: {src}
- Destination: {dst}
- Protocol: {protocol}
- Size: {size} bytes
- Timestamp: {timestamp}

**Protocol Details:**
{protocol_details}

**Security Analysis:**
{security_analysis}
""",
            'protocol_explanation': """
🔗 **{protocol} Protocol Analysis**

**Description:**
{description}

**Key Characteristics:**
{characteristics}

**Common Usage:**
{common_usage}

**Security Considerations:**
{security_considerations}

**Analysis Tips:**
{analysis_tips}
""",
            'security_assessment': """
🔍 **Security Assessment**

**Threat Level:** {threat_level}

**Identified Patterns:**
{patterns}

**Recommendations:**
{recommendations}

**Immediate Actions:**
{immediate_actions}
"""
        }
    
    def analyze_packet(
        self,
        packet_info: PacketInfo,
        protocol_layers: List[ProtocolLayer],
        query: str,
    ) -> AIResponse:
        """Analyse a packet and generate a response via the active provider."""
        start_time = time.time()
        self.total_queries += 1

        # Build structured prompt for LLM backends
        context = self._build_packet_context(packet_info, protocol_layers)
        system  = (
            "You are an expert network analyst and packet forensics assistant "
            "embedded in a packet capture tool. The user will provide raw packet "
            "data, decoded fields, or ask questions about network traffic. "
            "Your job is to: "
            "1. Clearly explain what the packet is doing in plain language. "
            "2. Identify the protocol stack (e.g., Ethernet > IP > TCP > HTTP). "
            "3. Flag any anomalies, suspicious patterns, or security concerns. "
            "4. When asked to 'follow the stream', reconstruct and summarize "
            "the application-layer conversation. "
            "5. Answer technical questions about packet fields, flags, checksums, "
            "and protocol behavior. "
            "Be concise but thorough. Use bullet points for multi-part explanations."
        )
        user_msg = f"Packet context:\n{context}\n\nUser question: {query}"

        response_text: Optional[str] = None
        provider_name = self._provider.name

        # Attempt LLM completion (if provider is not static-rules)
        if not isinstance(self._provider, StaticRulesProvider):
            response_text = self._provider.complete(system, user_msg)
            if response_text is None:
                # provider failed – log and use static rules
                log.warning(
                    "AICopilot: %s returned None, falling back to static rules",
                    self._provider.name,
                )
                provider_name = "Static Rules (fallback)"

        # Use static rules if LLM path didn't produce a result
        if response_text is None:
            response_text = self._run_static_rules(packet_info, protocol_layers, query)

        response_time = time.time() - start_time
        self.response_times.append(response_time)

        ai_response = AIResponse(
            query=query,
            response=response_text,
            confidence=self._calculate_confidence(packet_info, protocol_layers, query),
            timestamp=time.time(),
            context_used=["packet_info", "protocol_layers", "protocol_knowledge"],
            provider_name=provider_name,
        )

        self.conversation_history.append(ai_response)
        if len(self.conversation_history) > self.max_history:
            self.conversation_history.pop(0)

        return ai_response

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _build_packet_context(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer]) -> str:
        """Build a structured plain-text context block to pass to an LLM."""
        parts = [
            f"Protocol: {packet_info.protocol.upper()}",
            f"Source: {packet_info.src_ip}" + (f":{packet_info.src_port}" if packet_info.src_port else ""),
            f"Destination: {packet_info.dst_ip}" + (f":{packet_info.dst_port}" if packet_info.dst_port else ""),
            f"Length: {packet_info.length} bytes",
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet_info.timestamp))}",
        ]
        if packet_info.flags:
            parts.append(f"TCP Flags: {packet_info.flags}")
        if packet_info.seq_num is not None:
            parts.append(f"Seq: {packet_info.seq_num}  Ack: {packet_info.ack_num}")
        if protocol_layers:
            layer_names = ", ".join(l.name for l in protocol_layers)
            parts.append(f"Protocol layers: {layer_names}")
        return "\n".join(parts)

    def _run_static_rules(
        self,
        packet_info: PacketInfo,
        protocol_layers: List[ProtocolLayer],
        query: str,
    ) -> str:
        """Route the query to the appropriate static-rule handler."""
        query_lower = query.lower()
        if 'explain' in query_lower and 'packet' in query_lower:
            return self._explain_packet(packet_info, protocol_layers)
        elif 'protocol' in query_lower:
            return self._explain_protocol(packet_info, protocol_layers)
        elif 'security' in query_lower or 'suspicious' in query_lower:
            return self._security_assessment(packet_info, protocol_layers)
        elif 'filter' in query_lower:
            return self._suggest_filters(packet_info, protocol_layers)
        elif 'tcp' in query_lower and 'handshake' in query_lower:
            return self._explain_tcp_handshake(packet_info, protocol_layers)
        else:
            return self._general_analysis(packet_info, protocol_layers, query)
    
    def _explain_packet(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer]) -> str:
        """Generate detailed packet explanation"""
        src = f"{packet_info.src_ip}{f':{packet_info.src_port}' if packet_info.src_port else ''}"
        dst = f"{packet_info.dst_ip}{f':{packet_info.dst_port}' if packet_info.dst_port else ''}"
        
        # Build protocol details
        protocol_details = []
        for layer in protocol_layers:
            protocol_details.append(f"- **{layer.name}**: {layer.description}")
        
        # Security analysis
        security_analysis = self._analyze_packet_security(packet_info, protocol_layers)
        
        return self.analysis_templates['packet_explanation'].format(
            src=src,
            dst=dst,
            protocol=packet_info.protocol.upper(),
            size=packet_info.length,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet_info.timestamp)),
            protocol_details='\n'.join(protocol_details),
            security_analysis=security_analysis
        )
    
    def _explain_protocol(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer]) -> str:
        """Generate protocol explanation"""
        protocol = packet_info.protocol.lower()
        
        if protocol in self.protocol_knowledge:
            knowledge = self.protocol_knowledge[protocol]
            
            characteristics = '\n'.join([f"- {char}" for char in knowledge['characteristics']])
            common_usage = f"Common ports: {', '.join(map(str, knowledge['common_ports']))}"
            security_considerations = '\n'.join([f"- {sec}" for sec in knowledge['security_considerations']])
            analysis_tips = '\n'.join([f"- {tip}" for tip in knowledge['analysis_tips']])
            
            return self.analysis_templates['protocol_explanation'].format(
                protocol=protocol.upper(),
                description=knowledge['description'],
                characteristics=characteristics,
                common_usage=common_usage,
                security_considerations=security_considerations,
                analysis_tips=analysis_tips
            )
        else:
            return f"Protocol {packet_info.protocol.upper()} is not in my knowledge base."
    
    def _security_assessment(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer]) -> str:
        """Generate security assessment"""
        threats = []
        patterns = []
        recommendations = []
        immediate_actions = []
        
        # Analyze for security patterns
        if packet_info.protocol == 'tcp' and packet_info.flags:
            if 'SYN' in packet_info.flags and 'ACK' not in packet_info.flags:
                patterns.append("SYN packet without ACK (potential port scan)")
                recommendations.append("Monitor for additional SYN packets to same target")
                immediate_actions.append("Check if source IP is whitelisted")
        
        # Check for suspicious ports
        suspicious_ports = [1337, 31337, 12345, 54321]
        if packet_info.src_port in suspicious_ports or packet_info.dst_port in suspicious_ports:
            patterns.append(f"Traffic to/from suspicious port {packet_info.src_port or packet_info.dst_port}")
            recommendations.append("Investigate the application using this port")
            immediate_actions.append("Consider blocking the port if unauthorized")
        
        # Determine threat level
        threat_level = "Low"
        if len(patterns) > 2:
            threat_level = "Medium"
        if len(patterns) > 4:
            threat_level = "High"
        if "critical" in str(patterns).lower():
            threat_level = "Critical"
        
        if not patterns:
            patterns.append("No obvious security threats detected")
            recommendations.append("Continue monitoring")
            immediate_actions.append("No immediate action required")
        
        patterns_text = '\n'.join([f"- {pattern}" for pattern in patterns])
        recommendations_text = '\n'.join([f"- {rec}" for rec in recommendations])
        immediate_actions_text = '\n'.join([f"- {action}" for action in immediate_actions])
        
        return self.analysis_templates['security_assessment'].format(
            threat_level=threat_level,
            patterns=patterns_text,
            recommendations=recommendations_text,
            immediate_actions=immediate_actions_text
        )
    
    def _suggest_filters(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer]) -> str:
        """Suggest useful filters for this packet"""
        filters = []
        
        # Basic protocol filter
        filters.append(f"Protocol: `{packet_info.protocol}`")
        
        # IP filters
        if packet_info.src_ip:
            filters.append(f"Source IP: `src host {packet_info.src_ip}`")
        if packet_info.dst_ip:
            filters.append(f"Destination IP: `dst host {packet_info.dst_ip}`")
        
        # Port filters
        if packet_info.src_port:
            filters.append(f"Source Port: `src port {packet_info.src_port}`")
        if packet_info.dst_port:
            filters.append(f"Destination Port: `dst port {packet_info.dst_port}`")
        
        # Combined filters
        if packet_info.src_ip and packet_info.dst_ip:
            filters.append(f"Conversation: `host {packet_info.src_ip} and host {packet_info.dst_ip}`")
        
        # TCP specific filters
        if packet_info.protocol == 'tcp' and packet_info.flags:
            if 'SYN' in packet_info.flags:
                filters.append("TCP SYN: `tcp[tcpflags] & tcp-syn != 0`")
        
        filter_text = "🔍 **Suggested Filters**\n\n"
        for i, filter_suggestion in enumerate(filters, 1):
            filter_text += f"{i}. {filter_suggestion}\n"
        
        filter_text += "\n**Filter Tips:**\n"
        filter_text += "- Use `and`/`or` to combine conditions\n"
        filter_text += "- Use `not` to exclude traffic\n"
        filter_text += "- Port ranges: `port 80-443`\n"
        filter_text += "- Networks: `net 192.168.1.0/24`"
        
        return filter_text
    
    def _explain_tcp_handshake(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer]) -> str:
        """Explain TCP handshake process"""
        if packet_info.protocol != 'tcp':
            return "This is not a TCP packet, so no TCP handshake analysis applies."
        
        handshake_info = "🤝 **TCP Handshake Analysis**\n\n"
        handshake_info += "**Three-Way Handshake Process:**\n\n"
        handshake_info += "1. **SYN** (Client → Server)\n"
        handshake_info += "   - Client sends SYN with initial sequence number\n"
        handshake_info += "   - Flags: SYN=1, ACK=0\n\n"
        handshake_info += "2. **SYN-ACK** (Server → Client)\n"
        handshake_info += "   - Server responds with SYN+ACK\n"
        handshake_info += "   - Flags: SYN=1, ACK=1\n\n"
        handshake_info += "3. **ACK** (Client → Server)\n"
        handshake_info += "   - Client acknowledges server's response\n"
        handshake_info += "   - Flags: SYN=0, ACK=1\n\n"
        handshake_info += "**Current Packet Analysis:**\n"
        
        if packet_info.flags:
            if 'SYN' in packet_info.flags and 'ACK' not in packet_info.flags:
                handshake_info += "→ This is Step 1: SYN packet (connection initiation)"
                if packet_info.seq_num:
                    handshake_info += f"\n  Initial Sequence Number: {packet_info.seq_num}"
            elif 'SYN' in packet_info.flags and 'ACK' in packet_info.flags:
                handshake_info += "→ This is Step 2: SYN-ACK packet (server response)"
                if packet_info.ack_num:
                    handshake_info += f"\n  Acknowledging: {packet_info.ack_num}"
            elif 'ACK' in packet_info.flags and 'SYN' not in packet_info.flags:
                handshake_info += "→ This is Step 3: ACK packet (handshake completion)"
            else:
                handshake_info += f"→ TCP Flags: {packet_info.flags}"
        else:
            handshake_info += "→ No TCP flags information available"
        
        return handshake_info
    
    def _general_analysis(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer], query: str) -> str:
        """Generate general analysis response"""
        return f"""📊 **General Packet Analysis**

**Query:** {query}

**Summary:**
This is a {packet_info.protocol.upper()} packet from {packet_info.src_ip} to {packet_info.dst_ip}.

**Key Information:**
- Protocol: {packet_info.protocol.upper()}
- Size: {packet_info.length} bytes
- Source: {packet_info.src_ip}{f':{packet_info.src_port}' if packet_info.src_port else ''}
- Destination: {packet_info.dst_ip}{f':{packet_info.dst_port}' if packet_info.dst_port else ''}

**Protocol Stack:**
{chr(10).join([f"- {layer.name}" for layer in protocol_layers])}

Would you like me to explain any specific aspect of this packet in more detail?
"""
    
    def _analyze_packet_security(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer]) -> str:
        """Analyze security aspects of the packet"""
        security_points = []
        
        # Check for suspicious indicators
        if packet_info.protocol == 'tcp' and packet_info.flags:
            if 'SYN' in packet_info.flags and 'ACK' not in packet_info.flags:
                security_points.append("• SYN-only packet (potential port scan)")
        
        # Check port usage
        suspicious_ports = [1337, 31337, 12345, 54321]
        if packet_info.src_port in suspicious_ports or packet_info.dst_port in suspicious_ports:
            security_points.append(f"• Suspicious port usage: {packet_info.src_port or packet_info.dst_port}")
        
        # Check packet size
        if packet_info.length < 20:
            security_points.append("• Unusually small packet")
        elif packet_info.length > 1500:
            security_points.append("• Oversized packet (possible fragmentation)")
        
        if not security_points:
            security_points.append("• No obvious security concerns detected")
        
        return '\n'.join(security_points)
    
    def _calculate_confidence(self, packet_info: PacketInfo, protocol_layers: List[ProtocolLayer], query: str) -> float:
        """Calculate confidence score for the response"""
        base_confidence = 0.8
        
        # Adjust based on protocol knowledge
        if packet_info.protocol.lower() in self.protocol_knowledge:
            base_confidence += 0.1
        
        # Adjust based on data completeness
        if packet_info.src_ip and packet_info.dst_ip:
            base_confidence += 0.05
        
        if packet_info.src_port and packet_info.dst_port:
            base_confidence += 0.05
        
        # Adjust based on query specificity
        if any(keyword in query.lower() for keyword in ['explain', 'protocol', 'security']):
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)
    
    def get_statistics(self) -> Dict:
        """Get AI copilot statistics"""
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        
        return {
            'total_queries': self.total_queries,
            'conversation_history_size': len(self.conversation_history),
            'average_response_time': avg_response_time,
            'protocols_in_knowledge_base': len(self.protocol_knowledge),
            'security_patterns': len(self.security_patterns)
        }
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history.clear()
        self.total_queries = 0
        self.response_times.clear()
