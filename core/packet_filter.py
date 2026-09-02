"""
Pure-Python Wireshark-style display filter for CyberOctet.

Runs AFTER capture on already-captured PacketInfo objects.
Supports:
  - Bare protocol names:  dns tcp udp icmp arp http
  - port 53 / src port 1234 / dst port 80
  - host 1.2.3.4 / src host 10.0.0.1 / dst host 8.8.8.8
  - ip 192.168.1.1  (same as host)
  - ip.src == 1.2.3.4 / ip.dst == 1.2.3.4
  - tcp.port == 443
  - net 192.168.0.0/24
  - not <expr>
  - <expr> and <expr>
  - <expr> or <expr>
  - (<expr>)
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple

# --------------------------------------------------------------------------- #
# PacketInfo duck-type interface (mirrors core.capture_engine.PacketInfo)
# --------------------------------------------------------------------------- #
# We do NOT import PacketInfo here to avoid a circular import; we rely on
# attribute access (duck typing) only.

# --------------------------------------------------------------------------- #
# Tokenizer
# --------------------------------------------------------------------------- #

# Token types
_TK_LPAREN  = "LPAREN"
_TK_RPAREN  = "RPAREN"
_TK_AND     = "AND"
_TK_OR      = "OR"
_TK_NOT     = "NOT"
_TK_EQ      = "EQ"
_TK_WORD    = "WORD"
_TK_EOF     = "EOF"


def _tokenize(text: str):
    """Tokenize a filter expression into a list of (type, value) tuples."""
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            tokens.append((_TK_LPAREN, "("))
            i += 1
            continue
        if ch == ")":
            tokens.append((_TK_RPAREN, ")"))
            i += 1
            continue
        if text[i:i+2] == "==":
            tokens.append((_TK_EQ, "=="))
            i += 2
            continue
        # Read a word token (letters, digits, dots, colons, slashes, underscores, hyphens)
        if ch.isalnum() or ch in (".", "/", "_", "!"):
            j = i
            while j < n and (text[j].isalnum() or text[j] in (".", "/", "_", "-", ":", "!")):
                j += 1
            word = text[i:j]
            i = j
            lo = word.lower()
            if lo == "and":
                tokens.append((_TK_AND, "and"))
            elif lo == "or":
                tokens.append((_TK_OR, "or"))
            elif lo == "not":
                tokens.append((_TK_NOT, "not"))
            else:
                tokens.append((_TK_WORD, word))
            continue
        # Unknown character — raise syntax error
        raise ValueError(f"Unexpected character '{ch}' in filter expression")
    tokens.append((_TK_EOF, ""))
    return tokens


# --------------------------------------------------------------------------- #
# Recursive-descent parser → AST nodes (plain tuples/dicts)
# --------------------------------------------------------------------------- #

class _Parser:
    """Parse token list into an AST."""

    def __init__(self, tokens):
        self._tokens = tokens
        self._pos = 0

    def _peek(self):
        return self._tokens[self._pos]

    def _consume(self, expected_type=None):
        tok = self._tokens[self._pos]
        if expected_type and tok[0] != expected_type:
            raise ValueError(f"Expected {expected_type} but got {tok}")
        self._pos += 1
        return tok

    def parse(self):
        node = self._parse_or()
        tok = self._peek()
        if tok[0] != _TK_EOF:
            raise ValueError(f"Unexpected token '{tok[1]}' after expression")
        return node

    def _parse_or(self):
        left = self._parse_and()
        while self._peek()[0] == _TK_OR:
            self._consume(_TK_OR)
            right = self._parse_and()
            left = ("or", left, right)
        return left

    def _parse_and(self):
        left = self._parse_not()
        while self._peek()[0] == _TK_AND:
            self._consume(_TK_AND)
            right = self._parse_not()
            left = ("and", left, right)
        return left

    def _parse_not(self):
        if self._peek()[0] == _TK_NOT:
            self._consume(_TK_NOT)
            operand = self._parse_not()
            return ("not", operand)
        return self._parse_primary()

    def _parse_primary(self):
        tok = self._peek()

        if tok[0] == _TK_LPAREN:
            self._consume(_TK_LPAREN)
            node = self._parse_or()
            self._consume(_TK_RPAREN)
            return node

        if tok[0] == _TK_WORD:
            return self._parse_predicate()

        raise ValueError(f"Unexpected token '{tok[1]}'")

    def _parse_predicate(self):
        """Parse a leaf predicate: protocol, host, port, net, etc."""
        word = self._consume(_TK_WORD)[1].lower()

        # ip.src == <addr>  /  ip.dst == <addr>
        if word in ("ip.src", "ip.dst"):
            self._consume(_TK_EQ)
            addr = self._consume(_TK_WORD)[1]
            return ("field_eq", word, addr)

        # tcp.port == <port>
        if word == "tcp.port":
            self._consume(_TK_EQ)
            port = self._consume(_TK_WORD)[1]
            return ("field_eq", "tcp.port", port)

        # Directional: src / dst
        if word in ("src", "dst"):
            direction = word
            next_tok = self._peek()
            if next_tok[0] == _TK_WORD:
                sub = self._consume(_TK_WORD)[1].lower()
                if sub == "port":
                    port = self._consume(_TK_WORD)[1]
                    return ("port", direction, port)
                elif sub in ("host", "ip"):
                    addr = self._consume(_TK_WORD)[1]
                    return ("host", direction, addr)
                else:
                    raise ValueError(f"Expected 'port', 'host', or 'ip' after '{direction}', got '{sub}'")
            raise ValueError(f"Unexpected end after '{direction}'")

        # port <n>
        if word == "port":
            port = self._consume(_TK_WORD)[1]
            return ("port", "both", port)

        # host <addr>  /  ip <addr>
        if word in ("host", "ip"):
            addr = self._consume(_TK_WORD)[1]
            return ("host", "both", addr)

        # net <cidr>
        if word == "net":
            cidr = self._consume(_TK_WORD)[1]
            return ("net", cidr)

        # Bare protocol names
        if word in ("tcp", "udp", "icmp", "arp", "dns", "http", "https",
                    "mdns", "ftp", "smtp", "tls", "ssl", "ipv4", "ipv6",
                    "dhcp", "snmp", "smb", "other"):
            return ("proto", word)

        raise ValueError(f"Unknown filter keyword: '{word}'")


# --------------------------------------------------------------------------- #
# Evaluator
# --------------------------------------------------------------------------- #

def _eval(node, pkt) -> bool:
    """Evaluate an AST node against a packet."""
    kind = node[0]

    if kind == "and":
        return _eval(node[1], pkt) and _eval(node[2], pkt)

    if kind == "or":
        return _eval(node[1], pkt) or _eval(node[2], pkt)

    if kind == "not":
        return not _eval(node[1], pkt)

    if kind == "proto":
        wanted = node[1].lower()
        actual = (getattr(pkt, "protocol", "") or "").lower()
        # "http" matches packets on ports 80/8080 even if labeled "tcp"
        if wanted == "http":
            sp = getattr(pkt, "src_port", None)
            dp = getattr(pkt, "dst_port", None)
            return actual in ("http",) or (actual == "tcp" and (sp in (80, 8080) or dp in (80, 8080)))
        # "dns" matches protocol=="dns" OR port 53
        if wanted == "dns":
            sp = getattr(pkt, "src_port", None)
            dp = getattr(pkt, "dst_port", None)
            return actual == "dns" or (sp == 53 or dp == 53)
        # "udp" matches udp AND dns (which is UDP-based)
        if wanted == "udp":
            return actual in ("udp", "dns", "mdns", "dhcp")
        return actual == wanted

    if kind == "port":
        direction, port_str = node[1], node[2]
        try:
            port_num = int(port_str)
        except ValueError:
            return False
        sp = getattr(pkt, "src_port", None)
        dp = getattr(pkt, "dst_port", None)
        if direction == "src":
            return sp == port_num
        if direction == "dst":
            return dp == port_num
        # both
        return sp == port_num or dp == port_num

    if kind == "host":
        direction, addr = node[1], node[2]
        sip = getattr(pkt, "src_ip", "") or ""
        dip = getattr(pkt, "dst_ip", "") or ""
        if direction == "src":
            return sip == addr
        if direction == "dst":
            return dip == addr
        return sip == addr or dip == addr

    if kind == "net":
        cidr = node[1]
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        sip = getattr(pkt, "src_ip", "") or ""
        dip = getattr(pkt, "dst_ip", "") or ""
        try:
            src_in = ipaddress.ip_address(sip) in network if sip else False
        except ValueError:
            src_in = False
        try:
            dst_in = ipaddress.ip_address(dip) in network if dip else False
        except ValueError:
            dst_in = False
        return src_in or dst_in

    if kind == "field_eq":
        field, value = node[1], node[2]
        if field == "ip.src":
            return (getattr(pkt, "src_ip", "") or "") == value
        if field == "ip.dst":
            return (getattr(pkt, "dst_ip", "") or "") == value
        if field == "tcp.port":
            try:
                port_num = int(value)
            except ValueError:
                return False
            sp = getattr(pkt, "src_port", None)
            dp = getattr(pkt, "dst_port", None)
            return sp == port_num or dp == port_num
        return False

    return False


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

class PacketFilter:
    """Stateless Wireshark-style display filter engine."""

    @staticmethod
    def validate(expression: str) -> Tuple[bool, str]:
        """
        Check whether *expression* is syntactically valid.
        Returns (True, "") or (False, error_message).
        """
        if not expression or not expression.strip():
            return True, ""
        try:
            tokens = _tokenize(expression.strip())
            parser = _Parser(tokens)
            parser.parse()
            return True, ""
        except ValueError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, f"Parse error: {exc}"

    @staticmethod
    def match(pkt, expression: str) -> bool:
        """
        Return True if *pkt* (a PacketInfo-like object) matches *expression*.
        Returns True if expression is empty (show all).
        Never raises — returns True on parse error to avoid hiding packets.
        """
        if not expression or not expression.strip():
            return True
        try:
            tokens = _tokenize(expression.strip())
            parser = _Parser(tokens)
            ast = parser.parse()
            return _eval(ast, pkt)
        except Exception:
            return True  # graceful: show packet on error
