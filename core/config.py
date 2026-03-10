"""
Configuration settings for CyberOctet Packet Analyzer
"""

class Config:
    """Application configuration constants"""
    
    # UI Configuration
    APP_NAME = "CyberOctet"
    VERSION = "1.0.0"
    
    # Dark Cyber Theme Colors
    COLORS = {
        'background': '#0a0a0a',
        'surface': '#1a1a1a',
        'surface_light': '#252525',
        'primary': '#00ff88',
        'secondary': '#00aaff',
        'accent': '#ff0088',
        'warning': '#ffaa00',
        'error': '#ff4444',
        'text_primary': '#ffffff',
        'text_secondary': '#cccccc',
        'text_muted': '#888888',
        'border': '#333333',
        'grid': '#2a2a2a',
        'highlight': '#00ff8820',
        'selection': '#00aaff30'
    }
    
    # Packet Capture Settings
    CAPTURE = {
        'default_buffer_size': 65536,
        'default_timeout': 1000,  # milliseconds
        'max_packets_per_capture': 1000000,
        'max_packets_in_memory': 50000,
        'max_raw_bytes_per_packet': 2048,
        'default_snaplen': 65535,
        'promiscuous_mode': True
    }
    
    # Display Settings
    DISPLAY = {
        'max_packet_list_items': 10000,
        'auto_scroll': True,
        'timestamp_format': '%Y-%m-%d %H:%M:%S.%f',
        'hex_bytes_per_line': 16,
        'font_family': 'Consolas, Monaco, monospace',
        'font_size': 10
    }
    
    # File Paths
    PATHS = {
        'captures_dir': 'captures',
        'logs_dir': 'logs',
        'temp_dir': 'temp'
    }
    
    # Protocol Priorities (for coloring and filtering)
    PROTOCOL_PRIORITY = {
        'ethernet': 1,
        'ipv4': 2, 'ipv6': 2,
        'tcp': 3, 'udp': 3, 'icmp': 3,
        'dns': 4, 'dhcp': 4,
        'http': 5, 'https': 5,
        'ftp': 6, 'smtp': 6, 'pop3': 6, 'imap': 6,
        'tls': 7, 'ssl': 7,
        'snmp': 8, 'smb': 8,
        'arp': 9
    }
    
    # Anomaly Detection Thresholds
    ANOMALY_THRESHOLDS = {
        'pps_spike_threshold': 1000,  # packets per second
        'port_scan_threshold': 50,    # ports per minute
        'syn_flood_threshold': 100,   # SYNs per second
        'dns_query_threshold': 500,   # queries per second
        'failed_handshake_threshold': 10  # per minute
    }
