"""
Traffic Anomaly Detection for CyberOctet
Detects suspicious network activity and potential security threats.

Key Design:
- MovingAverageBaseline: online EMA + variance for adaptive per-metric thresholds
- Each detector type (port scan, SYN flood, DNS, etc.) has its own baseline instance
- Static min-thresholds (from Config) act as a cold-start floor until the baseline
  has seen enough samples (>= min_samples)
"""

import math
import time
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from core.config import Config
from core.capture_engine import PacketInfo


# ─────────────────────────────────────────────────────────────────────────────
# Moving Average Baseline
# ─────────────────────────────────────────────────────────────────────────────

class MovingAverageBaseline:
    """Adaptive threshold baseline using Exponential Moving Average + Welford variance.

    Maintains a circular sample buffer for recent data and tracks EMA mean/variance
    for low-overhead online statistics. The `exceeds()` method returns True when a
    new value is more than `sigma` standard deviations above the current mean,
    with the static `min_threshold` acting as a floor during cold start.

    Args:
        window:        Sample buffer length (older samples are evicted).
        alpha:         EMA smoothing factor (0 < alpha <= 1, smaller = slower adapt).
        min_samples:   Minimum samples before dynamic threshold activates.
    """

    def __init__(self, window: int = 120, alpha: float = 0.15, min_samples: int = 5):
        self._window = window
        self._alpha = alpha
        self._min_samples = min_samples
        self._samples: deque = deque(maxlen=window)
        # Welford online mean / M2 (for variance)
        self._n = 0
        self._ema_mean  = 0.0
        self._ema_var   = 0.0   # EMA-based variance

    def update(self, value: float) -> None:
        """Record a new observation."""
        self._samples.append(value)
        self._n += 1
        if self._n == 1:
            self._ema_mean = float(value)
            self._ema_var  = 0.0
        else:
            prev_mean = self._ema_mean
            self._ema_mean = self._alpha * value + (1.0 - self._alpha) * self._ema_mean
            # EMA variance update (Holt-style)
            delta = value - prev_mean
            self._ema_var = self._alpha * (delta ** 2) + (1.0 - self._alpha) * self._ema_var

    def exceeds(self, value: float, sigma: float = 3.0, min_threshold: float = 0) -> bool:
        """Return True when *value* is anomalously high.

        During cold start (< min_samples seen), falls back to comparing against
        `min_threshold` directly.
        """
        if self._n < self._min_samples:
            return value >= min_threshold
        stdev = math.sqrt(max(self._ema_var, 0.0))
        dynamic = max(float(min_threshold), self._ema_mean + sigma * stdev)
        return value >= dynamic

    def get_stats(self) -> Dict:
        """Return current baseline statistics."""
        return {
            "samples": self._n,
            "ema_mean": round(self._ema_mean, 3),
            "ema_stdev": round(math.sqrt(max(self._ema_var, 0)), 3),
            "buffer_len": len(self._samples),
            "is_warm": self._n >= self._min_samples,
        }


@dataclass
class AnomalyAlert:
    """Represents a detected anomaly"""
    alert_type: str
    severity: str  # low, medium, high, critical
    timestamp: float
    description: str
    source_ip: str
    target_ip: Optional[str] = None
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class AnomalyDetector:
    """Main anomaly detection engine"""
    
    def __init__(self):
        self.thresholds = Config.ANOMALY_THRESHOLDS
        
        # Tracking data structures
        self.pps_history = deque(maxlen=300)  # 5 minutes at 1-second intervals
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))  # src_ip -> target_ip -> ports
        self.syn_flood_tracker = defaultdict(int)  # src_ip -> SYN count
        self.dns_tracker = defaultdict(int)  # src_ip -> DNS query count
        self.failed_handshake_tracker = defaultdict(int)  # src_ip -> failed handshakes
        
        # Time windows for tracking
        self.port_scan_window = 60  # seconds
        self.syn_flood_window = 10   # seconds
        self.dns_window = 10         # seconds
        self.handshake_window = 60   # seconds
        
        # Alerts
        self.alerts: List[AnomalyAlert] = []
        self.max_alerts = 1000
        
        # Suspicious IP tracking
        self.suspicious_ips: Set[str] = set()
        self.whitelisted_ips: Set[str] = set()
        
        # Statistics
        self.total_packets_analyzed = 0
        self.total_alerts_generated = 0

    def _get_dynamic_threshold(self, current_val: int, all_vals: List[int], min_threshold: int) -> bool:
        """Calculate if current value exceeds dynamic baseline (Mean + 3*StdDev)"""
        if len(all_vals) < 5:
            return current_val >= min_threshold
            
        import statistics
        mean = statistics.mean(all_vals)
        try:
            stdev = statistics.stdev(all_vals)
        except statistics.StatisticsError:
            stdev = 0
            
        dynamic_limit = max(min_threshold, mean + 3 * stdev)
        return current_val >= dynamic_limit
    
    def analyze_packet(self, packet_info: PacketInfo) -> List[AnomalyAlert]:
        """Analyze a single packet for anomalies."""
        self.total_packets_analyzed += 1
        alerts = []

        # Update PPS counter and feed baseline every second
        current_time = time.time()
        self.pps_history.append((current_time, 1))
        self._pps_counter += 1
        elapsed = current_time - self._last_pps_check
        if elapsed >= 1.0:
            pps = self._pps_counter / elapsed
            self._baselines["pps"].update(pps)
            self._pps_counter = 0
            self._last_pps_check = current_time

        # Run detection algorithms
        alerts.extend(self._detect_pps_spike())
        alerts.extend(self._detect_port_scan(packet_info))
        alerts.extend(self._detect_syn_flood(packet_info))
        alerts.extend(self._detect_dns_anomaly(packet_info))
        alerts.extend(self._detect_failed_handshake(packet_info))
        alerts.extend(self._detect_suspicious_ports(packet_info))
        alerts.extend(self._detect_unusual_packet_size(packet_info))
        alerts.extend(self._detect_private_to_public_communication(packet_info))

        for alert in alerts:
            self._add_alert(alert)

        return alerts

    def _detect_pps_spike(self) -> List[AnomalyAlert]:
        """Detect sudden spikes in packets-per-second rate."""
        alerts = []
        baseline = self._baselines["pps"]
        if not baseline.get_stats()["is_warm"]:
            return alerts
        recent_pps = self._pps_counter  # counter since last reset
        min_thresh = self.thresholds.get("pps_spike_threshold", 1000)
        if baseline.exceeds(recent_pps, sigma=3.0, min_threshold=min_thresh):
            alerts.append(AnomalyAlert(
                alert_type="PPS Spike",
                severity="high",
                timestamp=time.time(),
                description=f"Unusual traffic rate: {recent_pps:.0f} pps (baseline mean: {baseline.get_stats()['ema_mean']:.1f})",
                source_ip="(network)",
                details={
                    "pps": recent_pps,
                    **baseline.get_stats(),
                },
            ))
        return alerts
    
    def _detect_port_scan(self, packet_info: PacketInfo) -> List[AnomalyAlert]:
        """Detect potential port scanning activity."""
        alerts = []

        if packet_info.protocol == 'tcp' and packet_info.flags:
            if 'SYN' in packet_info.flags and 'ACK' not in packet_info.flags:
                src_ip   = packet_info.src_ip
                dst_ip   = packet_info.dst_ip
                dst_port = packet_info.dst_port

                if dst_port:
                    self.port_scan_tracker[src_ip][dst_ip].add(dst_port)
                    ports_scanned = len(self.port_scan_tracker[src_ip][dst_ip])

                    baseline  = self._baselines["port_scan"]
                    baseline.update(ports_scanned)
                    min_thresh = self.thresholds.get('port_scan_threshold', 20)

                    if baseline.exceeds(ports_scanned, sigma=3.0, min_threshold=min_thresh):
                        alerts.append(AnomalyAlert(
                            alert_type="Port Scan",
                            severity="high",
                            timestamp=packet_info.timestamp,
                            description=f"Port scan: {src_ip} scanned {ports_scanned} ports on {dst_ip}",
                            source_ip=src_ip,
                            target_ip=dst_ip,
                            details={
                                'ports_scanned': list(self.port_scan_tracker[src_ip][dst_ip]),
                                'scan_count': ports_scanned,
                                **baseline.get_stats(),
                            },
                        ))
                        self.suspicious_ips.add(src_ip)

        return alerts
    
    def _detect_syn_flood(self, packet_info: PacketInfo) -> List[AnomalyAlert]:
        """Detect SYN flood attacks."""
        alerts = []

        if packet_info.protocol == 'tcp' and packet_info.flags:
            if 'SYN' in packet_info.flags and 'ACK' not in packet_info.flags:
                src_ip = packet_info.src_ip
                self.syn_flood_tracker[src_ip] += 1

                # Rolling window cleanup
                current_time = time.time()
                if hasattr(self, '_syn_flood_cleanup_time'):
                    if current_time - self._syn_flood_cleanup_time > self.syn_flood_window:
                        self.syn_flood_tracker.clear()
                        self._syn_flood_cleanup_time = current_time
                else:
                    self._syn_flood_cleanup_time = current_time

                current_count = self.syn_flood_tracker[src_ip]
                baseline = self._baselines["syn_flood"]
                baseline.update(current_count)
                min_thresh = self.thresholds.get('syn_flood_threshold', 100)

                if baseline.exceeds(current_count, sigma=3.0, min_threshold=min_thresh):
                    alerts.append(AnomalyAlert(
                        alert_type="SYN Flood",
                        severity="critical",
                        timestamp=packet_info.timestamp,
                        description=f"SYN flood: {src_ip} sent {current_count} SYN packets in {self.syn_flood_window}s",
                        source_ip=src_ip,
                        details={
                            'syn_count': current_count,
                            'time_window': self.syn_flood_window,
                            **baseline.get_stats(),
                        },
                    ))
                    self.suspicious_ips.add(src_ip)

        return alerts
    
    def _detect_dns_anomaly(self, packet_info: PacketInfo) -> List[AnomalyAlert]:
        """Detect unusual DNS activity."""
        alerts = []

        if packet_info.protocol in ('udp', 'dns') and packet_info.dst_port == 53:
            src_ip = packet_info.src_ip
            self.dns_tracker[src_ip] += 1

            current_time = time.time()
            if hasattr(self, '_dns_cleanup_time'):
                if current_time - self._dns_cleanup_time > self.dns_window:
                    self.dns_tracker.clear()
                    self._dns_cleanup_time = current_time
            else:
                self._dns_cleanup_time = current_time

            current_count = self.dns_tracker[src_ip]
            baseline = self._baselines["dns"]
            baseline.update(current_count)
            min_thresh = self.thresholds.get('dns_query_threshold', 50)

            if baseline.exceeds(current_count, sigma=3.0, min_threshold=min_thresh):
                alerts.append(AnomalyAlert(
                    alert_type="DNS Anomaly",
                    severity="medium",
                    timestamp=packet_info.timestamp,
                    description=f"Unusual DNS activity: {src_ip} made {current_count} queries in {self.dns_window}s",
                    source_ip=src_ip,
                    details={
                        'query_count': current_count,
                        'time_window': self.dns_window,
                        **baseline.get_stats(),
                    },
                ))

        return alerts
    
    def _detect_failed_handshake(self, packet_info: PacketInfo) -> List[AnomalyAlert]:
        """Detect failed TCP handshakes (RST bursts)."""
        alerts = []

        if packet_info.protocol == 'tcp' and packet_info.flags:
            src_ip = packet_info.src_ip

            if 'RST' in packet_info.flags:
                self.failed_handshake_tracker[src_ip] += 1

                current_time = time.time()
                if hasattr(self, '_handshake_cleanup_time'):
                    if current_time - self._handshake_cleanup_time > self.handshake_window:
                        self.failed_handshake_tracker.clear()
                        self._handshake_cleanup_time = current_time
                else:
                    self._handshake_cleanup_time = current_time

                current_count = self.failed_handshake_tracker[src_ip]
                baseline = self._baselines["handshake"]
                baseline.update(current_count)
                min_thresh = self.thresholds.get('failed_handshake_threshold', 20)

                if baseline.exceeds(current_count, sigma=3.0, min_threshold=min_thresh):
                    alerts.append(AnomalyAlert(
                        alert_type="Failed Handshakes",
                        severity="medium",
                        timestamp=packet_info.timestamp,
                        description=f"RST burst: {src_ip} had {current_count} failures in {self.handshake_window}s",
                        source_ip=src_ip,
                        details={
                            'failure_count': current_count,
                            'time_window': self.handshake_window,
                            **baseline.get_stats(),
                        },
                    ))

        return alerts
    
    def _detect_suspicious_ports(self, packet_info: PacketInfo) -> List[AnomalyAlert]:
        """Detect traffic to/from suspicious ports"""
        alerts = []
        
        # List of commonly suspicious ports
        suspicious_ports = {
            1337, 31337, 12345, 54321, 9999, 4444, 5555, 6666, 7777, 8888,
            9999, 31338, 31339, 31340, 12346, 20034, 21554, 23456, 27444,
            31335, 31336, 31337, 31338, 31339, 31340, 31341, 31342,
            31343, 31344, 31345, 31346, 31347, 31348, 31349, 31350
        }
        
        src_port = packet_info.src_port
        dst_port = packet_info.dst_port
        
        if src_port in suspicious_ports or dst_port in suspicious_ports:
            alert = AnomalyAlert(
                alert_type="Suspicious Port",
                severity="low",
                timestamp=packet_info.timestamp,
                description=f"Suspicious port usage: {src_port} → {dst_port}",
                source_ip=packet_info.src_ip,
                target_ip=packet_info.dst_ip,
                details={
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': packet_info.protocol
                }
            )
            alerts.append(alert)
        
        return alerts
    
    def _detect_unusual_packet_size(self, packet_info: PacketInfo) -> List[AnomalyAlert]:
        """Detect unusually sized packets"""
        alerts = []
        
        # Check for unusually small packets (possible covert channel)
        if packet_info.length < 20:
            alert = AnomalyAlert(
                alert_type="Unusual Packet Size",
                severity="low",
                timestamp=packet_info.timestamp,
                description=f"Unusually small packet: {packet_info.length} bytes",
                source_ip=packet_info.src_ip,
                target_ip=packet_info.dst_ip,
                details={
                    'packet_size': packet_info.length,
                    'protocol': packet_info.protocol
                }
            )
            alerts.append(alert)
        
        # Check for oversized packets (possible fragmentation or tunneling)
        elif packet_info.length > 1500:
            alert = AnomalyAlert(
                alert_type="Oversized Packet",
                severity="medium",
                timestamp=packet_info.timestamp,
                description=f"Oversized packet: {packet_info.length} bytes",
                source_ip=packet_info.src_ip,
                target_ip=packet_info.dst_ip,
                details={
                    'packet_size': packet_info.length,
                    'protocol': packet_info.protocol
                }
            )
            alerts.append(alert)
        
        return alerts
    
    def _detect_private_to_public_communication(self, packet_info: PacketInfo) -> List[AnomalyAlert]:
        """Detect internal hosts communicating with external destinations"""
        alerts = []
        
        if self._is_private_ip(packet_info.src_ip) and not self._is_private_ip(packet_info.dst_ip):
            # This is normal for most networks, but we can flag specific patterns
            # For example, internal hosts communicating with known malicious IPs
            # This would require external threat intelligence feeds
            
            # For now, just track the communication
            pass
        
        return alerts
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _add_alert(self, alert: AnomalyAlert):
        """Add an alert to the alerts list"""
        self.alerts.append(alert)
        self.total_alerts_generated += 1
        
        # Maintain maximum alert count
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop(0)
    
    def get_recent_alerts(self, minutes: int = 60) -> List[AnomalyAlert]:
        """Get alerts from the last N minutes"""
        cutoff_time = time.time() - (minutes * 60)
        return [alert for alert in self.alerts if alert.timestamp >= cutoff_time]
    
    def get_alerts_by_type(self, alert_type: str) -> List[AnomalyAlert]:
        """Get alerts of a specific type"""
        return [alert for alert in self.alerts if alert.alert_type == alert_type]
    
    def get_alerts_by_severity(self, severity: str) -> List[AnomalyAlert]:
        """Get alerts by severity level"""
        return [alert for alert in self.alerts if alert.severity == severity]
    
    def get_alerts_by_ip(self, ip: str) -> List[AnomalyAlert]:
        """Get alerts involving a specific IP"""
        return [alert for alert in self.alerts 
                if alert.source_ip == ip or alert.target_ip == ip]
    
    def get_suspicious_ips(self) -> List[str]:
        """Get list of suspicious IPs"""
        return list(self.suspicious_ips)
    
    def add_whitelisted_ip(self, ip: str):
        """Add IP to whitelist"""
        self.whitelisted_ips.add(ip)
    
    def remove_whitelisted_ip(self, ip: str):
        """Remove IP from whitelist"""
        self.whitelisted_ips.discard(ip)
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        return ip in self.whitelisted_ips
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        alert_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for alert in self.alerts:
            alert_counts[alert.alert_type] += 1
            severity_counts[alert.severity] += 1
        
        return {
            'total_packets_analyzed': self.total_packets_analyzed,
            'total_alerts_generated': self.total_alerts_generated,
            'active_alerts': len(self.alerts),
            'suspicious_ips': len(self.suspicious_ips),
            'whitelisted_ips': len(self.whitelisted_ips),
            'alert_types': dict(alert_counts),
            'severity_distribution': dict(severity_counts)
        }
    
    def clear_alerts(self):
        """Clear all alerts and reset tracking state."""
        self.alerts.clear()
        self.suspicious_ips.clear()
        self.port_scan_tracker.clear()
        self.syn_flood_tracker.clear()
        self.dns_tracker.clear()
        self.failed_handshake_tracker.clear()
        # Reset baselines so the detector can relearn the new baseline
        for bl in self._baselines.values():
            bl.__init__(bl._window, bl._alpha, bl._min_samples)

    def get_baseline_stats(self) -> Dict[str, Dict]:
        """Return current adaptive baseline statistics for all metrics.

        Useful for displaying adaptive threshold info in the UI.
        Returns a dict mapping metric name -> stats dict from MovingAverageBaseline.
        """
        return {name: bl.get_stats() for name, bl in self._baselines.items()}
    
    def export_alerts(self, filename: str) -> bool:
        """Export alerts to file"""
        try:
            import json
            
            alerts_data = []
            for alert in self.alerts:
                alerts_data.append({
                    'alert_type': alert.alert_type,
                    'severity': alert.severity,
                    'timestamp': alert.timestamp,
                    'description': alert.description,
                    'source_ip': alert.source_ip,
                    'target_ip': alert.target_ip,
                    'details': alert.details
                })
            
            with open(filename, 'w') as f:
                json.dump(alerts_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting alerts: {e}")
            return False
