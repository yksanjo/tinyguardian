"""
Threat Classifier
Classifies security events based on LLM analysis and heuristics.
"""

from typing import Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from loguru import logger


class ThreatType(str, Enum):
    """Types of security threats."""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    BRUTE_FORCE = "brute_force"
    NETWORK_ANOMALY = "network_anomaly"
    CONFIGURATION_CHANGE = "configuration_change"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    DENIAL_OF_SERVICE = "denial_of_service"
    UNKNOWN = "unknown"


@dataclass
class SecurityEvent:
    """Represents a security event."""
    event_id: str
    device_id: str
    timestamp: datetime
    log_message: str
    threat_level: str
    severity: float
    threat_type: ThreatType
    explanation: str
    recommendation: str
    source_ip: Optional[str] = None
    user: Optional[str] = None


class ThreatClassifier:
    """
    Classifies security events and determines threat types.
    """
    
    def __init__(self, severity_threshold: float = 0.7):
        """
        Initialize threat classifier.
        
        Args:
            severity_threshold: Minimum severity to trigger alert
        """
        self.severity_threshold = severity_threshold
        self.recent_events: Dict[str, list] = {}  # device_id -> events
        self.event_window = timedelta(minutes=5)
        
        logger.info(f"Threat classifier initialized (threshold: {severity_threshold})")
    
    def classify(self, 
                 device_id: str,
                 log_message: str,
                 llm_analysis: Dict,
                 timestamp: Optional[datetime] = None) -> SecurityEvent:
        """
        Classify a security event.
        
        Args:
            device_id: Device identifier
            log_message: Original log message
            llm_analysis: Analysis from LLM
            timestamp: Event timestamp
            
        Returns:
            SecurityEvent object
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # Determine threat type from analysis
        threat_type = self._determine_threat_type(log_message, llm_analysis)
        
        # Extract additional metadata
        source_ip = self._extract_ip(log_message)
        user = self._extract_user(log_message)
        
        # Check for pattern-based escalation
        severity = llm_analysis.get("severity", 0.0)
        if self._check_pattern(device_id, threat_type, timestamp):
            severity = min(1.0, severity + 0.2)  # Escalate
        
        event = SecurityEvent(
            event_id=f"evt_{timestamp.timestamp():.0f}_{device_id}",
            device_id=device_id,
            timestamp=timestamp,
            log_message=log_message,
            threat_level=llm_analysis.get("threat_level", "unknown"),
            severity=severity,
            threat_type=threat_type,
            explanation=llm_analysis.get("explanation", ""),
            recommendation=llm_analysis.get("recommendation", ""),
            source_ip=source_ip,
            user=user
        )
        
        # Store in recent events
        if device_id not in self.recent_events:
            self.recent_events[device_id] = []
        self.recent_events[device_id].append(event)
        
        # Clean old events
        self._clean_old_events(device_id, timestamp)
        
        return event
    
    def _determine_threat_type(self, log_message: str, llm_analysis: Dict) -> ThreatType:
        """Determine threat type from log and analysis."""
        message_lower = log_message.lower()
        explanation_lower = llm_analysis.get("explanation", "").lower()
        combined = f"{message_lower} {explanation_lower}"
        
        # Pattern matching
        if any(term in combined for term in ["failed login", "authentication failed", "invalid password"]):
            if any(term in combined for term in ["multiple", "repeated", "brute"]):
                return ThreatType.BRUTE_FORCE
            return ThreatType.UNAUTHORIZED_ACCESS
        
        if any(term in combined for term in ["unauthorized", "access denied", "permission denied"]):
            return ThreatType.UNAUTHORIZED_ACCESS
        
        if any(term in combined for term in ["network", "connection", "socket", "port scan"]):
            return ThreatType.NETWORK_ANOMALY
        
        if any(term in combined for term in ["config", "setting", "configuration changed"]):
            return ThreatType.CONFIGURATION_CHANGE
        
        if any(term in combined for term in ["data", "export", "download", "exfiltrat"]):
            return ThreatType.DATA_EXFILTRATION
        
        if any(term in combined for term in ["malware", "virus", "trojan", "ransomware"]):
            return ThreatType.MALWARE
        
        if any(term in combined for term in ["dos", "ddos", "denial", "overload"]):
            return ThreatType.DENIAL_OF_SERVICE
        
        return ThreatType.UNKNOWN
    
    def _extract_ip(self, log_message: str) -> Optional[str]:
        """Extract IP address from log message."""
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, log_message)
        return matches[0] if matches else None
    
    def _extract_user(self, log_message: str) -> Optional[str]:
        """Extract username from log message."""
        import re
        # Common patterns: user=, username=, user:, etc.
        patterns = [
            r'user[=:]\s*(\w+)',
            r'username[=:]\s*(\w+)',
            r'login[=:]\s*(\w+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, log_message, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _check_pattern(self, device_id: str, threat_type: ThreatType, timestamp: datetime) -> bool:
        """Check if event is part of a pattern (e.g., repeated attacks)."""
        if device_id not in self.recent_events:
            return False
        
        recent = [
            e for e in self.recent_events[device_id]
            if e.timestamp >= timestamp - self.event_window
            and e.threat_type == threat_type
        ]
        
        # If 3+ similar events in window, it's a pattern
        return len(recent) >= 3
    
    def _clean_old_events(self, device_id: str, current_time: datetime):
        """Remove events outside the time window."""
        if device_id not in self.recent_events:
            return
        
        cutoff = current_time - self.event_window
        self.recent_events[device_id] = [
            e for e in self.recent_events[device_id]
            if e.timestamp >= cutoff
        ]
    
    def is_alert(self, event: SecurityEvent) -> bool:
        """Determine if event should trigger an alert."""
        return event.severity >= self.severity_threshold




