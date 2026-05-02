"""
SIEM Detection Rules Engine
Handles rule-based and anomaly-based detection for security events
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
import json
import re
from collections import defaultdict
from abc import ABC, abstractmethod


class SeverityLevel(Enum):
    """Alert severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class EventType(Enum):
    """Security event types"""
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FILE_ACCESS = "file_access"
    PROCESS_EXECUTION = "process_execution"
    NETWORK_CONNECTION = "network_connection"
    MALWARE_DETECTED = "malware_detected"
    POLICY_VIOLATION = "policy_violation"
    UNUSUAL_ACTIVITY = "unusual_activity"
    FIREWALL_BLOCKED = "firewall_blocked"


@dataclass
class SecurityEvent:
    """Raw security event from any source"""
    timestamp: datetime
    source: str  # Windows, Linux, Firewall, etc.
    event_type: EventType
    severity: SeverityLevel
    user: Optional[str] = None
    host: Optional[str] = None
    ip_address: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    raw_log: str = ""

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type.value,
            "severity": self.severity.name,
            "user": self.user,
            "host": self.host,
            "ip_address": self.ip_address,
            "details": self.details,
        }


@dataclass
class Alert:
    """Generated security alert"""
    id: str
    timestamp: datetime
    severity: SeverityLevel
    title: str
    description: str
    events: List[SecurityEvent]
    rule_name: str
    status: str = "new"  # new, acknowledged, investigating, resolved
    assigned_to: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "rule_name": self.rule_name,
            "event_count": len(self.events),
            "status": self.status,
            "assigned_to": self.assigned_to,
        }


class DetectionRule(ABC):
    """Base class for detection rules"""

    def __init__(self, name: str, severity: SeverityLevel):
        self.name = name
        self.severity = severity

    @abstractmethod
    def detect(self, event: SecurityEvent, context: Dict) -> Optional[Alert]:
        """Check if event matches this rule"""
        pass


class ThresholdRule(DetectionRule):
    """Detects when a metric exceeds threshold within time window"""

    def __init__(
        self,
        name: str,
        severity: SeverityLevel,
        metric: str,
        threshold: int,
        window_minutes: int,
        group_by: str = "user",
    ):
        super().__init__(name, severity)
        self.metric = metric
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.group_by = group_by
        self.event_history: Dict[str, List[SecurityEvent]] = defaultdict(list)

    def detect(self, event: SecurityEvent, context: Dict) -> Optional[Alert]:
        key = getattr(event, self.group_by, "unknown")
        self.event_history[key].append(event)

        # Clean old events
        cutoff = event.timestamp - timedelta(minutes=self.window_minutes)
        self.event_history[key] = [
            e for e in self.event_history[key] if e.timestamp > cutoff
        ]

        count = len(self.event_history[key])
        if count >= self.threshold:
            return Alert(
                id=f"alert_{int(event.timestamp.timestamp())}_{key}",
                timestamp=event.timestamp,
                severity=self.severity,
                title=f"{self.name} - {key}",
                description=f"{count} events detected for {key} in {self.window_minutes} minutes (threshold: {self.threshold})",
                events=self.event_history[key][-self.threshold :],
                rule_name=self.name,
            )
        return None


class PatternRule(DetectionRule):
    """Detects patterns across multiple events"""

    def __init__(self, name: str, severity: SeverityLevel, pattern: Callable):
        super().__init__(name, severity)
        self.pattern = pattern
        self.recent_events: List[SecurityEvent] = []

    def detect(self, event: SecurityEvent, context: Dict) -> Optional[Alert]:
        self.recent_events.append(event)
        # Keep last 100 events
        self.recent_events = self.recent_events[-100:]

        result = self.pattern(event, self.recent_events, context)
        if result:
            events, description = result
            return Alert(
                id=f"alert_{int(event.timestamp.timestamp())}_{self.name}",
                timestamp=event.timestamp,
                severity=self.severity,
                title=self.name,
                description=description,
                events=events,
                rule_name=self.name,
            )
        return None


class AnomalyRule(DetectionRule):
    """Detects statistical anomalies in event streams"""

    def __init__(
        self,
        name: str,
        severity: SeverityLevel,
        metric: str,
        baseline_window_hours: int = 24,
        std_dev_threshold: float = 3.0,
    ):
        super().__init__(name, severity)
        self.metric = metric
        self.baseline_window_hours = baseline_window_hours
        self.std_dev_threshold = std_dev_threshold
        self.baseline: Dict[str, List[int]] = defaultdict(list)

    def detect(self, event: SecurityEvent, context: Dict) -> Optional[Alert]:
        key = getattr(event, "user", "unknown")

        # In production, calculate baseline from DB
        # For now, simple detection
        metric_value = event.details.get(self.metric, 0)

        if isinstance(metric_value, (int, float)):
            baseline_values = self.baseline.get(key, [])
            if len(baseline_values) > 10:
                avg = sum(baseline_values) / len(baseline_values)
                variance = sum((x - avg) ** 2 for x in baseline_values) / len(
                    baseline_values
                )
                std_dev = variance ** 0.5

                if std_dev > 0 and abs(metric_value - avg) > self.std_dev_threshold * std_dev:
                    return Alert(
                        id=f"alert_anomaly_{int(event.timestamp.timestamp())}",
                        timestamp=event.timestamp,
                        severity=self.severity,
                        title=f"{self.name} - Anomaly Detected",
                        description=f"Unusual {self.metric}: {metric_value} (baseline avg: {avg:.1f}, std: {std_dev:.1f})",
                        events=[event],
                        rule_name=self.name,
                    )

            self.baseline[key].append(metric_value)
            if len(self.baseline[key]) > 1000:
                self.baseline[key] = self.baseline[key][-1000:]

        return None


class DetectionEngine:
    """Main SIEM detection engine"""

    def __init__(self):
        self.rules: List[DetectionRule] = []
        self.alerts: List[Alert] = []
        self.event_history: List[SecurityEvent] = []
        self._initialize_default_rules()

    def _initialize_default_rules(self):
        """Initialize built-in detection rules"""

        # Failed login threshold rule
        self.add_rule(
            ThresholdRule(
                name="Multiple Failed Logins",
                severity=SeverityLevel.MEDIUM,
                metric="failed_login",
                threshold=5,
                window_minutes=15,
                group_by="user",
            )
        )

        # Failed login from multiple IPs
        self.add_rule(
            ThresholdRule(
                name="Failed Logins from Multiple IPs",
                severity=SeverityLevel.HIGH,
                metric="failed_login",
                threshold=3,
                window_minutes=10,
                group_by="ip_address",
            )
        )

        # Privilege escalation pattern
        def privilege_escalation_pattern(event, recent_events, context):
            if event.event_type != EventType.PRIVILEGE_ESCALATION:
                return None

            # Look for escalation attempts
            escalations = [
                e
                for e in recent_events[-20:]
                if e.event_type == EventType.PRIVILEGE_ESCALATION
                and e.user == event.user
            ]

            if len(escalations) >= 2:
                return (
                    escalations,
                    f"Multiple privilege escalation attempts by {event.user}",
                )
            return None

        self.add_rule(
            PatternRule(
                name="Privilege Escalation Pattern",
                severity=SeverityLevel.HIGH,
                pattern=privilege_escalation_pattern,
            )
        )

        # Brute force detection
        def brute_force_pattern(event, recent_events, context):
            if event.event_type != EventType.FAILED_LOGIN:
                return None

            failures = [
                e
                for e in recent_events[-50:]
                if e.event_type == EventType.FAILED_LOGIN
                and e.ip_address == event.ip_address
            ]

            if len(failures) >= 10:
                return (
                    failures[-10:],
                    f"Potential brute force attack from {event.ip_address}",
                )
            return None

        self.add_rule(
            PatternRule(
                name="Brute Force Attack",
                severity=SeverityLevel.CRITICAL,
                pattern=brute_force_pattern,
            )
        )

    def add_rule(self, rule: DetectionRule):
        """Add a custom detection rule"""
        self.rules.append(rule)

    def process_event(self, event: SecurityEvent) -> List[Alert]:
        """Process incoming security event and run detection rules"""
        self.event_history.append(event)
        if len(self.event_history) > 10000:
            self.event_history = self.event_history[-10000:]

        generated_alerts = []
        context = {"event_history": self.event_history[-100:]}

        for rule in self.rules:
            alert = rule.detect(event, context)
            if alert:
                # Deduplicate alerts
                if not self._is_duplicate_alert(alert):
                    generated_alerts.append(alert)
                    self.alerts.append(alert)

        return generated_alerts

    def _is_duplicate_alert(self, alert: Alert) -> bool:
        """Check if alert is duplicate of recent alert"""
        recent_cutoff = datetime.now() - timedelta(minutes=5)
        for existing in self.alerts:
            if (
                existing.timestamp > recent_cutoff
                and existing.rule_name == alert.rule_name
                and existing.title == alert.title
            ):
                return True
        return False

    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[SeverityLevel] = None,
        limit: int = 100,
    ) -> List[Alert]:
        """Get alerts with optional filtering"""
        filtered = self.alerts

        if status:
            filtered = [a for a in filtered if a.status == status]
        if severity:
            filtered = [a for a in filtered if a.severity == severity]

        return sorted(filtered, key=lambda a: a.timestamp, reverse=True)[:limit]

    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics"""
        return {
            "total_alerts": len(self.alerts),
            "critical": len([a for a in self.alerts if a.severity == SeverityLevel.CRITICAL]),
            "high": len([a for a in self.alerts if a.severity == SeverityLevel.HIGH]),
            "medium": len([a for a in self.alerts if a.severity == SeverityLevel.MEDIUM]),
            "low": len([a for a in self.alerts if a.severity == SeverityLevel.LOW]),
            "new": len([a for a in self.alerts if a.status == "new"]),
            "event_count": len(self.event_history),
        }

    def acknowledge_alert(self, alert_id: str, assigned_to: Optional[str] = None):
        """Mark alert as acknowledged"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.status = "acknowledged"
                alert.assigned_to = assigned_to
                break

    def resolve_alert(self, alert_id: str):
        """Mark alert as resolved"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.status = "resolved"
                break
