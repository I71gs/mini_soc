"""Rule-based detection engine for Mini SOC.

Provides a small set of built-in security detections for suspicious process start,
repeated failed logons, and high-risk outbound network connections.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from src.core.events import EventSeverity, SecurityEvent

SUSPICIOUS_PROCESS_NAMES = {
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "netsh.exe",
    "bcdedit.exe",
    "psexec.exe",
}

SUSPICIOUS_CMD_PATTERNS = (
    "/c powershell",
    "/k powershell",
    "powershell -enc",
    "powershell -e",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "wmic",
    "netsh",
    "curl http",
    "curl https",
    "start /b",
    "mshta",
)

SUSPICIOUS_POWERSHELL_PATTERNS = (
    "-enc",
    "encodedcommand",
    "downloadstring",
    "invoke-webrequest",
    "invoke-expression",
    "frombase64string",
    "iex",
    "bypass",
    "noninteractive",
    "-w hidden",
    "http://",
    "https://",
    "rundll32",
    "wmic",
    "certutil",
    "bitsadmin",
    "regsvr32",
)

SUSPICIOUS_REMOTE_PORTS = {22, 23, 3389, 445, 4444, 4445, 4446, 8080, 8443}


def _is_suspicious_cmd_command(command_line: str) -> bool:
    """Treat cmd.exe as suspicious only when used for obvious offensive chaining."""
    lowered = re.sub(r"\s+", " ", command_line.lower()).strip()
    if not lowered:
        return False
    return any(pattern in lowered for pattern in SUSPICIOUS_CMD_PATTERNS)


def _is_suspicious_powershell_command(command_line: str) -> bool:
    """Reduce false positives by requiring suspicious PowerShell execution patterns."""
    lowered = re.sub(r"\s+", " ", command_line.lower()).strip()
    if not lowered:
        return False

    tokenized = set(re.findall(r"[a-z0-9./:-]+", lowered))
    if any(token in tokenized for token in {"-enc", "encodedcommand", "downloadstring", "iex"}):
        return True

    if any(token in lowered for token in SUSPICIOUS_POWERSHELL_PATTERNS):
        return True

    return False


@dataclass(frozen=True)
class DetectionAlert:
    """Single detection alert raised by a rule."""

    rule_name: str
    title: str
    description: str
    severity: EventSeverity
    source: str
    related_event_ids: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DetectionRule:
    """Base class for a rule that evaluates events and emits alerts."""

    name: str = "base_rule"
    description: str = "Base detection rule"
    severity: EventSeverity = EventSeverity.MEDIUM

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
        """Return zero or more alerts for the given event sequence."""
        return []


class SuspiciousProcessRule(DetectionRule):
    """Flag known suspicious process names seen during startup."""

    name = "suspicious_process"
    description = "Detects process starts matching known admin/abuse tool names"
    severity = EventSeverity.HIGH

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        for event in events:
            if event.event_type != "process_started":
                continue

            process_name = str(event.attributes.get("name", "")).lower()
            command_line = str(
                event.attributes.get("command_line")
                or event.attributes.get("command")
                or event.attributes.get("args")
                or ""
            ).lower()

            if process_name in {"cmd.exe"}:
                if not _is_suspicious_cmd_command(command_line):
                    continue
            elif process_name in {"powershell.exe", "powershell_ise.exe"}:
                if not _is_suspicious_powershell_command(command_line):
                    continue
            elif process_name not in SUSPICIOUS_PROCESS_NAMES:
                continue

            alerts.append(
                DetectionAlert(
                    rule_name=self.name,
                    title=f"Suspicious process observed: {process_name}",
                    description=(
                        f"Process '{process_name}' was started on host '{event.host}' and may be "
                        "used for defense evasion or administrative abuse."
                    ),
                    severity=self.severity,
                    source=event.source,
                    related_event_ids=[str(event.event_id)],
                    attributes={
                        "pid": event.attributes.get("pid"),
                        "exe": event.attributes.get("exe"),
                        "username": event.attributes.get("username"),
                        "command_line": event.attributes.get("command_line") or event.attributes.get("command"),
                    },
                )
            )
        return alerts


class FailedLogonSpikeRule(DetectionRule):
    """Flag repeated failed authentications as a possible brute-force pattern."""

    name = "failed_logon_spike"
    description = "Raises alerts when multiple failed logons occur in a short period"
    severity = EventSeverity.HIGH

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
        failed_events = [
            event for event in events if event.event_type == "windows_logon_failed"
        ]
        if len(failed_events) < 3:
            return []

        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in failed_events:
            account = str(event.attributes.get("account_name") or "unknown")
            grouped[account].append(event)

        alerts: list[DetectionAlert] = []
        for account, account_events in grouped.items():
            if len(account_events) < 3:
                continue
            related_ids = [str(event.event_id) for event in account_events]
            alerts.append(
                DetectionAlert(
                    rule_name=self.name,
                    title=f"Failed logon spike for account '{account}'",
                    description=(
                        f"{len(account_events)} failed Windows logons were observed for account '{account}' "
                        "within the current observation period, which may indicate an attack or brute-force pattern."
                    ),
                    severity=self.severity,
                    source="windows_event_log",
                    related_event_ids=related_ids,
                    attributes={
                        "account_name": account,
                        "failed_count": len(account_events),
                    },
                )
            )
        return alerts


class SuspiciousOutboundConnectionRule(DetectionRule):
    """Flag high-risk outbound connectivity to known service ports."""

    name = "suspicious_network"
    description = "Detects outbound connections to risky external service ports"
    severity = EventSeverity.MEDIUM

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        for event in events:
            if event.event_type != "network_connection_observed":
                continue

            remote_ip = event.attributes.get("remote_ip")
            remote_port = event.attributes.get("remote_port")
            if remote_ip is None or remote_port is None:
                continue

            try:
                port_value = int(remote_port)
            except (TypeError, ValueError):
                continue

            if port_value not in SUSPICIOUS_REMOTE_PORTS:
                continue

            if remote_ip.startswith(("127.", "0.0.0.0", "10.", "192.168.", "172.")):
                continue

            alerts.append(
                DetectionAlert(
                    rule_name=self.name,
                    title=f"Outbound connection to risky port {port_value}",
                    description=(
                        f"A network connection was observed to {remote_ip}:{port_value} on host '{event.host}'. "
                        "This profile can be consistent with remote administration or command-and-control traffic."
                    ),
                    severity=self.severity,
                    source=event.source,
                    related_event_ids=[str(event.event_id)],
                    attributes={
                        "remote_ip": remote_ip,
                        "remote_port": port_value,
                        "protocol": event.attributes.get("protocol"),
                    },
                )
            )
        return alerts


class DetectionEngine:
    """Coordinates rule evaluation and returns a flattened set of alerts."""

    def __init__(self, rules: Sequence[DetectionRule] | None = None) -> None:
        self.rules = list(rules) if rules is not None else [
            SuspiciousProcessRule(),
            FailedLogonSpikeRule(),
            SuspiciousOutboundConnectionRule(),
        ]

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
        """Return alerts raised by all configured rules."""
        alerts: list[DetectionAlert] = []
        for rule in self.rules:
            alerts.extend(rule.evaluate(events))
        return alerts


def default_detection_engine() -> DetectionEngine:
    """Create a detection engine with the built-in rule set."""
    return DetectionEngine()
