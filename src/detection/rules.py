"""Rule-based detection engine for Mini SOC.

Provides built-in heuristics for selected process starts, attributed failed-logon
spikes, and established connections using selected remote service ports.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import ipaddress
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

SUSPICIOUS_LOLBIN_PATTERNS = {
    "rundll32.exe": ("javascript:", "comsvcs.dll,minidump", "http://", "https://"),
    "regsvr32.exe": ("scrobj.dll", "/i:http", "/i:https"),
    "wmic.exe": ("process call create", "/node:"),
    "mshta.exe": ("javascript:", "vbscript:", "http://", "https://"),
    "certutil.exe": ("-urlcache", "-decode", "-encode", "-verifyctl"),
    "bitsadmin.exe": ("/transfer", "/addfile", "/setnotifycmdline"),
    "netsh.exe": ("portproxy", "add helper", "firewall add"),
    "bcdedit.exe": ("testsigning on", "nointegritychecks on", "debug on"),
    "psexec.exe": ("\\\\", "-s "),
}

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
    alert_key: str = ""

    def __post_init__(self) -> None:
        if not self.alert_key:
            identity = "|".join(
                (self.rule_name, self.source, *sorted(self.related_event_ids))
            )
            object.__setattr__(self, "alert_key", sha256(identity.encode("utf-8")).hexdigest())


class DetectionRule:
    """Base class for a rule that evaluates events and emits alerts."""

    name: str = "base_rule"
    description: str = "Base detection rule"
    severity: EventSeverity = EventSeverity.MEDIUM
    event_types: tuple[str, ...] = ()
    requires_complete_event_set = False

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
        """Return zero or more alerts for the given event sequence."""
        return []


class SuspiciousProcessRule(DetectionRule):
    """Flag selected process command patterns that warrant analyst review."""

    name = "suspicious_process"
    description = "Flags selected process and command-line patterns for review"
    scope = "Newly observed process starts matching configured tool and command-line indicators."
    limitations = (
        "Administrative and dual-use tools can be legitimate; names and command-line patterns "
        "are heuristics and do not establish malicious intent."
    )
    severity = EventSeverity.HIGH
    event_types = ("process_started",)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        for event in events:
            if event.event_type != "process_started":
                continue

            process_name = str(event.attributes.get("name", "")).lower()
            process_name = process_name.rsplit("\\", 1)[-1]
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
            elif process_name in SUSPICIOUS_PROCESS_NAMES:
                patterns = SUSPICIOUS_LOLBIN_PATTERNS.get(process_name, ())
                if not command_line or not any(pattern in command_line for pattern in patterns):
                    continue
            else:
                continue

            alerts.append(
                DetectionAlert(
                    rule_name=self.name,
                    title=f"Suspicious process observed: {process_name}",
                    description=(
                        f"Process '{process_name}' started on host '{event.host}' and matched a "
                        "configured suspicious command-line indicator. This dual-use tool may be "
                        "legitimate; validate the user, parent process, command line, and host context."
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
    """Flag repeated failed authentications with complete attribution."""

    name = "failed_logon_spike"
    description = "Flags three or more fully attributed failed logons within ten minutes"
    scope = "Groups failures by host, account, and valid source IP within a ten-minute window."
    limitations = (
        "Events missing a host, account, or valid source IP are excluded from correlation. "
        "A spike can result from user error, stale credentials, or automated clients and is not "
        "proof of brute force or compromise."
    )
    severity = EventSeverity.HIGH
    window = timedelta(minutes=10)
    threshold = 3
    event_types = ("windows_logon_failed",)
    requires_complete_event_set = True

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionAlert]:
        cutoff = datetime.now(timezone.utc) - self.window
        failed_events = [
            event for event in events
            if event.event_type == "windows_logon_failed" and event.timestamp >= cutoff
        ]
        if len(failed_events) < self.threshold:
            return []

        grouped: dict[tuple[str, str, str], list[SecurityEvent]] = defaultdict(list)
        for event in failed_events:
            account_value = event.attributes.get("account_name")
            source_value = event.attributes.get("source_ip")
            account = str(account_value).strip() if account_value is not None else ""
            host = str(event.host).strip() if event.host is not None else ""
            source = str(source_value).strip() if source_value is not None else ""
            unknown_values = {"", "-", "unknown", "<unknown>", "none", "null", "n/a", "not available"}
            if (
                account.casefold() in unknown_values
                or host.casefold() in unknown_values
                or source.casefold() in unknown_values
            ):
                continue
            try:
                source_ip = str(ipaddress.ip_address(source))
            except ValueError:
                continue
            grouped[(account.casefold(), host.casefold(), source_ip)].append(event)

        alerts: list[DetectionAlert] = []
        for (account_key, host_key, source_ip), account_events in grouped.items():
            if len(account_events) < self.threshold:
                continue
            related_ids = [str(event.event_id) for event in account_events]
            first_event = min(account_events, key=lambda event: event.timestamp)
            account = str(account_events[0].attributes["account_name"]).strip()
            host = str(account_events[0].host).strip()
            identity = f"{self.name}|{host_key}|{account_key}|{source_ip}|{first_event.event_id}"
            alerts.append(
                DetectionAlert(
                    rule_name=self.name,
                    title=f"Failed logon spike for '{account}' (attributed)",
                    description=(
                        f"{len(account_events)} failed Windows logons with known account and source IP "
                        f"were observed for '{account}' from {source_ip} on host '{host}' within 10 minutes. "
                        "This may reflect user error or an automated client; verify the source and "
                        "authentication context. Failures with missing attribution are not included."
                    ),
                    severity=self.severity,
                    source="windows_event_log",
                    related_event_ids=related_ids,
                    attributes={
                        "account_name": account,
                        "host": host,
                        "source_ip": source_ip,
                        "failed_count": len(account_events),
                        "window_minutes": 10,
                    },
                    detected_at=max(event.timestamp for event in account_events),
                    alert_key=sha256(identity.encode("utf-8")).hexdigest(),
                )
            )
        return alerts


class SuspiciousOutboundConnectionRule(DetectionRule):
    """Flag established connections whose remote endpoint uses selected service ports."""

    name = "suspicious_network"
    description = "Flags established connections to global remote endpoints on selected service ports"
    scope = "Established observed connections with a global remote IP and a configured remote port."
    limitations = (
        "The event does not establish traffic direction or which endpoint initiated the connection. "
        "Common service ports are frequently benign; a port match alone is not evidence of maliciousness."
    )
    severity = EventSeverity.MEDIUM
    event_types = ("network_connection_observed",)

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

            try:
                address = ipaddress.ip_address(str(remote_ip))
            except ValueError:
                continue

            if not address.is_global:
                continue

            if event.attributes.get("status") != "ESTABLISHED":
                continue

            alerts.append(
                DetectionAlert(
                    rule_name=self.name,
                    title=f"Established connection observed on service port {port_value}",
                    description=(
                        f"An established connection with remote endpoint {remote_ip}:{port_value} was "
                        f"observed on host '{event.host}'. Direction and initiating endpoint are unknown. "
                        "The port is commonly used by legitimate services and is not evidence of "
                        "maliciousness by itself; validate the owning process, destination, and expected "
                        "host behavior before treating this as suspicious."
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
