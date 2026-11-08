"""Standardized security event model for Mini SOC.

Defines the core SecurityEvent data model using Pydantic v2.
Supports UTC normalization, strict timezone awareness, enum validations,
extensible attribute dictionaries, and JSON/database persistence compatibility.
"""

from datetime import datetime, timezone
from enum import Enum
import json
import socket
from typing import Any
import uuid

from pydantic import BaseModel, Field, ValidationInfo, field_validator


class EventSeverity(str, Enum):
    """Standard security event severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventCategory(str, Enum):
    """Standard security event categories."""

    SYSTEM = "SYSTEM"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    AUTHENTICATION = "AUTHENTICATION"
    FILE = "FILE"
    REGISTRY = "REGISTRY"
    APPLICATION = "APPLICATION"
    OTHER = "OTHER"


class SecurityEvent(BaseModel):
    """Standardized security event model for Mini SOC.

    Represents a normalized security occurrence across host, system, network,
    and application telemetry sources.

    Attributes:
        event_id: Unique event identifier (UUIDv4).
        timestamp: Timezone-aware UTC timestamp when the event occurred.
        source: Identifier of the event source (e.g. 'windows_event_log', 'sysmon').
        category: High-level category of the event (e.g. PROCESS, NETWORK).
        event_type: Specific event action/type (e.g. 'process_created', 'logon_failed').
        severity: Assessed severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL).
        host: Hostname of the system where the event originated.
        description: Human-readable explanation of the event.
        attributes: Extensible key-value dictionary containing event-specific metadata.
        schema_version: Schema specification version (defaults to '1.0').
    """

    event_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Unique event identifier (automatically generated UUIDv4).",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timezone-aware UTC timestamp when the event occurred.",
    )
    source: str = Field(
        ...,
        description="Identifier of the event collector/source.",
    )
    category: EventCategory | str = Field(
        ...,
        description="Event category classifying the security domain.",
    )
    event_type: str = Field(
        ...,
        description="Specific event type or action name.",
    )
    severity: EventSeverity = Field(
        default=EventSeverity.INFO,
        description="Event severity level.",
    )
    host: str = Field(
        default_factory=socket.gethostname,
        description="Hostname associated with the event origin.",
    )
    description: str = Field(
        ...,
        description="Human-readable summary of the security event.",
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible dictionary for event-specific attributes.",
    )
    schema_version: str = Field(
        default="1.0",
        description="Version of the security event schema.",
    )

    @field_validator("source", "event_type", "description", "host", "schema_version", mode="before")
    @classmethod
    def validate_non_empty_strings(cls, value: Any, info: ValidationInfo) -> str:
        """Validate that string fields are non-empty after stripping whitespace."""
        if not isinstance(value, str):
            raise ValueError(f"{info.field_name} must be a string, got {type(value).__name__}")
        stripped = value.strip()
        if not stripped:
            raise ValueError(f"{info.field_name} cannot be empty or whitespace only")
        return stripped

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> EventCategory | str:
        """Validate category and normalize standard categories to EventCategory enum."""
        if isinstance(value, EventCategory):
            return value
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                raise ValueError("category cannot be empty or whitespace only")
            try:
                return EventCategory(stripped.upper())
            except ValueError:
                return stripped
        raise ValueError(f"category must be an EventCategory or string, got {type(value).__name__}")

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, value: Any) -> EventSeverity:
        """Validate and normalize severity into an EventSeverity enum."""
        if isinstance(value, EventSeverity):
            return value
        if isinstance(value, str):
            try:
                return EventSeverity(value.strip().upper())
            except ValueError:
                valid = [s.value for s in EventSeverity]
                raise ValueError(f"Invalid severity '{value}'. Allowed values are: {valid}")
        raise ValueError(f"severity must be an EventSeverity enum or string, got {type(value).__name__}")

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_and_normalize_timestamp(cls, value: Any) -> datetime:
        """Reject naive timestamps and normalize timezone-aware timestamps to UTC."""
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError as err:
                raise ValueError(f"Invalid ISO timestamp format: {err}") from err

        if isinstance(value, datetime):
            if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
                raise ValueError("Timestamp must be timezone-aware (naive datetimes are rejected)")
            return value.astimezone(timezone.utc)

        raise ValueError(f"timestamp must be a datetime or ISO string, got {type(value).__name__}")

    def to_db_record(self) -> dict[str, Any]:
        """Flatten event into a dictionary suitable for SQLite database storage.

        Converts UUID, datetime, Enum, and nested attributes into serializable primitives.
        """
        category_val = self.category.value if isinstance(self.category, Enum) else str(self.category)
        return {
            "event_id": str(self.event_id),
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "category": category_val,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "host": self.host,
            "description": self.description,
            "attributes": json.dumps(self.attributes),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_db_record(cls, record: dict[str, Any]) -> "SecurityEvent":
        """Reconstruct a SecurityEvent instance from a database record."""
        data = dict(record)
        raw_attrs = data.get("attributes")
        if isinstance(raw_attrs, str):
            try:
                data["attributes"] = json.loads(raw_attrs)
            except json.JSONDecodeError as err:
                raise ValueError(f"Failed to decode attributes JSON: {err}") from err
        return cls.model_validate(data)
