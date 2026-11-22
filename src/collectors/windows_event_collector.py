"""Windows Event Log telemetry collector.

Retrieves security and system events using Windows native APIs (pywin32 / win32evtlog),
normalizes records into SecurityEvent models, supports efficient XPath filtering,
handles access permissions gracefully, and enforces persistent checkpoint deduplication.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import socket
from typing import Any, Sequence
import xml.etree.ElementTree as ET

try:
    import win32evtlog
    import pywintypes
    HAS_WIN32EVTLOG = True
except ImportError:  # pragma: no cover
    win32evtlog = None
    pywintypes = None
    HAS_WIN32EVTLOG = False

from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.collectors.health import CollectorHealth
from src.database.checkpoint_repository import CheckpointRepository
from src.database.event_repository import EventRepository

logger = logging.getLogger(__name__)

# Default channels and high-value event IDs
DEFAULT_CHANNELS_CONFIG: dict[str, list[int]] = {
    "Security": [4624, 4625, 1102],
    "System": [7045],
}


def _build_query_xpath(
    event_ids: list[int],
    last_record_id: int | None = None,
    start_time: datetime | None = None,
) -> str:
    """Construct an efficient XPath query for Windows Event Log filtering.

    Args:
        event_ids: Target Windows Event IDs to capture.
        last_record_id: Optional EventRecordID checkpoint for incremental queries.
        start_time: Optional UTC cutoff for the initial historical import.

    Returns:
        str: Formatted XPath query expression.
    """
    id_clause = " or ".join(f"EventID={eid}" for eid in event_ids)
    conditions = [f"({id_clause})"]
    if last_record_id is not None and last_record_id > 0:
        conditions.append(f"EventRecordID > {last_record_id}")
    if start_time is not None:
        cutoff = start_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        conditions.append(f"TimeCreated[@SystemTime >= '{cutoff}']")
    return f"*[System[{' and '.join(conditions)}]]"


def _parse_event_timestamp(system_time_str: str | None) -> datetime:
    """Normalize event SystemTime string to a timezone-aware UTC datetime."""
    if system_time_str:
        try:
            dt = datetime.fromisoformat(system_time_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _find_first_by_tag(parent: ET.Element, tag: str) -> ET.Element | None:
    """Helper to locate child element by tag name ignoring XML namespaces."""
    for child in parent.iter():
        child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if child_tag == tag:
            return child
    return None


def parse_event_xml(xml_content: str) -> dict[str, Any] | None:
    """Parse raw Windows Event XML into structured event attributes.

    Extracts core header fields and named EventData entries while discarding
    unnecessary raw XML markup.

    Args:
        xml_content: Rendered XML string from EvtRender.

    Returns:
        dict[str, Any] | None: Parsed fields, or None if malformed/unparseable.
    """
    try:
        root = ET.fromstring(xml_content)
    except Exception as err:
        logger.debug("Failed to parse event XML string: %s", err)
        return None

    system_elem = _find_first_by_tag(root, "System")
    if system_elem is None:
        return None

    def get_tag_text(tag: str) -> str | None:
        assert system_elem is not None
        elem = _find_first_by_tag(system_elem, tag)
        return elem.text.strip() if elem is not None and elem.text else None

    raw_event_id = get_tag_text("EventID")
    if not raw_event_id:
        return None
    try:
        event_id = int(raw_event_id)
    except ValueError:
        return None

    raw_record_id = get_tag_text("EventRecordID")
    try:
        record_id = int(raw_record_id) if raw_record_id else 0
    except ValueError:
        record_id = 0

    channel = get_tag_text("Channel") or "Unknown"
    computer = get_tag_text("Computer") or socket.gethostname()

    time_elem = _find_first_by_tag(system_elem, "TimeCreated")
    system_time_str = time_elem.attrib.get("SystemTime") if time_elem is not None else None

    # Parse named EventData fields
    event_data: dict[str, str] = {}
    event_data_elem = _find_first_by_tag(root, "EventData")
    if event_data_elem is not None:
        for child in event_data_elem:
            child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child_tag == "Data":
                name = child.attrib.get("Name")
                text = (child.text or "").strip()
                if name:
                    event_data[name] = text
                else:
                    event_data[f"Data_{len(event_data)}"] = text

    return {
        "event_id": event_id,
        "record_id": record_id,
        "channel": channel,
        "computer": computer,
        "system_time": system_time_str,
        "event_data": event_data,
    }


def normalize_event(parsed: dict[str, Any]) -> SecurityEvent:
    """Transform parsed Windows event record dictionary into a SecurityEvent instance.

    Maps supported Windows Event IDs (4624, 4625, 1102, 7045) into normalized
    event types and appropriate security categories and severity levels.

    Args:
        parsed: Output from parse_event_xml.

    Returns:
        SecurityEvent: Fully populated SecurityEvent model.
    """
    event_id = parsed["event_id"]
    channel = parsed["channel"]
    record_id = parsed["record_id"]
    computer = parsed["computer"]
    timestamp = _parse_event_timestamp(parsed["system_time"])
    data = parsed["event_data"]

    if event_id == 4624:
        account = data.get("TargetUserName") or data.get("SubjectUserName") or "unknown"
        logon_type = data.get("LogonType") or "unknown"
        desc = f"Windows logon succeeded for account '{account}' (Logon Type: {logon_type})"
        attrs = {
            "windows_event_id": 4624,
            "channel": channel,
            "record_id": record_id,
            "account_name": account,
            "domain": data.get("TargetDomainName") or data.get("SubjectDomainName"),
            "logon_type": logon_type,
            "workstation_name": data.get("WorkstationName"),
            "source_ip": data.get("IpAddress"),
            "source_port": data.get("IpPort"),
            "process_name": data.get("ProcessName"),
            "logon_id": data.get("TargetLogonId"),
        }
        return SecurityEvent(
            source="windows_event_log",
            category=EventCategory.AUTHENTICATION,
            event_type="windows_logon_success",
            severity=EventSeverity.INFO,
            host=computer,
            timestamp=timestamp,
            description=desc,
            attributes=attrs,
        )

    if event_id == 4625:
        account = data.get("TargetUserName") or "unknown"
        source_ip = data.get("IpAddress") or "unknown"
        status = data.get("Status") or "unknown"
        desc = f"Windows logon failed for account '{account}' (Status: {status})"
        attribution_complete = (
            account.strip().casefold() not in {"", "-", "unknown", "<unknown>", "none", "null", "n/a"}
            and computer.strip().casefold() not in {"", "-", "unknown", "<unknown>", "none", "null", "n/a"}
        )
        try:
            source_ip = str(ipaddress.ip_address(source_ip.strip()))
        except ValueError:
            attribution_complete = False
            source_ip = source_ip.strip() or "unknown"
        attrs = {
            "windows_event_id": 4625,
            "channel": channel,
            "record_id": record_id,
            "account_name": account,
            "domain": data.get("TargetDomainName"),
            "logon_type": data.get("LogonType"),
            "status": status,
            "sub_status": data.get("SubStatus"),
            "failure_reason": data.get("FailureReason"),
            "workstation_name": data.get("WorkstationName"),
            "source_ip": source_ip,
            "attribution_status": "complete" if attribution_complete else "incomplete",
            "source_port": data.get("IpPort"),
            "process_name": data.get("ProcessName"),
        }
        return SecurityEvent(
            source="windows_event_log",
            category=EventCategory.AUTHENTICATION,
            event_type="windows_logon_failed",
            severity=EventSeverity.MEDIUM,
            host=computer,
            timestamp=timestamp,
            description=desc,
            attributes=attrs,
        )

    if event_id == 1102:
        account = data.get("SubjectUserName") or "unknown"
        desc = f"Windows security audit log was cleared by '{account}'"
        attrs = {
            "windows_event_id": 1102,
            "channel": channel,
            "record_id": record_id,
            "account_name": account,
            "domain": data.get("SubjectDomainName"),
            "logon_id": data.get("SubjectLogonId"),
        }
        return SecurityEvent(
            source="windows_event_log",
            category=EventCategory.SYSTEM,
            event_type="windows_audit_log_cleared",
            severity=EventSeverity.HIGH,
            host=computer,
            timestamp=timestamp,
            description=desc,
            attributes=attrs,
        )

    if event_id == 7045:
        service_name = data.get("ServiceName") or "unknown"
        image_path = data.get("ImagePath") or "unknown"
        desc = f"New Windows service installed: '{service_name}' ({image_path})"
        attrs = {
            "windows_event_id": 7045,
            "channel": channel,
            "record_id": record_id,
            "service_name": service_name,
            "image_path": image_path,
            "service_type": data.get("ServiceType"),
            "start_type": data.get("StartType"),
            "account_name": data.get("AccountName"),
        }
        return SecurityEvent(
            source="windows_event_log",
            category=EventCategory.SYSTEM,
            event_type="windows_service_installed",
            severity=EventSeverity.MEDIUM,
            host=computer,
            timestamp=timestamp,
            description=desc,
            attributes=attrs,
        )

    # Generic fallback mapping for any other configured Windows Event ID
    desc = f"Windows event {event_id} observed on channel '{channel}'"
    attrs = {
        "windows_event_id": event_id,
        "channel": channel,
        "record_id": record_id,
        **data,
    }
    return SecurityEvent(
        source="windows_event_log",
        category=EventCategory.SYSTEM,
        event_type=f"windows_event_{event_id}",
        severity=EventSeverity.INFO,
        host=computer,
        timestamp=timestamp,
        description=desc,
        attributes=attrs,
    )


class WindowsEventCollector:
    """Collects security and system telemetry from Windows Event Logs using native APIs."""

    def __init__(
        self,
        repository: EventRepository | None = None,
        checkpoint_repo: CheckpointRepository | None = None,
        channels: dict[str, list[int]] | None = None,
        max_records_per_channel: int = 100,
        initial_backfill_days: int = 7,
    ) -> None:
        """Initialize WindowsEventCollector.

        Args:
            repository: Optional EventRepository for persisting SecurityEvent records.
            checkpoint_repo: Optional CheckpointRepository for persistent channel checkpoints.
            channels: Mapping of channel names to list of target event IDs.
            max_records_per_channel: Maximum number of events to read per channel per poll.
            initial_backfill_days: Recent history imported when a channel has no checkpoint.
        """
        if max_records_per_channel < 1:
            raise ValueError("max_records_per_channel must be at least 1")
        if initial_backfill_days < 1:
            raise ValueError("initial_backfill_days must be at least 1")

        self.repository = repository
        self.checkpoint_repo = checkpoint_repo
        self.channels = channels or dict(DEFAULT_CHANNELS_CONFIG)
        self.max_records_per_channel = max_records_per_channel
        self.initial_backfill_days = initial_backfill_days

        self._in_memory_checkpoints: dict[str, int] = {}
        self._processed_keys: set[tuple[str, int]] = set()
        self._permission_warned_channels: set[str] = set()
        self.health = CollectorHealth("Windows Event Log")
        self._collection_errors: list[str] = []

    def get_checkpoint(self, channel: str) -> int | None:
        """Get the last processed EventRecordID for a channel."""
        if self.checkpoint_repo is not None:
            persisted_checkpoint = self.checkpoint_repo.get_checkpoint(channel)
            in_memory_checkpoint = self._in_memory_checkpoints.get(channel)
            if self.repository is None and in_memory_checkpoint is not None:
                return max(persisted_checkpoint or 0, in_memory_checkpoint)
            return persisted_checkpoint
        return self._in_memory_checkpoints.get(channel)

    def set_checkpoint(self, channel: str, record_id: int) -> None:
        """Update the checkpoint for a channel in memory and persistent storage."""
        current = self._in_memory_checkpoints.get(channel, 0)
        self._in_memory_checkpoints[channel] = max(current, record_id)
        if self.checkpoint_repo is not None:
            self.checkpoint_repo.set_checkpoint(channel, record_id)

    def reset_checkpoint(self, channel: str) -> None:
        """Reset the channel checkpoint to 0 in memory and persistent storage."""
        self._in_memory_checkpoints[channel] = 0
        if self.checkpoint_repo is not None:
            self.checkpoint_repo.reset_checkpoint(channel)

    def _is_channel_reset(self, channel: str, last_checkpoint: int) -> bool:
        """Check if an event log channel was cleared or rolled over, resetting record IDs.

        If the newest record in the channel has an EventRecordID smaller than our stored
        checkpoint, the log has been cleared or reset.

        Args:
            channel: Target event log channel name.
            last_checkpoint: Currently recorded checkpoint record ID.

        Returns:
            bool: True if rollover/reset is detected.
        """
        if not HAS_WIN32EVTLOG:
            return False
        query = None
        raw = []
        try:
            query = win32evtlog.EvtQuery(
                channel,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                "*",
            )
            raw = win32evtlog.EvtNext(query, 1)
            if raw:
                xml_str = win32evtlog.EvtRender(raw[0], win32evtlog.EvtRenderEventXml)
                parsed = parse_event_xml(xml_str)
                if parsed and parsed["record_id"] > 0:
                    if parsed["record_id"] < last_checkpoint:
                        return True
        except Exception as err:
            logger.debug("Failed to inspect channel '%s' for rollover: %s", channel, err)
        finally:
            close_handle = getattr(win32evtlog, "EvtClose", None)
            if close_handle is not None:
                for handle in raw:
                    close_handle(handle)
                if query is not None:
                    close_handle(query)
        return False

    def collect_events(self) -> list[SecurityEvent]:
        """Perform a single read-only event collection cycle across configured channels.

        Extracts new events, normalizes them into SecurityEvents, updates checkpoints,
        and persists them atomically to the EventRepository.

        Returns:
            list[SecurityEvent]: Newly captured and normalized security events.
        """
        all_new_events: list[SecurityEvent] = []
        self._collection_errors = []
        if not HAS_WIN32EVTLOG:
            message = "pywin32 is not available on this platform"
            self.health.mark_unavailable(message)
            logger.warning(message)
            return []

        for channel, event_ids in self.channels.items():
            if not event_ids:
                continue
            try:
                channel_events = self._collect_channel(channel, event_ids)
                all_new_events.extend(channel_events)
            except Exception as err:
                self._collection_errors.append(f"{channel}: {err}")
                logger.exception("Windows Event Log collection failed for channel '%s'.", channel)

        error = "; ".join(self._collection_errors) or None
        self.health.record(len(all_new_events), error)
        return all_new_events

    def _collect_channel(self, channel: str, event_ids: list[int]) -> list[SecurityEvent]:
        """Collect events from a single channel using native EvtQuery."""
        last_checkpoint = self.get_checkpoint(channel)

        # Check for event log rollover / reset
        if last_checkpoint is not None and last_checkpoint > 0:
            if self._is_channel_reset(channel, last_checkpoint):
                logger.warning(
                    "Event log reset/rollover detected on channel '%s' (newest record < checkpoint %d). Resetting checkpoint.",
                    channel,
                    last_checkpoint,
                )
                self.reset_checkpoint(channel)
                last_checkpoint = None

        initial_import = last_checkpoint is None or last_checkpoint <= 0
        initial_cutoff = (
            datetime.now(timezone.utc) - timedelta(days=self.initial_backfill_days)
            if initial_import else None
        )
        xpath = _build_query_xpath(event_ids, last_checkpoint, initial_cutoff)
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection

        try:
            query_handle = win32evtlog.EvtQuery(channel, flags, xpath)
        except Exception as err:
            # Handle Access Denied (error code 5) or missing channel gracefully.
            # This environment can legitimately deny Security log access, so warn once per channel
            # instead of spamming the log on every collection cycle.
            if channel not in self._permission_warned_channels:
                logger.warning(
                    "Unable to query Windows Event Log channel '%s' (Access/Channel limitation): %s",
                    channel,
                    err,
                )
                self._permission_warned_channels.add(channel)
            self._collection_errors.append(f"{channel}: {err}")
            return []

        imported_events: list[SecurityEvent] = []
        try:
            while True:
                try:
                    raw_events = win32evtlog.EvtNext(
                        query_handle, self.max_records_per_channel
                    )
                except Exception as err:
                    self._collection_errors.append(f"{channel}: {err}")
                    logger.warning("Failed to fetch records from channel '%s': %s", channel, err)
                    break

                if not raw_events:
                    break

                xml_records: list[str] = []
                render_failed = False
                close_handle = getattr(win32evtlog, "EvtClose", None)
                try:
                    for handle in raw_events:
                        try:
                            xml_records.append(
                                win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                            )
                        except Exception as err:
                            self._collection_errors.append(f"{channel} render: {err}")
                            logger.debug(
                                "Failed to render event handle on channel '%s': %s",
                                channel,
                                err,
                            )
                            render_failed = True
                            break
                finally:
                    if close_handle is not None:
                        for handle in raw_events:
                            close_handle(handle)

                errors_before_batch = len(self._collection_errors)
                try:
                    imported_events.extend(self.process_xml_records(channel, xml_records))
                except Exception as err:
                    self._collection_errors.append(f"{channel} persistence: {err}")
                    logger.exception(
                        "Failed to persist an event batch from channel '%s'.", channel
                    )
                    break

                if render_failed or len(self._collection_errors) > errors_before_batch:
                    break
        finally:
            close_handle = getattr(win32evtlog, "EvtClose", None)
            if close_handle is not None:
                close_handle(query_handle)

        return imported_events

    def process_xml_records(self, channel: str, xml_records: Sequence[str]) -> list[SecurityEvent]:
        """Process and normalize raw XML records, ensuring atomic persistence and checkpoint advancement.

        Guarantees that:
        1. Malformed events do not cause valid events to be skipped.
        2. Checkpoint never advances beyond successfully persisted events.
        3. Event insertion and checkpoint update occur atomically in a single SQLite transaction.

        Args:
            channel: The channel name.
            xml_records: List of raw event XML strings.

        Returns:
            list[SecurityEvent]: Validated, deduplicated SecurityEvent instances.
        """
        new_events: list[SecurityEvent] = []
        new_record_keys: list[tuple[str, int]] = []
        current_checkpoint = self.get_checkpoint(channel) or 0
        highest_persisted_id = current_checkpoint

        for xml_str in xml_records:
            parsed = parse_event_xml(xml_str)
            if parsed is None:
                self._collection_errors.append(
                    f"{channel}: malformed event XML blocked checkpoint advancement"
                )
                break

            record_id = parsed["record_id"]
            if record_id <= 0:
                self._collection_errors.append(
                    f"{channel}: invalid event record ID blocked checkpoint advancement"
                )
                break
            record_key = (channel, record_id)

            # Deduplication: check session keys and record checkpoint
            if record_key in self._processed_keys:
                continue
            if current_checkpoint > 0 and record_id <= current_checkpoint:
                continue

            try:
                event = normalize_event(parsed)
                new_events.append(event)
                new_record_keys.append(record_key)
                # Only advance highest_persisted_id for successfully normalized events
                if record_id > highest_persisted_id:
                    highest_persisted_id = record_id
            except Exception as err:
                logger.warning("Failed to normalize event record %s: %s", record_id, err)
                self._collection_errors.append(
                    f"{channel}: record {record_id} normalization failed"
                )
                break

        # Atomic persistence and checkpoint advancement
        if self.repository is not None:
            self.repository.save_events_with_checkpoint(
                new_events,
                channel,
                highest_persisted_id if highest_persisted_id > current_checkpoint else 0,
            )

        # Update in-memory tracking only after successful persistence
        self._processed_keys.update(new_record_keys)
        if highest_persisted_id > current_checkpoint:
            self._in_memory_checkpoints[channel] = highest_persisted_id

        return new_events
