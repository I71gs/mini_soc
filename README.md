# Mini SOC

A standalone, local-first Security Operations Center (SOC) application tailored for Windows environments. Mini SOC provides lightweight, local host and network telemetry aggregation, suspicious activity detection, incident alerting, and guided investigation workflows — all running entirely on the local machine without external cloud dependencies.

---

## 1. Project Overview

Mini SOC is designed to run locally on a Windows workstation or server. It focuses on:
- **Local-first Operation**: All data, events, and telemetry stay on the local system.
- **Privacy & Security**: Zero telemetry phone-home, no credentials stored in configuration, and strict permission boundaries.
- **Standardized Telemetry**: A unified, validated security event schema across heterogeneous data collectors (host event logs, process execution, network connections).
- **Incident Lifecycle**: From raw event collection to rule-based detection, incident triage, and controlled response actions.
- **Analyst Console**: A PySide6 desktop dashboard for reviewing events, triaging detections, managing incidents, and exporting reports.

---

## 2. Architecture

The project follows a modular, decoupled architecture:

```
+─────────────────────────────────────────────────────────────+
│                          Mini SOC                           │
+─────────────────────────────────────────────────────────────+
│ [PySide6 Desktop Console]                                   │
│  Overview · Events · Detections · Incidents · Settings      │
+──────────────────────────┬──────────────────────────────────+
│ [Detection Engine]       │ [Incident Management]            │
│  Rule evaluation, alerts │  Triage, status lifecycle, notes │
+──────────────────────────┼──────────────────────────────────+
│ [Collectors]                                                │
│  Process Monitor · Network Monitor · Windows Event Logs     │
+─────────────────────────────────────────────────────────────+
│ [Core Foundation]                                           │
│  SecurityEvent (Pydantic v2) · AppConfig · SQLite Persist.  │
+─────────────────────────────────────────────────────────────+
```

### Core Components
- **`AppConfig`** (`src/core/config.py`): Centralized configuration. Resolves all paths relative to the project root, safely ensures data/log directories exist, stores no secrets.
- **`SecurityEvent`** (`src/core/events.py`): Pydantic v2 model with UUIDv4, UTC timestamps, severity enums, extensible attributes, bidirectional JSON & SQLite serialization.
- **`DatabaseManager`** (`src/database/connection.py`): SQLite connection management with foreign keys, timeouts, parameterized queries, and transaction support.
- **`EventRepository`** (`src/database/event_repository.py`): CRUD and filtered querying for security events.
- **`DetectionEngine`** (`src/detection/rules.py`): Rule-based evaluation for suspicious processes, failed logon spikes, and risky outbound connections.
- **`IncidentManager`** (`src/incidents/manager.py`): Alert-to-incident conversion, status lifecycle, and analyst notes.

---

## Backend Concepts

This section explains the serverless/backend implementation in Mini SOC. "Backend" in this project means the local Python collection, normalization, persistence, detection, and incident-processing layers; it does not mean a web server or cloud service.

### End-to-End Data Flow

1. **Bootstrap** - `main.py` creates the application configuration, opens or initializes the SQLite database, and initializes the schema.
2. **Collection** - the Windows Event Log collector and host monitoring service read local telemetry.
3. **Normalization** - each source is converted into a Pydantic `SecurityEvent` with a consistent field contract.
4. **Persistence** - repositories serialize events and incidents to SQLite using parameterized queries and transactions.
5. **Detection** - `DetectionEngine` evaluates a snapshot of stored events with independent rule classes.
6. **Incident management** - a detection alert can be converted into an `Incident`, then triaged and persisted.
7. **Presentation** - the PySide6 window reads the repositories and cached backend state to update dashboard views and exports.

```text
Windows Event Log / psutil
            |
            v
Collector -> SecurityEvent -> EventRepository -> SQLite
                                  |
                                  v
                          DetectionEngine
                                  |
                                  v
                         DetectionAlert
                                  |
                                  v
                         IncidentManager -> IncidentRepository
```

### Application Entry Points

- `main.py` is the primary entry point.
  - Running it without arguments executes one headless collection/detection cycle.
  - Running it with `--gui` starts the PySide6 desktop application.
- `src/ui/app.py::run_app()` initializes configuration and SQLite, creates `MainWindow`, and starts the Qt event loop.
- `src/ui/main_window.py::MainWindow` owns the desktop application's backend wiring. It creates repositories, the host monitor, the Windows Event Log collector, the detection engine, and the incident manager.
- In GUI mode, manual **Poll Sensors** performs a collection cycle. The Qt UI also refreshes database-backed views every 30 seconds without automatically starting a new sensor poll.

### Configuration and Paths

`AppConfig` in `src/core/config.py` centralizes runtime paths and metadata:

| Setting | Default | Purpose |
|---|---|---|
| `app_name` | `Mini SOC` | Application display name |
| `version` | `0.1.0` | Application version |
| `project_root` | Directory containing the repository | Base directory for all relative storage |
| `data_dir` | `<project_root>/data` | Local application storage |
| `database_path` | `<project_root>/data/minisoc.db` | SQLite database |
| `log_dir` | `<project_root>/data/logs` | Operational log files |

Relative paths are resolved against `project_root`, and absolute paths must remain inside the project root. This blocks path traversal and ensures that custom storage locations do not escape the application directory. `ensure_directories()` creates the data and log directories. App configuration does not contain credentials or remote endpoints.

### Security Event Contract

`SecurityEvent` in `src/core/events.py` is the canonical backend event model.

| Field | Type | Meaning |
|---|---|---|
| `event_id` | UUID | Unique event identity; generated with UUIDv4 |
| `timestamp` | timezone-aware `datetime` | UTC event time |
| `source` | string | Collector or source, for example `process_collector` or `windows_event_log` |
| `category` | `EventCategory` or string | Domain such as PROCESS, NETWORK, AUTHENTICATION, or SYSTEM |
| `event_type` | string | Stable action name such as `process_started` or `windows_logon_failed` |
| `severity` | `EventSeverity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `host` | string | Hostname or Windows computer name |
| `description` | string | Human-readable event summary |
| `attributes` | dictionary | Source-specific metadata, fields, IDs, paths, IPs, accounts, and ports |
| `schema_version` | string | Event contract version; currently `1.0` |

Pydantic validates event fields when a `SecurityEvent` is created or loaded. Empty source, host, event type, description, and schema strings are rejected. Category and severity values are normalized to uppercase. Naive timestamps are rejected and timezone-aware timestamps are converted to UTC. UUID, enum, datetime, and nested attribute values are converted to SQLite/JSON primitives by `to_db_record()` and reconstructed by `from_db_record()`.

### Collector Concepts

#### Process Collector

`ProcessCollector` uses `psutil.process_iter()` to snapshot running Windows processes. It records PID, executable name, creation time, executable path, and username where accessible.

The process key is `(PID, create_time)`. This combination avoids treating normal PID reuse as the same process instance. The collector maintains an in-memory set of known process keys:

- on the first snapshot, processes are compared against an empty set or an explicit baseline;
- an instance not in the known set produces a `process_started` event;
- the known set is replaced with the current snapshot after each cycle.

Protected or disappeared processes are skipped without crashing the collection cycle. Access-denied executable or username details are left as `None`.

#### Network Collector

`NetworkCollector` uses `psutil.net_connections(kind="inet")` to snapshot Internet-family sockets. It normalizes IPv4/IPv6 and TCP/UDP protocol names and records local/remote endpoints, status, and associated PID.

A connection key includes protocol, local address and port, remote address and port, and PID. The first unseen key emits `network_connection_observed`. Baseline initialization and subsequent polling prevent the same connection key from being reported repeatedly within a single in-memory monitoring session.

Listening sockets and other malformed or inaccessible entries are handled defensively; access-denied socket enumeration produces no events for that cycle rather than stopping the application.

#### Windows Event Log Collector

`WindowsEventCollector` uses pywin32 native EvtQuery/EvtNext/EvtRender APIs. The default channels and event IDs are:

| Channel | IDs | Normalized result |
|---|---:|---|
| Security | 4624 | Successful Windows logon |
| Security | 4625 | Failed Windows logon |
| Security | 1102 | Security audit log cleared |
| System | 7045 | Windows service installed |

Raw event XML is parsed for the system header and named `EventData` values, then normalized into the common `SecurityEvent` model. The default initial poll reads up to 100 records per channel in reverse direction, reverses them to chronological order, and advances a persistent checkpoint. Later polls use the checkpoint and forward direction.

A channel checkpoint is the highest successfully processed Windows `EventRecordID`, not a wall-clock timestamp. The collector detects channel reset/rollover by comparing the newest record ID with the stored checkpoint. Missing channels and denied access are reported once per channel and collection continues with other sources.

#### Host Monitoring Orchestration

`HostMonitorService` coordinates process and network collection. It supports one collection cycle or a daemon polling loop at a configurable interval (5 seconds by default). Each collector is invoked independently, so an exception in one does not prevent the other from running. `start()` and `stop()` provide thread lifecycle control, and `stop()` waits up to a configurable timeout.

### SQLite Persistence

`DatabaseManager` opens a short-lived SQLite connection for every repository operation. Connections enable foreign-key enforcement, use `sqlite3.Row`, have a 10-second busy timeout, commit successful operations, roll back exceptions, and close reliably.

The database is located at `data/minisoc.db` by default. It is a file-backed local database; tests can use `:memory:` databases.

#### Schema and Migrations

The schema is versioned in the `schema_version` table. `initialize_database()` safely applies missing migrations without overwriting existing records.

| Version | Tables/Indexes added | Purpose |
|---:|---|---|
| 1 | `security_events`, event indexes, `schema_version` | Core normalized telemetry |
| 2 | `event_log_checkpoints` | Per-channel Windows Event Log positions |
| 3 | `incidents`, incident indexes | Persisted analyst cases |

`security_events` stores every normalized event as primitive values. JSON in the `attributes` column preserves source-specific fields. Its indexes support timestamp, severity, source, and event-type queries.

`event_log_checkpoints` maps channel names to `last_record_id` and update time. It prevents replay of already processed Windows events across application restarts.

`incidents` stores title, description, severity, status, source, related event IDs, attributes, notes, and creation time. JSON columns preserve event IDs, attributes, and analyst notes.

#### Repositories

Repositories are the boundary between domain objects and SQLite:

- `EventRepository` inserts individual/batched events, atomically inserts events with checkpoints, retrieves by UUID, counts records, and lists filtered events newest-first.
- `CheckpointRepository` gets, updates, lists, and resets per-channel record IDs.
- `IncidentRepository` inserts or updates incidents, retrieves one incident, lists incidents by status, and updates incident state.

The repository API uses named or positional parameters instead of interpolating user input into SQL. Event and incident JSON fields are converted explicitly before database storage.

### Atomic Event/Checkpoint Transactions

Windows Event Log ingestion is checkpointed atomically. `save_events_with_checkpoint()` inserts all normalized events and updates the channel checkpoint in the same SQLite transaction. If event insertion or checkpoint update fails, the transaction is rolled back.

The collector also maintains an in-session record-key set and checks the persisted checkpoint, providing duplicate protection even if the same record arrives during repeated reads. The persisted checkpoint advances only to the highest successfully normalized and inserted record.

### Detection Engine

`DetectionEngine` combines a sequence of independent `DetectionRule` implementations and flattens their `DetectionAlert` results. The default engine contains three rules:

#### Suspicious Process Rule

The rule examines `process_started` events and flags names in a built-in set of administrative or abuse tools, including `rundll32.exe`, `regsvr32.exe`, `wmic.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `netsh.exe`, `bcdedit.exe`, and `psexec.exe`.

It also applies command-pattern checks for `cmd.exe` and PowerShell. The alert severity is `HIGH`, and the original event UUID is attached through `related_event_ids`.

#### Failed Logon Spike Rule

The rule scans `windows_logon_failed` events, groups them by `account_name`, and raises one `HIGH` alert when an account has at least three failures in the current observation window. The alert links every grouped event and includes the account name and failed count.

The observation window is the event snapshot supplied to `DetectionEngine`, not a continuously scheduled rolling-time rule. In GUI mode this is controlled by the selected Overview timeframe.

#### Suspicious Outbound Rule

The rule examines `network_connection_observed` events with a remote IP and remote port. It flags external destinations on risky service ports such as 22, 23, 3389, 445, 4444-4446, 8080, and 8443. Loopback and common private IPv4 ranges are excluded. The alert severity is `MEDIUM`.

Alerts are not a verdict: they identify patterns requiring analyst validation and are converted only to incidents when the analyst acts or when GUI startup/refresh finds no existing incident set and alerts are present.

### Incident Model and Lifecycle

An `Incident` is a triage case created from one or more detection alerts. It contains a UUID, title, description, severity, status, source, related event IDs, attributes, analyst notes, and UTC creation time.

The supported workflow is:

```text
open -> investigating -> mitigated -> resolved
```

`IncidentManager`:

- converts `DetectionAlert` objects into `Incident` objects;
- stores new incidents through `IncidentRepository`;
- hydrates incidents from SQLite;
- updates status in memory and SQLite;
- appends analyst notes and persists the complete incident.

The manager does not own an automated containment or remediation system. Incident status and notes represent analyst workflow only.

### Reporting and Export

`ReportingExporter` creates common artifacts for analyst use:

- event CSV (core event fields);
- incident CSV (core incident fields);
- event JSON (including `attributes`);
- incident JSON (including attributes and notes);
- summary JSON (event severity, incident severity, incident status, and generated time).

Parent directories are created automatically for export destinations.

### Security and Logging

The backend has multiple defensive measures:

- no network API server, cloud telemetry, secrets store, or remote credential configuration;
- storage paths are restricted to the project root;
- SQLite uses parameterized statements;
- timestamps are normalized and event fields are validated;
- local log entries are sanitized with `redact_sensitive_data()`;
- sensitive key names containing password, secret, token, API key, authorization, cookie, session, JWT, private key, or access key are replaced with `[REDACTED]`;
- collector exceptions are isolated so a process, network, or Windows channel failure does not crash the application.

Operational logs are written to `data/logs/minisoc.log`. The backend uses an INFO-level project logger by default, with file-only logging in the normal application process.

### GUI-to-Backend Synchronization

`MainWindow.refresh_all_data()` is the main GUI synchronization method:

1. optionally polls process, network, and Windows Event Log collectors;
2. loads up to 500 events for the selected 1-hour, 24-hour, 7-day, or all-time timeframe;
3. evaluates the detection engine over that event snapshot;
4. loads or creates in-memory incidents;
5. refreshes overview metrics, event/detection grids, incident panels, and settings diagnostics;
6. updates the last-synchronization timestamp.

The UI caches the latest backend snapshot for fast view updates. Repositories remain the source of persistence and can be queried directly by the same application components.

### Backend Extension Guide

To add a new telemetry source:

1. create a collector that produces `SecurityEvent` instances;
2. add source/category-specific fields to `attributes`;
3. persist batches through `EventRepository`;
4. wire the collector into `HostMonitorService` or `MainWindow`;
5. add tests for collection, normalization, persistence, and failure handling.

To add a detection rule:

1. subclass `DetectionRule`;
2. set `name`, `description`, and `severity`;
3. implement `evaluate(events)` and return `DetectionAlert` objects;
4. link relevant event UUIDs through `related_event_ids`;
5. pass the rule into `DetectionEngine` or add it to the default rule list;
6. add positive and false-positive test cases.

SQLite schema changes should create a new migration version in `schema.py` and a corresponding table/repository test. Existing event and incident fields should not be renamed in place without migration and deserialization compatibility.

---

## 3. Project Directory Structure

```
mini-soc/
├── main.py                         # Entry point: headless (default) or --gui
├── requirements.txt                # Production and testing dependencies
├── README.md
├── data/                           # Local storage (SQLite database, logs)
│   └── .gitkeep
├── src/
│   ├── __init__.py
│   ├── core/
│   │   ├── config.py               # AppConfig
│   │   ├── events.py               # SecurityEvent model and enums
│   │   ├── logging_utils.py        # Operational and sanitized logging
│   │   └── security.py             # Redaction and safe path validation
│   ├── collectors/
│   │   ├── process_collector.py     # Windows process monitor (psutil)
│   │   ├── network_collector.py     # Network connection monitor (psutil)
│   │   ├── windows_event_collector.py  # Windows Event Log reader (pywin32)
│   │   └── monitor_service.py       # Orchestrator: HostMonitorService
│   ├── database/
│   │   ├── connection.py            # DatabaseManager
│   │   ├── schema.py               # Versioned schema migrations
│   │   ├── event_repository.py     # Event persistence
│   │   ├── checkpoint_repository.py # Event log checkpoint tracking
│   │   └── incident_repository.py  # Incident persistence
│   ├── detection/
│   │   └── rules.py                # DetectionEngine + built-in rules
│   ├── incidents/
│   │   ├── models.py               # Incident dataclass
│   │   └── manager.py              # IncidentManager
│   ├── reporting/
│   │   └── exporter.py             # CSV, JSON, and summary exporters
│   └── ui/
│       ├── app.py                  # run_app() PySide6 entry point
│       ├── main_window.py          # MainWindow shell with sidebar + header
│       ├── styles.py               # Dark cybersecurity theme and palette
│       ├── components/
│       │   ├── severity_badge.py   # SeverityBadge & StatusBadge widgets
│       │   └── status_card.py      # Metric summary card
│       └── views/
│           ├── overview_view.py    # Dashboard overview with status cards
│           ├── events_view.py      # Telemetry browser with filters & inspector
│           ├── detections_view.py  # Detection alerts with triage actions
│           ├── incidents_view.py   # Incident management panel
│           └── settings_view.py    # Diagnostics and configuration view
└── tests/
    ├── test_config.py
    ├── test_events.py
    ├── test_database.py
    ├── test_process_collector.py
    ├── test_network_collector.py
    ├── test_windows_event_collector.py
    ├── test_detection.py
    ├── test_reporting.py
    ├── test_security.py
    └── test_ui.py                  # PySide6 UI tests (offscreen)
```

---

## 4. Getting Started

### Prerequisites
- **Windows 10/11**
- **Python 3.12 or newer** (tested on Windows 11 with Python 3.14)
- **Git** to clone the repository

### Quick setup (Windows PowerShell)
```powershell
git clone https://github.com/I71gs/mini_soc.git
cd mini_soc
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

You do not need to activate the virtual environment when using the commands below; they call its Python executable directly. If you prefer to activate it in PowerShell, run:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, continue using `.venv\Scripts\python.exe` as shown above.

### Try the desktop app

```powershell
.venv\Scripts\python.exe main.py --gui
```

### Run the headless collection check

```powershell
.venv\Scripts\python.exe main.py
```

The first run initializes a local SQLite database at `data\minisoc.db` and creates local logs under `data\logs`. The app does not send telemetry to a cloud service. The headless run collects available host telemetry and attempts to read configured Windows Event Log channels.

> **Windows permissions:** Windows may deny access to the Security Event Log when the app is run as a standard user. The app should still start; Security log collection will be unavailable in that session. Run with the required Windows permissions only if you need to test that source, and only on a machine you are authorized to monitor.

#### Dependencies
| Package | Purpose |
|---|---|
| `pydantic>=2.0.0` | Data validation and serialization for event contracts |
| `psutil>=5.9.0` | Process and network telemetry collection |
| `pywin32>=306` | Windows Event Log API access |
| `PySide6>=6.5.0` | Desktop GUI framework |
| `pytest>=7.0.0` | Automated test runner |

---

## 5. Running the Application

The quick-start commands above use the project virtual environment. If you activated it, you can use `python` instead of `.venv\Scripts\python.exe`.

### Headless Mode
Collect available telemetry, run detection rules, and print a summary to the console:

```powershell
.venv\Scripts\python.exe main.py
```

### Desktop GUI Mode
Launch the PySide6 security console:

```powershell
.venv\Scripts\python.exe main.py --gui
```

Or launch the UI module directly:

```powershell
.venv\Scripts\python.exe -m src.ui.app
```

### Desktop Console Features
- **Overview**: Status cards (events, detections, incidents, health), host summary, timeframe filters (1h / 24h / 7d / All), recent activity and detections tables.
- **Events**: Full telemetry browser with severity, source, category, and text filters. Sortable columns, JSON inspector, copy-to-clipboard, CSV export.
- **Detections**: Rule-based alerts with mark-as-reviewed, create-incident, open-related-event, severity/rule/status filters, CSV export.
- **Incidents**: Lifecycle management (open → investigating → mitigated → resolved), analyst notes, related event navigation.
- **Settings**: Environment paths, database health, schema version, record counts, checkpoint metadata, sensor status.

### Screenshots

| Overview | Events |
|---|---|
| ![Mini SOC overview](screenshots/overview.png) | ![Mini SOC events](screenshots/events.png) |

| Detections | Incidents |
|---|---|
| ![Mini SOC detections](screenshots/detections.png) | ![Mini SOC incidents](screenshots/incidents.png) |

---

## 6. Running Tests

```powershell
.venv\Scripts\python.exe -m pytest -v
```

Run a specific test file:

```powershell
.venv\Scripts\python.exe -m pytest -v tests/test_ui.py        # PySide6 desktop UI tests
.venv\Scripts\python.exe -m pytest -v tests/test_database.py  # SQLite persistence tests
.venv\Scripts\python.exe -m pytest -v tests/test_detection.py # Detection engine tests
```

The tests use mocks and temporary databases for most collector and persistence checks; they do not require access to a real Security Event Log. The UI tests run without needing to open the desktop window.

The suite covers configuration, events, database, collectors, detection, reporting, security, and UI. The test count can change as tests are added.

---

## 7. Implementation Status

| Feature / Component | Status | Details |
|---|---|---|
| Project Structure | ✅ Complete | Modular package skeleton: core, collectors, database, detection, incidents, ui |
| Central Configuration | ✅ Complete | Deterministic path resolution, data/log directory creation, zero secrets |
| Security Event Model | ✅ Complete | Pydantic v2 `SecurityEvent` with UUIDv4, UTC enforcement, extensible attributes |
| SQLite Persistence | ✅ Complete | Versioned schema, indexes, checkpoints, EventRepository, IncidentRepository |
| Host Telemetry Collectors | ✅ Complete | Process and network connection collectors with deduplication |
| Windows Event Log Collector | ✅ Complete | Security & System logs (IDs 4624, 4625, 1102, 7045), persistent checkpoints |
| Monitoring Orchestrator | ✅ Complete | HostMonitorService for polling with error isolation |
| Detection Engine | ✅ Complete | 3 rules: suspicious processes, failed logon spikes, risky outbound ports |
| Incident Workflow | ✅ Complete | Alert → Incident conversion, status lifecycle, analyst notes, SQLite persistence |
| Reporting & Export | ✅ Complete | CSV and JSON export for events, incidents, and summaries |
| Desktop Console (PySide6) | ✅ Complete | 5-view dashboard with dark theme, severity badges, filters, triage actions, CSV export |
| Automated Test Suite | ✅ Complete | Tests cover all subsystems including UI tests |
