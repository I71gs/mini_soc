# Mini SOC Project Status Report

## Project summary

Mini SOC is a local-first, single-user Windows SOC MVP. It collects selected process, network, and Windows Event Log telemetry; stores normalized events and incidents in SQLite; evaluates heuristic detection rules; and provides a PySide6 interface for investigation and triage.

The project is suitable for development, demonstration, and authorized local monitoring. It is not a certified endpoint detection product: detections are heuristics, telemetry can be incomplete, and the application does not provide authentication, role-based access, encryption at rest, or automated containment.

## Implemented capabilities

| Area | Current implementation |
|---|---|
| Configuration | `AppConfig` resolves per-user storage paths, supports an absolute `MINISOC_DATA_DIR` override, and defaults event retention to 90 days. |
| Event model | Pydantic `SecurityEvent` schema with UUID identifiers, timezone-aware UTC timestamps, validated fields, and source-specific attributes. |
| Host telemetry | `psutil` process and network collectors emit events for newly observed activity. The GUI monitor polls every five seconds by default and isolates collector failures. |
| Windows Event Logs | Reads Security IDs 4624, 4625, 1102 and System ID 7045 through pywin32. New channels backfill up to seven days; persistent record-ID checkpoints support incremental reads and retry after failures. |
| Persistence | Versioned SQLite schema (currently version 4), repositories for events, incidents, checkpoints, and detection review state, with transactional event/checkpoint updates. |
| Detection | Four heuristic rules are enabled by the default engine; their scopes and known limitations are listed below. |
| Incident workflow | Alerts can be persisted as deduplicated incidents. Status, analyst notes, reviewed-alert state, and related event IDs are retained. |
| Desktop UI | Overview, Events, Detections, Incidents, and Settings views; database-backed paging, filters, evidence navigation, health diagnostics, and CSV export. |
| Reporting | Event and incident CSV/JSON exports and a JSON summary. JSON and UI detail views redact values under sensitive-keyed fields; CSV output neutralizes spreadsheet formula prefixes. |
| Backup and migration | SQLite online backups refuse to overwrite an existing destination and perform an integrity check. A historical repository-local database is copied, not deleted, when initializing a configured database that does not yet exist. |

## Detection coverage

All rules evaluate collected event metadata. Alerts identify activity for analyst review; they do not prove compromise.

| Rule | Scope and severity | Important limitation |
|---|---|---|
| `suspicious_process` | Selected command-line patterns for `cmd.exe`, PowerShell, and administrative/dual-use tools; HIGH. | Legitimate administration and support activity can match. |
| `possible_keylogger` | Process-start name, executable path, or command line contains an explicit keylogger marker or configured keyboard-capture API/library indicator; MEDIUM. Indicators include `SetWindowsHookEx`, `GetAsyncKeyState`, `pynput.keyboard`, `keyboard.hook`, and `keyboard.listener`. | Metadata matching does not observe runtime hooks, inspect memory, or establish that keystrokes are captured. Accessibility and automation tools may match. |
| `failed_logon_spike` | Three or more failed Windows logons within ten minutes grouped by host, account, and valid source IP; HIGH. | Events with missing/placeholder attribution or invalid IP addresses are excluded. User error and automated clients can also cause spikes. |
| `suspicious_network` | Established connections to selected service ports on globally routable remote IP addresses; MEDIUM. | The collector does not establish connection direction or malicious intent; common service ports can be benign. |

The keylogger rule is defensive process-metadata detection only. Mini SOC does not record keyboard input. Positive and benign detection cases are in `tests/test_detection.py`.

## Data flow and operations

1. `main.py` initializes configuration and SQLite, applies event retention, and collects telemetry. Without arguments it runs one headless collection cycle; `--gui` starts the desktop application.
2. The collectors normalize observations to `SecurityEvent` records and persist them through repositories.
3. The detection engine evaluates events and emits `DetectionAlert` records. The headless run evaluates up to the latest 500 stored events; the GUI loads evidence for rules independently of the currently displayed event page.
4. The incident manager persists alerts as incidents and reuses an existing incident for a previously seen alert fingerprint.
5. In GUI mode, background collection runs at the configured interval, the dashboard refreshes every 30 seconds, and **Poll Sensors** requests an immediate collection cycle.

By default on Windows, the database is `%LOCALAPPDATA%\Mini SOC\minisoc.db` and logs are under `%LOCALAPPDATA%\Mini SOC\logs`. Set `MINISOC_DATA_DIR` to an absolute path to change the storage root. Existing data in the historical `<project_root>\data\minisoc.db` is copied only when the configured database does not exist; the source database is preserved.

## Security and known limitations

- The application has no web server, cloud API, built-in user authentication, or roles. Windows account permissions and filesystem ACLs are the access boundary.
- The database, logs, backups, and exports are not encrypted by Mini SOC. Protect their directories and files with OS permissions; handle exported files separately from database retention.
- The process collector masks values for common inline credential switches, and sensitive-keyed fields are redacted in supported JSON/logging/detail paths. Redaction is best-effort; arbitrary secrets embedded in free text may remain.
- Process and network collectors establish an in-memory baseline at startup, so already-running processes and connections are not emitted as new events. Short-lived activity between polls and data hidden by Windows permissions can be missed.
- Windows Event Log access depends on channel ACLs, account privileges, and local policy. Collector health reports errors and visibility restrictions but cannot guarantee complete OS telemetry.
- Event retention removes events older than the configured period at application startup. Incidents can remain after supporting events expire. Backups and exports are not automatically deleted.
- The GUI requests UAC elevation only for a UAC-filtered administrator token; declining continues with standard-user visibility. Headless mode does not request elevation.
- The application does not automatically isolate hosts, terminate processes, block connections, or remediate incidents.

Run Mini SOC only on systems you are authorized to monitor. Before deployment, verify effective Windows permissions, storage ACLs, backup/restore procedures, retention expectations, and export handling on the target host.

## Tests and validation

The test suite covers configuration, event validation, SQLite repositories and migrations, collectors, detection, incident workflows, reporting, security helpers, CLI startup, and offscreen UI behavior. Collector and UI tests use mocks or temporary data for most cases; they do not establish live telemetry coverage on another Windows host.

Run the suite from the repository root:

```powershell
py -3 -m pytest -q
```

During this documentation update, the full run reported **162 passed**, but the Python process then exited with Windows code `-1073740791` instead of a clean zero exit. Treat the run as unresolved and repeat it in CI or a clean environment before claiming a successful full-suite validation. The focused detection tests completed with **13 passed**.

## Release acceptance checklist

- Run the full test suite and confirm a zero exit status.
- Perform a clean installation and headless startup on a supported Windows host.
- Verify collector behavior under the intended standard-user account and, only where authorized, the intended Windows Event Log permissions.
- Test database backup and restore, legacy database migration, event retention, and export handling using disposable data.
- Review ACLs for the database, logs, backups, and exported files.
- Describe the product as an MVP with heuristic detections unless broader platform, telemetry, and operational testing has been completed.
