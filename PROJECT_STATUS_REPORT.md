# Mini SOC Project Status Report

## Executive summary

Mini SOC is a local-first, single-user Windows desktop SOC MVP. The codebase now covers event collection and normalization, SQLite persistence, rule-based detections, deduplicated incidents, analyst review state, event exports, and PySide6 investigation workflows.

The workflow gaps identified during review have been addressed in code and regression tests. This is not yet a production certification: the changes were validated with automated tests, not with live standard-user and authorized elevated Windows telemetry or a clean-install acceptance run.

## Architecture and data flow

1. `main.py` or the GUI bootstrap loads `AppConfig`, initializes the SQLite schema, and applies configured event retention.
2. The Windows Event Log collector reads configured Security/System event IDs and uses persistent record-ID checkpoints. Host collectors capture process and network observations through `psutil`.
3. Collectors normalize observations into `SecurityEvent` records and persist them through repositories.
4. The detection engine evaluates the selected event snapshot and creates stable alert identities.
5. Incidents persist status, notes, alert fingerprints, and related evidence IDs. Detection review state is persisted independently.
6. The desktop UI presents Overview, Events, Detections, Incidents, and Settings views; exports provide CSV/JSON reporting.

There is no web server, cloud API, built-in authentication, role system, or automated containment. Local OS account and filesystem protections are the access boundary.

## Workflow and reliability improvements

- Events and detections distinguish no telemetry observed from no activity; collector diagnostics show last successful collection time, current errors/restrictions, and known coverage limitations.
- Events and incidents use SQLite-backed pages of 100 records, removing the previous 500-record retrieval ceilings. Per-event detections query their required event types in batches of 500 independently of the visible page; failed-logon correlation loads its complete 10-minute window.
- Opening an incident's supporting event switches the event browser to All Time and directly resolves the event, including evidence older than the default page/time window. Missing or expired evidence is identified.
- Stable detection fingerprints support persistent review decisions and prevent repeated scans from creating duplicate incidents.
- Incident notes and status changes persist. Incident details include a chronological evidence timeline.
- Windows Event Log checkpoint updates and event inserts remain transactional; failed collection attempts do not silently advance checkpoints.
- A new channel backfills matching events from the preceding seven days in ascending batches of up to 100; read/render/normalization/persistence failures leave the cursor at the last committed batch for retry.
- The GUI starts a serialized background collection loop for process, network, and Windows Event Log telemetry at five-second intervals and stops it when the window closes. Dashboard data refreshes every 30 seconds; **Poll Sensors** requests an immediate additional cycle.
- The GUI requests UAC elevation at startup from a UAC-filtered administrator token to improve process metadata access; declining continues in standard-user mode. It does not persist elevated privileges, and protected Windows processes may remain inaccessible. Process field restrictions are reported as limited visibility, not as a failed collection cycle.
- Process and network collectors retain the low-noise startup baseline policy: existing processes/connections are not emitted as events. The UI explicitly reports this blind spot, polling gaps, and possible Windows permission restrictions; a successful poll is not presented as complete coverage.
- Event retention defaults to 90 days. Incident records can outlive event evidence; exports are not automatically expired.
- Common credential command-line switches are masked, sensitive-keyed fields are redacted in displays/exports, and CSV formula cells are neutralized. These protections are best-effort; arbitrary secrets in command lines may remain.
- In-memory SQLite now uses shared connections so application components can use the same database.

## Detection coverage and limitations

Built-in rule scopes and limitations are documented in the README and alert descriptions. Process command matches can be legitimate dual-use administration. Failed-logon correlation requires a known host, account, and valid source IP; missing or placeholder values are excluded rather than merged into shared "unknown" buckets and are labeled `attribution_status: incomplete` by the Windows Event Log normalizer. The network heuristic flags established connections to selected service ports on global remote endpoints, but cannot infer direction or maliciousness. Positive and benign/false-positive cases are covered in `tests/test_detection.py`; these tests validate rule behavior, not real-world precision against production telemetry.

The Windows Event Log collector targets Security IDs 4624, 4625, 1102 and System ID 7045. Access to Security events varies with account permissions and local policy. Process/network visibility can also be restricted. Startup baselines intentionally suppress events for pre-existing activity; short-lived activity between polls may be missed. Health status reports collector failures and known limitations but cannot prove that Windows exposed every record.

## Privacy and operations

- The application has no built-in authentication or roles; use a protected Windows account and restrictive ACLs.
- Database and logs default to `%LOCALAPPDATA%\Mini SOC` on Windows, outside the repository checkout. `MINISOC_DATA_DIR` supports an absolute custom location.
- On upgrade, an existing repository-local database is copied with SQLite's online backup API only when the new database does not exist; the old database remains untouched for verification.
- Database/log contents are plaintext, not application-encrypted. Inspect Windows ACLs on the configured folder and protect backups and exports separately.
- `python -m src.database.backup <new-path>` creates a consistent database snapshot and refuses to overwrite an existing destination.
- The 90-day cleanup runs at application startup and removes only aged event rows. Incidents may retain references to expired events; database backups and exported files do not have automatic retention/deletion.
- Run collectors only on systems the operator is authorized to monitor. Grant the minimum Windows permissions required for the chosen data sources.
- Before upgrades or migration cleanup, make a backup and verify event/incident counts at the new location. Do not delete the old database until that verification is complete.

## Validation

- `C:\Users\Lenovo\anaconda3\python.exe -m pytest -q` — **160 passed**.
- Pylance syntax checks — no syntax errors in the modified collector, UI, or test files.
- `git diff --check` — passed.
- Added regression coverage for persistent review state, alert/incident deduplication, database paging beyond 500 events/incidents, detections whose evidence is outside the visible event page, simulated standard-user process/network access denials and their health reporting, unique process-level access-denied counts, partial-metadata health classification, GUI UAC relaunch/fallback behavior, continuous background collection and shutdown, detection positive and benign cases including incomplete logon attribution, multi-batch Windows event backfill beyond 100 records, retry without gaps, checkpoint rollback, evidence timelines, opening events outside the default timeframe, absolute per-user storage overrides, legacy database migration without source deletion, non-overwriting SQLite backups with integrity validation, 90-day event cleanup, and export-file retention.

## Remaining acceptance work

1. A clean headless startup was tested on this Windows workstation under the current medium-integrity token (the Administrators group was deny-only). With an isolated `MINISOC_DATA_DIR`, it created the database/logs and exited successfully. Security Event Log access was denied; network collection was healthy. A subsequent read-only process snapshot enumerated all 259 PIDs reported by `psutil`, with 169 process records having at least one restricted field (168 rows lacked username and command-line data, and one lacked an executable path). These counts vary by snapshot. The isolated test data was removed afterward.
2. A one-time UAC-approved process snapshot returned 275 process records versus 276 PIDs during enumeration; 8 records had at least one denied field (1 missing executable path, 7 missing command lines, and none missing usernames). Process starts/exits during enumeration and protected-process restrictions mean full visibility cannot be guaranteed.
3. The current `%LOCALAPPDATA%\Mini SOC` directory ACL was inspected: inherited full-control entries were present for the current user, `SYSTEM`, and `BUILTIN\\Administrators`. No database was present there at inspection time. These observations apply to this account and host only.
4. Migration preservation, SQLite online backup/integrity, event-retention behavior, and export-file survival are covered by automated tests; a live migration/restore against the user's repository data was not performed.
5. A UAC-approved, read-only Security Event Log check completed successfully: the collector reported healthy and read 229 matching records. The account is also in Event Log Readers; its existing standard-user token still needs sign-out/sign-in to pick up that membership. The GUI's UAC-approved administrator token can read the Security channel under its existing ACL without broadening permissions.
6. Recheck ACLs, backup restore, retention and exports on each target deployment. Automated tests cannot certify another account's ACLs, Security channel policy, synchronization configuration, or operational export-retention policy.

Until these environment-specific checks are complete, describe the project as a hardened MVP rather than production-ready software.
