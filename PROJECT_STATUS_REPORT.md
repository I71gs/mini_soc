# Mini SOC Project Status Report

## Executive summary

Mini SOC is a working local-first Windows security telemetry and incident prototype. The backend is functional, the database layer is durable, and the detection logic is active. The project is not a broken or empty starter; it is a legitimate MVP with real telemetry, incident creation, reporting, and a desktop interface.

However, it is still a prototype rather than a fully hardened enterprise SOC platform. The main constraints are environmental: Windows Event Log access is often restricted in non-elevated sessions, and the product still needs additional analyst UX polish and richer real-world correlation logic.

## Current project state

### Completed
- Local-first architecture and config management
- SQLite event persistence and schema versioning
- Windows Event Log extraction pipeline with checkpoint handling
- Host process/network telemetry collection
- Rule-based detection engine
- Incident creation and lifecycle management
- Reporting/export support
- Security hardening and redaction helpers
- PySide6 desktop UI shell and overview/event views
- Automated test coverage for detection, persistence, reporting, and UI behavior

### Remaining / next stage work
- Deeper analyst workflow polish in the UI
- More realistic correlation and triage flows
- Additional detection rules for privilege escalation, lateral movement, and persistence
- Expanded operational dashboards and filtering
- More production-hardening for enterprise deployments

## Validation results

The following checks were run in the current workspace:

- `python -m pytest -q` → passed
  - Result: 112 passed in 10.59s
- `python main.py` → booted successfully
  - Result: app initializes, database loads, telemetry checks execute, and startup completes without crashing

## Known limitations and runtime realities

### 1. Windows Event Log access is permission-gated
When running outside an elevated Windows session, querying the Security log can fail with an access denial. This behavior is non-fatal and intentionally handled by the collector, but it limits the quality of Windows auth telemetry in normal user sessions.

### 2. Host telemetry depends on the host environment
The host process and network collectors work best in a proper Windows workstation or server. In a restricted environment, some data sources remain empty even though the app is functioning correctly.

### 3. Detection rules are heuristic
The detection engine is intentionally designed to catch suspicious patterns, but it can still produce false positives if normal admin tooling or local scripting resembles malicious behavior. Reducing the rule noise is an ongoing operational task.

### 4. The app is still a prototype
This is not yet a polished enterprise SOC, but it is already a credible local-first MVP with useful security operations primitives.

## Fixes applied during review

During validation, the project was tightened in two important ways:

- Detection noise reduction
  - suspicious process alerts now require suspicious execution patterns rather than matching generic names alone
  - command-line-based suspicious behavior is filtered more carefully to avoid common false positives
- Permission warning deduplication
  - repeated Windows Event Log permission warnings are now suppressed per channel to reduce log spam in restricted environments

## Git status

Repository: https://github.com/I71gs/mini_soc.git
Branch: main

## Summary

Mini SOC is in a strong working MVP state: the backend is functional, tests pass, and the app boots successfully. The remaining work is mostly product maturity, analyst UX refinement, and deepening the detection logic rather than fixing broken basics.
