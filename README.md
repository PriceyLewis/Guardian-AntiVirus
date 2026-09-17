# Guardian Antivirus

Linux desktop ClamAV frontend using PySide6. This is a beta file scanner and folder monitor, not a certified antivirus or a kernel-level execution blocker.

## Run

Use Python 3.10 or newer in a writable checkout:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python guardian.py
```

Install ClamAV and its signature databases using your distribution's supported packages. Maintain definitions using the distribution's FreshClam service. Guardian first attempts the local ClamAV daemon, then falls back to `clamscan`. A missing engine, unreadable file, or scan timeout is an error, never a clean result. Desktop notifications optionally use `notify-send`.

Data paths are anchored to the checkout, regardless of working directory, preserving the previous database location. Set `GUARDIAN_DATA_DIR` to use a separate writable directory; existing data is not automatically migrated.

## Behaviour

- Quick Scan checks existing Downloads, Desktop and Documents folders.
- Home Scan checks your home directory, not the entire computer. Custom Scan checks a selected folder.
- Symlinks and Guardian's quarantine directory are excluded.
- Threats are moved into a private quarantine directory and recorded in SQLite. Restore refuses to overwrite existing files. Restored files have restrictive permissions and may be detected again by monitoring.
- Folder monitoring responds to creation, modification, moves and close events. It is asynchronous detection, not access prevention. Large downloads may generate multiple scan records.
- Real-time settings apply immediately. Notifications and archive settings are read for subsequent operations. Disabling archive inspection selects `clamscan`; otherwise daemon archive policy comes from your ClamAV configuration.
- Login startup creates a user XDG autostart entry pointing to the current Python environment and checkout. Update this setting after moving the checkout or replacing its virtual environment.
- The Keep running when the window closes setting controls tray behaviour; without an available tray, closing always exits. Quit waits for an active scan operation to return (CLI timeout: 120 seconds).
- Definition freshness is not verified by Guardian. The dashboard does not assert that definitions are current or that monitoring alone guarantees protection.

## Tests

```sh
python -m pip install pytest
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

Regression tests cover scanner status handling and archive policy, quarantine/restore/delete and overwrite protection, database thread ownership, worker failures, settings, navigation and scan lifecycle. Scanner tests use controlled engine responses; they do not prove live ClamAV detection.

Before relying on a release, verify on the target Linux desktop: ClamAV daemon permissions and fallback, current signature databases, official harmless EICAR test detection in a disposable folder, notifications, tray close/quit and login autostart. No live malware is needed. Review performance on large folder trees and active downloads. File changes concurrent with scanning or quarantine are not an adversarially hardened isolation boundary.

## Interface and settings

Overview includes quick, home and custom folder scans, cancellation after the active file, and a result summary that distinguishes clean files, detections, quarantined files and errors. A cancelled scan is never labelled complete. History searches full paths and threat names, filters by outcome, and exports only the visible subset of the latest 500 results as CSV. Spreadsheet formula prefixes in exported values are escaped. Quarantine supports search and uses stored IDs for confirmed restore/delete actions.

All five settings save automatically. Failed saves restore the previous controls and attempt to restore runtime/autostart state, with a visible error if rollback fails. Unrelated preference changes do not rewrite the login entry. Disabling monitoring pauses dispatch immediately without blocking the UI on an active ClamAV call; its observer is stopped and joined when Guardian quits. Re-enabling resumes observation, but does not retrospectively scan changes made while paused.

Settings also provides Restore defaults (with confirmation), a non-blocking engine version check, and a notification test (available only when notifications are enabled). Checks time out after 10 seconds. A successful engine version check verifies command availability only, not detection or current definitions. A successful notification request still depends on the desktop displaying it.

The UI was inspected with Qt offscreen at 1180×820 and 900×650. Each page scrolls independently so longer settings content does not stretch history or quarantine. Native Nobara tray integration, login behaviour, notification delivery and live ClamAV remain target-machine checks.
