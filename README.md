# Guardian Antivirus

[![Tests](https://github.com/PriceyLewis/Guardian-AntiVirus/actions/workflows/tests.yml/badge.svg)](https://github.com/PriceyLewis/Guardian-AntiVirus/actions/workflows/tests.yml)

A Linux desktop security application built with Python, PySide6, ClamAV and SQLite. Guardian coordinates malware scanning, asynchronous folder monitoring, quarantine workflows, persistent history and defensive settings behaviour through a desktop UI.

![Guardian Antivirus portfolio preview](https://priceylewis.github.io/assets/guardian.svg)

> **Portfolio scope:** Guardian is a beta ClamAV frontend and filesystem monitor, not a certified antivirus and not a kernel-level execution blocker. The source is public for portfolio review; no open-source licence is currently attached.

## Why this project stands out

Guardian goes beyond a normal CRUD application. It demonstrates:

- Linux-specific process and filesystem integration;
- long-running/background work without blocking the UI;
- ClamAV daemon use with CLI fallback;
- quarantine, restore and overwrite protection;
- SQLite-backed scan history;
- settings rollback when persistence/runtime updates fail;
- tray, notification and login-startup integration;
- explicit failure states instead of treating scanner errors as clean files;
- automated pytest regression coverage.

## Recruiter walkthrough

A useful local demo takes only a few minutes:

1. Open the Overview page and show Quick / Home / Custom scan options.
2. Run a disposable-folder scan.
3. Use the official harmless EICAR test file if live ClamAV is configured.
4. Show the detection result and quarantine record.
5. Open History and demonstrate search/filter/export behaviour.
6. Open Quarantine and demonstrate safe restore/delete controls.
7. Toggle monitoring/settings and show that UI state reflects the runtime behaviour.

No live malware is required or recommended.

## Run locally

Use Python 3.10+ in a writable checkout:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python guardian.py
```

Install ClamAV and its signature databases using your Linux distribution's supported packages and maintain definitions with FreshClam.

Guardian first attempts the local ClamAV daemon and then falls back to `clamscan`. A missing engine, unreadable file or scan timeout is surfaced as an error rather than a clean result.

## Architecture

```text
PySide6 / Qt UI
       |
       +--> Scan manager ------> clamd / clamscan
       |
       +--> Watcher -----------> filesystem events
       |
       +--> Quarantine --------> protected local files
       |
       +--> Settings ----------> runtime + persistence
       |
       +--> SQLite ------------> scan/history state
       |
       +--> Notifier / tray / autostart
```

The implementation keeps scanning, monitoring, persistence, quarantine and notification concerns separate rather than embedding system work directly in the UI layer.

## Behaviour and defensive decisions

- Quick Scan checks existing Downloads, Desktop and Documents folders.
- Home Scan checks the user's home directory. Custom Scan checks a selected folder.
- Symlinks and Guardian's quarantine directory are excluded.
- Threats are moved into a private quarantine directory and recorded in SQLite.
- Restore refuses to overwrite an existing destination.
- Monitoring reacts asynchronously to creation, modification, move and close events; it is detection, not access prevention.
- Disabling monitoring pauses dispatch immediately and stops the observer cleanly on exit.
- Cancelled scans are not presented as completed scans.
- Definition freshness is not falsely asserted by the app.
- CSV export escapes spreadsheet-formula prefixes in exported values.

## Tests

```sh
python -m pip install pytest
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

Regression coverage includes:

- scanner status and error handling;
- archive-policy behaviour;
- quarantine / restore / delete;
- overwrite protection;
- database thread ownership;
- worker failures;
- settings persistence and rollback;
- navigation and scan lifecycle.

Scanner tests use controlled engine responses, so they verify application behaviour rather than claiming to prove live antivirus detection.

## Target-machine verification

Before treating a build as fully verified on a Linux desktop, check:

- ClamAV daemon permissions and CLI fallback;
- current signature databases;
- official harmless EICAR detection in a disposable folder;
- notification delivery;
- tray close/quit behaviour;
- login autostart;
- performance across large folder trees and active downloads.

The UI has also been exercised offscreen at 1180×820 and 900×650 to catch layout regressions.

## Data location

Data paths are anchored to the checkout by default. Set `GUARDIAN_DATA_DIR` to use a separate writable data directory. Existing data is not automatically migrated.

## What this demonstrates

Python desktop development · Linux integration · defensive programming · asynchronous work · SQLite · security tooling · pytest · CI · careful product claims.
