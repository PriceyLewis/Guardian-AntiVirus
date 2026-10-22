# Guardian Antivirus — v1.1.0

**Release date:** 22 October 2026  
**Status:** Portfolio release, installable package

Guardian 1.1 turns the portfolio build into an installable Linux app and fills the everyday gaps of a desktop scanner: scanning any file, choosing what is monitored, managing quarantine over time, and explaining the engine's state honestly.

## Highlights

### Scanning
- Scan selected files, or drop files and folders onto the window.
- `guardian --scan [--report-only] PATH…` scans from a terminal with clamscan-style exit codes.
- Without the ClamAV daemon, files are batched into one `clamscan` run per 100 files instead of reloading signatures per file.
- Daily Quick scan and weekly Home scan, at a preferred time of day; missed slots run when Guardian next opens.

### Real-time monitoring
- Choose the monitored folders and exclude trusted ones.
- Files are scanned once they stop changing; browser partial downloads are skipped until renamed.
- Pause for an hour from the tray; monitoring resumes automatically.

### Quarantine
- SHA-256 fingerprint for every detection, for lookups such as VirusTotal without uploading the file.
- Multi-select restore and delete, CSV report export and disk-usage summary.
- Optional automatic deletion after 30 or 90 days.
- Optional restore of original permissions (setuid, setgid and sticky bits are never restored).

### Engine and diagnostics
- Overview shows signature version and age, warning when definitions are missing or more than 7 days old.
- Update definitions with FreshClam from Settings, with guidance when the service or administrator rights are needed.
- Guided setup and live status for ClamAV on-access blocking (clamonacc).
- Rotating diagnostic log, opened from Settings.

### Desktop
- Install with `pipx install`; `guardian --install-menu-entry` adds Guardian to the application menu.
- Data lives in `~/.local/share/guardian`; data from earlier versions moves there automatically.
- Light theme that follows the desktop, or a fixed light or dark choice.
- Keyboard shortcuts: Ctrl+1–4, Ctrl+F, F5, Ctrl+Q and Delete in Quarantine.
- Only one instance runs at a time; login start goes straight to the tray.

## Fixes
- Monitoring no longer rescans Guardian's own database when its data folder is inside a monitored folder (previously hundreds of self-scans per second).
- The tray menu keeps Open, Quick Scan, History and Quit (they were being garbage collected).
- Quitting during a running engine check no longer crashes.
- Removing an excluded folder no longer reads a deleted list item.

## Verification completed
- Pytest regression suite: 102 tests.
- End-to-end runs against the real ClamAV engine, with both the daemon and `clamscan`, using a local EICAR test signature.
- The wheel builds and installs into a clean environment, and the installed `guardian` command scans and launches.
- Browser demo journeys pass on desktop and mobile in both themes.

## Portfolio scope

Guardian is a ClamAV frontend and folder monitor, not a certified antivirus. Without on-access blocking it detects threats after files are written rather than preventing access. It is released under the MIT licence.

---

This file contains the release notes prepared for the GitHub **v1.1.0** release entry.
