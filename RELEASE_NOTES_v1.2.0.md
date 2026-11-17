# Guardian Antivirus — v1.2.0

**Release date:** 16 November 2026  
**Status:** Portfolio release, installable package

Guardian 1.2 is about speed and a second opinion. Scans are several times faster, repeat scans skip files that have not changed, and files ClamAV passes are also checked against known-malware fingerprints and community YARA rules.

## Highlights

### Faster scanning
- Several files are sent to the ClamAV daemon at once. Files the daemon's own user cannot read are handed over as open descriptors instead of starting `clamscan` for each one.
- Without the daemon, a scan streams results from one `clamscan` process (up to four for large scans with memory to spare) rather than reloading signatures every 100 files.
- Files already found clean are not rescanned until they change, or until the engine, its signatures, the threat lists or the relevant settings change. Turn this off under Settings, or pass `--full` on the command line.
- Optional: skip audio, video and image files, or files above a chosen size, in folder scans. Files you pick yourself are always scanned.
- Pause and resume a running scan.
- Scheduled scans run gently by default: one worker at low processor and disk priority.

### Second-opinion engines
- **Hash lookup:** each file's SHA-256 is compared with MalwareBazaar's list of known malware. A match is quarantined like any detection.
- **YARA-X:** the YARA Forge core rules recognise malware families and variants. Needs the optional `yara-x` package (`pip install "guardian-antivirus[yara]"`).
- Both look inside zip and tar archives, within size limits.
- A file matched only by YARA rules is marked **Suspicious** and left in place. From History you can look it up, quarantine it, or ignore it; an ignored file is not reported again unless its contents change.
- Threat lists download without an account from Settings or `guardian --update-threat-lists`, and refresh daily while Guardian is open. Your own `.txt` hash lists and `.yar` rules can be added to the same folder.

### VirusTotal, without an API key
- *Check on VirusTotal* in Quarantine and History, *Check detections on VirusTotal* after a scan, and a *Second opinion* card on Overview for any file or link.
- Reports open in your browser. Files are never uploaded; only their SHA-256 fingerprint is sent.

### Desktop integration
- New downloads are announced once checked, with a *Look up on VirusTotal* button where the notification service supports actions.
- Guardian offers to scan a USB drive when it is plugged in.
- Overview shows whether the ClamAV daemon is connected and what the second-opinion engines have loaded, and offers the commands to set the daemon up.
- Settings reports and explains extra freshclam signature sources.

### Easier to install
- **One command:** `install.sh` sets up ClamAV, its update service and daemon from your distribution (apt, dnf, pacman or zypper), installs Guardian for your user with pipx, adds the menu entry and downloads the threat lists. `--uninstall` removes it again.
- **Flatpak:** a self-contained bundle with its own ClamAV, which downloads and refreshes its own virus definitions. Built and smoke-tested in CI and attached to tagged releases.
- `guardian --update-definitions` updates the definitions Guardian scans with.

### Housekeeping
- Per-file scan history is kept for 90 days by default; choose 30 days, a year or forever under Settings.

- Threat-list downloads are checked before they replace the installed lists: an error page in place of a hash list, a rule pack less than half the installed size, or rules that do not compile are refused. The empty file's fingerprint is never treated as malware.

## Fixes
- A file with a line break in its name could be reported clean by the daemon, which answered about a different file. Such names are now passed by descriptor, and an answer about any other file is not believed.
- A file whose name is not valid UTF-8 no longer aborts the scan, and can be quarantined.
- Without the daemon, very long paths and names containing a carriage return were reported as errors instead of being scanned.
- Scan results are written in short transactions, so a slow file no longer locks the database against monitoring or Settings.

## Upgrade notes
- History older than 90 days is removed on first run unless you change *Keep scan history for* first.
- The first scan after upgrading checks every file; later scans skip unchanged ones.
- The second-opinion engines do nothing until threat lists are downloaded.

## Verification
- 184 automated tests, including 6 that run against real `clamscan` and `clamd` in CI, also run with YARA-X absent and with ClamAV absent.
- Scans against a real ClamAV daemon and `clamscan`: hostile file names, an unprivileged user with unreadable files, 90,000 files, pause and resume, and the main window driven through scan, quarantine, cancel and daemon failure.
- The YARA Forge core rules were downloaded for real and matched none of 11,818 ordinary system files.

Not verified in the test environment, which blocks the relevant hosts: the MalwareBazaar and URLhaus downloads, official ClamAV definitions, a real notification service and browser, and a real USB drive.
