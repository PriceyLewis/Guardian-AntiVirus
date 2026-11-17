"""Headless scanning: python guardian.py --scan [--report-only] [--full] PATH..."""
import sys
from PySide6.QtCore import QCoreApplication
from core.scan_worker import ScanWorker

USAGE = "usage: guardian.py --scan [--report-only] [--full] PATH...\n"


def run_scan(args, out=sys.stdout, err=sys.stderr):
    """Scan files and folders in the foreground. Exit codes follow clamscan:
    0 nothing found, 1 threat found, 2 errors only."""
    report_only = "--report-only" in args
    # --full rechecks files that are unchanged since they were last found clean.
    full = "--full" in args
    paths = [arg for arg in args if arg not in ("--report-only", "--full")]
    if not paths:
        err.write(USAGE)
        return 2
    QCoreApplication.instance() or QCoreApplication([])
    worker = ScanWorker(paths, "Command-line scan", quarantine=not report_only, skip_unchanged=False if full else None)
    summary = {}
    labels = {"clean": "OK", "found": "FOUND", "suspicious": "SUSPICIOUS", "error": "ERROR"}
    reported = set()

    def result(path, status, detail):
        out.write(f"{path}: {labels.get(status, status)}{' ' + detail if detail else ''}\n")
        if status == "error":
            reported.add(f"{path}: {detail}")

    def error(message):
        # Per-file engine errors were already printed as result lines.
        if message not in reported:
            err.write(message + "\n")

    worker.result.connect(result)
    worker.error.connect(error)
    worker.summary.connect(summary.update)
    try:
        worker.run()
    except KeyboardInterrupt:
        worker.cancelled.set()
    action = "reported only" if report_only else f"{summary.get('quarantined', 0)} quarantined"
    if summary.get("flagged"):
        action += f"), {summary['flagged']} suspicious (matched by YARA rules only, left in place"
    scanned = summary.get("scanned", 0)
    unchanged = f" ({summary['unchanged']} unchanged since last scan, not rechecked)" if summary.get("unchanged") else ""
    out.write(f"\nScanned {scanned} file{'' if scanned == 1 else 's'}: {summary.get('clean', 0)} clean{unchanged}, "
              f"{summary.get('found', 0)} found ({action}), {summary.get('errors', 0)} error{'' if summary.get('errors') == 1 else 's'}\n")
    if summary.get("skipped"):
        out.write(f"Skipped {summary['skipped']} large or media file{'' if summary['skipped'] == 1 else 's'}, as set in Settings.\n")
    # Suspicious files need attention too.
    if summary.get("found") or summary.get("flagged"):
        return 1
    return 2 if summary.get("errors") else 0


def update_threat_lists(out=sys.stdout):
    """Download the hash list and YARA rules. Exit code 0 only if every list updated."""
    from core import threatlists
    outcome = threatlists.update()
    for name, succeeded, message in outcome:
        out.write(f"{name}: {'updated, ' if succeeded else 'FAILED: '}{message}\n")
    return 0 if all(succeeded for _, succeeded, _ in outcome) else 2

