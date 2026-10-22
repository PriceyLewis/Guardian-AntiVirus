"""Headless scanning: python guardian.py --scan [--report-only] PATH..."""
import sys
from PySide6.QtCore import QCoreApplication
from core.scan_worker import ScanWorker

USAGE = "usage: guardian.py --scan [--report-only] PATH...\n"


def run_scan(args, out=sys.stdout, err=sys.stderr):
    """Scan files and folders in the foreground. Exit codes follow clamscan:
    0 nothing found, 1 threat found, 2 errors only."""
    report_only = "--report-only" in args
    paths = [arg for arg in args if arg != "--report-only"]
    if not paths:
        err.write(USAGE)
        return 2
    QCoreApplication.instance() or QCoreApplication([])
    worker = ScanWorker(paths, "Command-line scan", quarantine=not report_only)
    summary = {}
    labels = {"clean": "OK", "found": "FOUND", "error": "ERROR"}
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
    scanned = summary.get("scanned", 0)
    out.write(f"\nScanned {scanned} file{'' if scanned == 1 else 's'}: {summary.get('clean', 0)} clean, "
              f"{summary.get('found', 0)} found ({action}), {summary.get('errors', 0)} error{'' if summary.get('errors') == 1 else 's'}\n")
    if summary.get("found"):
        return 1
    return 2 if summary.get("errors") else 0
