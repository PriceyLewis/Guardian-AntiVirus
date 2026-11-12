import os
import time
from pathlib import Path
from threading import Event
from PySide6.QtCore import QObject, Signal
import core.paths as paths
from core.paths import QUARANTINE, is_excluded, is_guardian_storage
from core.scanner import GuardianScanner
from core.quarantine import QuarantineManager
from core.notifier import GuardianNotifier
from core.log import log
from database.database import GuardianDatabase

# Seconds of scan history held in one database transaction.
COMMIT_INTERVAL = 1


class ScanWorker(QObject):
    progress = Signal(int)
    maximum = Signal(int)
    current_file = Signal(str)
    finished = Signal(int)
    error = Signal(str)
    summary = Signal(dict)
    result = Signal(str, str, str)

    def __init__(self, folders, name="Scan", quarantine=True):
        super().__init__()
        # Despite the name, entries may also be individual files.
        self.folders = folders
        self.name = name
        self.quarantine_found = quarantine
        self.cancelled = Event()

    def run(self):
        db = None
        scanned = 0
        totals = {"clean": 0, "found": 0, "errors": 0, "quarantined": 0}
        began = time.monotonic()
        def report_error(message):
            totals["errors"] += 1
            log.warning("%s: %s", self.name, message)
            self.error.emit(message)
        log.info("%s started: %s", self.name, ", ".join(map(str, self.folders)))
        try:
            scanner = GuardianScanner()
            db = GuardianDatabase()
            quarantine = QuarantineManager()
            exclusions = db.get_exclusions()
            files = set()
            for folder in self.folders:
                target = Path(folder).absolute()
                if not target.is_symlink() and target.is_file():
                    if not is_guardian_storage(target, QUARANTINE) and not is_excluded(target, exclusions):
                        files.add(target)
                    continue
                if not target.is_dir():
                    report_error(f"Not found or not accessible: {folder}")
                    continue
                # Directory entries already know their type, sparing a stat call per file.
                pending = [target]
                while pending:
                    if self.cancelled.is_set():
                        return
                    base = pending.pop()
                    if is_guardian_storage(base, QUARANTINE) or is_excluded(base, exclusions):
                        continue
                    try:
                        with os.scandir(base) as entries:
                            entries = list(entries)
                    except OSError as exc:
                        report_error(str(exc))
                        continue
                    # Past the checks above, only Guardian's own data folder holds files to skip.
                    own = base.resolve() == paths.DATA.resolve()
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                pending.append(base / entry.name)
                            elif entry.is_file(follow_symlinks=False) and not (own and is_guardian_storage(entry.path, QUARANTINE)):
                                files.add(base / entry.name)
                        except OSError as exc:
                            report_error(str(exc))
            self.maximum.emit(len(files))
            def started(paths):
                more = f"  (+{len(paths) - 1:,} more in this batch)" if len(paths) > 1 else ""
                self.current_file.emit(str(paths[0]) + more)
            committed = time.monotonic()
            for file, result in scanner.scan_files(sorted(files), started=started):
                status, virus = result["status"], result.get("virus")
                db.add_scan(str(file), status, virus, commit=False)
                # An open write transaction would lock out the quarantine's own connection.
                if status == "found" or time.monotonic() - committed >= COMMIT_INTERVAL:
                    db.commit()
                    committed = time.monotonic()
                self.result.emit(str(file), status, virus or "")
                if status in ("clean", "found"):
                    totals[status] += 1
                if status == "error":
                    report_error(f"{file}: {virus}")
                if status == "found":
                    log.warning("Detection %s in %s", virus, file)
                if status == "found" and self.quarantine_found:
                    try:
                        quarantine.quarantine(file, virus)
                        totals["quarantined"] += 1
                        GuardianNotifier.notify("Guardian", f"Threat quarantined: {file.name}")
                    except Exception as exc:
                        report_error(f"Could not quarantine {file}: {exc}")
                scanned += 1
                self.progress.emit(scanned)
                # Checked after recording so the generator never starts more work.
                if self.cancelled.is_set():
                    break
        except Exception as exc:
            report_error(str(exc))
        finally:
            duration = round(time.monotonic() - began, 1)
            cancelled = self.cancelled.is_set()
            if db:
                try:
                    db.add_scan_run(self.name, scanned, totals["found"], totals["errors"], cancelled, duration)
                except Exception as exc:
                    report_error(f"Could not record scan: {exc}")
                db.close()
            log.info("%s %s: %d scanned, %d found, %d quarantined, %d errors in %.1fs", self.name,
                     "cancelled" if cancelled else "finished", scanned, totals["found"], totals["quarantined"], totals["errors"], duration)
            self.summary.emit(dict(totals, scanned=scanned, cancelled=cancelled, duration=duration))
            self.finished.emit(scanned)
