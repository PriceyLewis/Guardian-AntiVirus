import os
import time
from datetime import datetime
from pathlib import Path
from threading import Event, get_native_id
from PySide6.QtCore import QObject, Signal
import core.paths as paths
from core.paths import QUARANTINE, display, is_excluded, is_guardian_storage
from core.scanner import GuardianScanner
from core.engines import SecondOpinion
from core.quarantine import QuarantineManager, sha256
from core.notifier import GuardianNotifier
from core.log import log
from config import load_config
from database.database import GuardianDatabase

# Audio, video and image formats skipped when the user asks: large, slow to scan and rarely a carrier.
MEDIA_SUFFIXES = frozenset(".mp3 .flac .wav .ogg .opus .m4a .aac .wma .mp4 .mkv .avi .mov .webm .wmv .flv .m4v .mpg .mpeg .ts "
                           ".jpg .jpeg .png .gif .bmp .webp .tif .tiff .heic .raw .cr2 .nef .arw .psd".split())
# Seconds of scan results collected before they are written to the database together.
COMMIT_INTERVAL = 1


class ScanWorker(QObject):
    progress = Signal(int)
    maximum = Signal(int)
    current_file = Signal(str)
    finished = Signal(int)
    error = Signal(str)
    summary = Signal(dict)
    result = Signal(str, str, str)

    def __init__(self, folders, name="Scan", quarantine=True, skip_unchanged=None, background=False):
        super().__init__()
        # Despite the name, entries may also be individual files.
        self.folders = folders
        self.name = name
        self.quarantine_found = quarantine
        # None follows the user's setting; False forces every file to be checked.
        self.skip_unchanged = skip_unchanged
        # Scheduled scans run at low priority so they do not slow the desktop.
        self.background = background
        self.cancelled = Event()
        self.paused = Event()

    def run(self):
        _ScanRun(self).run()


class Cancelled(Exception):
    """Raised to stop a scan the user cancelled before any file was checked."""


class _ScanRun:
    """One scan from start to finish: collect files, check them, record and act on results."""

    def __init__(self, worker):
        self.worker = worker
        self.db = None
        self.scanner = None
        self.scanned = 0
        self.totals = {"clean": 0, "found": 0, "errors": 0, "quarantined": 0, "unchanged": 0, "flagged": 0, "skipped": 0}
        self.detections = []
        # Results waiting to be written; nothing is held open in the database meanwhile.
        self.rows, self.clean, self.stale = [], [], []
        self.committed = time.monotonic()
        self.began = time.monotonic()

    # ----- helpers

    def report_error(self, message):
        self.totals["errors"] += 1
        log.warning("%s: %s", self.worker.name, message)
        self.worker.error.emit(message)

    def check_cancelled(self):
        if self.worker.cancelled.is_set():
            raise Cancelled

    def flush(self):
        self.db.record_scans(self.rows, self.clean, self.stale)
        self.rows.clear(), self.clean.clear(), self.stale.clear()
        self.committed = time.monotonic()

    def wait_while_paused(self):
        worker = self.worker
        if not worker.paused.is_set():
            return
        pause = getattr(self.scanner, "pause", None)
        if pause:
            pause()
        while worker.paused.is_set() and not worker.cancelled.is_set():
            time.sleep(0.1)
        resume = getattr(self.scanner, "resume", None)
        if resume:
            resume()

    # ----- steps

    def collect(self):
        """Every regular file under the chosen folders, and the files the user named directly."""
        exclusions = self.db.get_exclusions()
        files, named = set(), set()
        for folder in self.worker.folders:
            target = Path(folder).absolute()
            if not target.is_symlink() and target.is_file():
                if not is_guardian_storage(target, QUARANTINE) and not is_excluded(target, exclusions):
                    files.add(target)
                    named.add(target)
                continue
            if not target.is_dir():
                self.report_error(f"Not found or not accessible: {display(folder)}")
                continue
            # Directory entries already know their type, sparing a stat call per file.
            pending = [target]
            while pending:
                self.check_cancelled()
                base = pending.pop()
                if is_guardian_storage(base, QUARANTINE) or is_excluded(base, exclusions):
                    continue
                try:
                    with os.scandir(base) as entries:
                        entries = list(entries)
                except OSError as exc:
                    self.report_error(str(exc))
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
                        self.report_error(str(exc))
        return files, named

    def drop_large_and_media(self, files, named):
        """Leave out what the user chose not to scan in folders; files they picked always stay."""
        limit = self.settings["max_scan_size_mb"] * 1024 * 1024
        if not limit and not self.settings["skip_media"]:
            return
        for file in list(files - named):
            skip = self.settings["skip_media"] and file.suffix.lower() in MEDIA_SUFFIXES
            if not skip and limit:
                try:
                    skip = file.lstat().st_size > limit
                except OSError:
                    pass
            if skip:
                files.discard(file)
                self.totals["skipped"] += 1

    def split_unchanged(self, files):
        """Files to scan, after passing over those found clean before and unchanged since.

        Files the same engines already found clean, and unchanged since, are not rescanned.
        A scan that rechecks everything still records what it found clean, for later scans.
        """
        worker = self.worker
        skip = self.settings["skip_unchanged"] if worker.skip_unchanged is None else worker.skip_unchanged
        self.key = getattr(self.scanner, "engine_key", lambda: None)()
        if self.key:
            self.key += "|" + self.extra.key()
            self.db.cache_engine(self.key)
        self.signatures = {}
        queue = []
        for file in sorted(files):
            if self.key and display(file) == str(file):
                self.check_cancelled()
                try:
                    stat = file.lstat()
                    # ctime cannot be set back by a program that restores a file's mtime.
                    self.signatures[file] = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino)
                except OSError:
                    pass
                if skip and file in self.signatures and self.db.cached_clean(str(file)) == self.signatures[file]:
                    self.totals["clean"] += 1
                    self.totals["unchanged"] += 1
                    self.scanned += 1
                    worker.result.emit(str(file), "clean", "")
                    continue
            queue.append(file)
        return queue

    def record(self, file, result):
        """Store one result, then quarantine or flag the file as the settings say."""
        worker = self.worker
        status, virus = result["status"], result.get("virus")
        # Pattern rules misfire more than signatures: unless the user asked for such
        # matches to be quarantined they are recorded as suspicious and left in place.
        if status == "found" and result.get("engine") == "yara" and not self.settings["yara_quarantine"]:
            status = "suspicious"
        # File names are bytes on disk and need not be valid text.
        shown = display(file)
        digest = None
        if status in ("found", "suspicious"):
            try:
                digest = result.get("sha256") or sha256(file)
                self.detections.append(digest)
            except OSError:
                pass
        self.rows.append((datetime.now().isoformat(timespec="seconds"), shown, status, virus, digest))
        if self.key and shown == str(file):
            # The signature predates the scan, so a file changed meanwhile is checked again next time.
            if status == "clean" and file in self.signatures:
                self.clean.append((shown, self.signatures[file]))
            else:
                self.stale.append(shown)
        # Written before quarantining, which records the file through its own connection.
        if status == "found" or time.monotonic() - self.committed >= COMMIT_INTERVAL:
            self.flush()
        worker.result.emit(shown, status, virus or "")
        if status in ("clean", "found"):
            self.totals[status] += 1
        if status == "error":
            self.report_error(f"{shown}: {virus}")
        if status == "found":
            log.warning("Detection %s in %s", virus, shown)
        if status == "suspicious":
            self.totals["flagged"] += 1
            log.warning("Suspicious: %s matches %s (left in place)", shown, virus)
        if status == "found" and worker.quarantine_found:
            try:
                self.quarantine.quarantine(file, virus)
                self.totals["quarantined"] += 1
                GuardianNotifier.notify("Guardian", f"Threat quarantined: {display(file.name)}")
            except Exception as exc:
                self.report_error(f"Could not quarantine {shown}: {exc}")

    def finish(self):
        worker = self.worker
        duration = round(time.monotonic() - self.began, 1)
        cancelled = worker.cancelled.is_set()
        if self.db:
            try:
                self.flush()
                self.db.add_scan_run(worker.name, self.scanned, self.totals["found"], self.totals["errors"], cancelled, duration)
            except Exception as exc:
                self.report_error(f"Could not record scan: {exc}")
            self.db.close()
        totals = self.totals
        log.info("%s %s: %d scanned, %d found, %d quarantined, %d errors in %.1fs", worker.name,
                 "cancelled" if cancelled else "finished", self.scanned, totals["found"], totals["quarantined"], totals["errors"], duration)
        worker.summary.emit(dict(totals, scanned=self.scanned, cancelled=cancelled, duration=duration, detections=self.detections))
        worker.finished.emit(self.scanned)

    def run(self):
        worker = self.worker
        log.info("%s started: %s", worker.name, ", ".join(map(display, worker.folders)))
        try:
            self.scanner = GuardianScanner()
            self.settings = load_config()
            if worker.background:
                self.scanner.background = True
                try:
                    # On Linux this lowers only the scanning thread, not the interface.
                    os.setpriority(os.PRIO_PROCESS, get_native_id(), 10)
                except OSError:
                    pass
            self.db = GuardianDatabase()
            self.quarantine = QuarantineManager()
            files, named = self.collect()
            self.drop_large_and_media(files, named)
            worker.maximum.emit(len(files))
            self.extra = SecondOpinion()
            self.extra.gentle = worker.background
            queue = self.split_unchanged(files)
            worker.progress.emit(self.scanned)

            def started(paths):
                more = f"  (+{len(paths) - 1:,} more in this batch)" if len(paths) > 1 else ""
                worker.current_file.emit(display(paths[0]) + more)

            for file, result in self.extra.review(self.scanner.scan_files(queue, started=started), expected=len(queue)):
                self.record(file, result)
                self.scanned += 1
                worker.progress.emit(self.scanned)
                self.wait_while_paused()
                # Checked after recording so the generator never starts more work.
                if worker.cancelled.is_set():
                    break
        except Cancelled:
            pass
        except Exception as exc:
            self.report_error(str(exc))
        finally:
            self.finish()
