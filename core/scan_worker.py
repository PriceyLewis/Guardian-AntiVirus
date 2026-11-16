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
        db = None
        scanned = 0
        totals = {"clean": 0, "found": 0, "errors": 0, "quarantined": 0, "unchanged": 0, "flagged": 0, "skipped": 0}
        detections = []
        began = time.monotonic()
        def report_error(message):
            totals["errors"] += 1
            log.warning("%s: %s", self.name, message)
            self.error.emit(message)
        # Results waiting to be written; nothing is held open in the database meanwhile.
        rows, clean, stale = [], [], []
        def flush():
            db.record_scans(rows, clean, stale)
            rows.clear(), clean.clear(), stale.clear()
        log.info("%s started: %s", self.name, ", ".join(map(display, self.folders)))
        try:
            scanner = GuardianScanner()
            settings = load_config()
            if self.background:
                scanner.background = True
                try:
                    # On Linux this lowers only the scanning thread, not the interface.
                    os.setpriority(os.PRIO_PROCESS, get_native_id(), 10)
                except OSError:
                    pass
            def wait_while_paused():
                if not self.paused.is_set():
                    return
                pause = getattr(scanner, "pause", None)
                if pause:
                    pause()
                while self.paused.is_set() and not self.cancelled.is_set():
                    time.sleep(0.1)
                resume = getattr(scanner, "resume", None)
                if resume:
                    resume()
            db = GuardianDatabase()
            quarantine = QuarantineManager()
            exclusions = db.get_exclusions()
            files = set()
            # Files the user named are always scanned, whatever the size and media settings say.
            named = set()
            for folder in self.folders:
                target = Path(folder).absolute()
                if not target.is_symlink() and target.is_file():
                    if not is_guardian_storage(target, QUARANTINE) and not is_excluded(target, exclusions):
                        files.add(target)
                        named.add(target)
                    continue
                if not target.is_dir():
                    report_error(f"Not found or not accessible: {display(folder)}")
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
            limit = settings["max_scan_size_mb"] * 1024 * 1024
            if limit or settings["skip_media"]:
                for file in list(files - named):
                    skip_file = settings["skip_media"] and file.suffix.lower() in MEDIA_SUFFIXES
                    if not skip_file and limit:
                        try:
                            skip_file = file.lstat().st_size > limit
                        except OSError:
                            pass
                    if skip_file:
                        files.discard(file)
                        totals["skipped"] += 1
            self.maximum.emit(len(files))
            # Files the same engine and signatures already found clean, and unchanged since, are not rescanned.
            # A scan that rechecks everything still records what it found clean, for later scans.
            skip = settings["skip_unchanged"] if self.skip_unchanged is None else self.skip_unchanged
            extra = SecondOpinion()
            extra.gentle = self.background
            yara_quarantine = settings["yara_quarantine"]
            key = getattr(scanner, "engine_key", lambda: None)()
            if key:
                key += "|" + extra.key()
            if key:
                db.cache_engine(key)
            signatures = {}
            queue = []
            for file in sorted(files):
                if key and display(file) == str(file):
                    if self.cancelled.is_set():
                        return
                    try:
                        stat = file.lstat()
                        # ctime cannot be set back by a program that restores a file's mtime.
                        signatures[file] = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino)
                    except OSError:
                        pass
                    if skip and file in signatures and db.cached_clean(str(file)) == signatures[file]:
                        totals["clean"] += 1
                        totals["unchanged"] += 1
                        scanned += 1
                        self.result.emit(str(file), "clean", "")
                        continue
                queue.append(file)
            self.progress.emit(scanned)
            def started(paths):
                more = f"  (+{len(paths) - 1:,} more in this batch)" if len(paths) > 1 else ""
                self.current_file.emit(display(paths[0]) + more)
            committed = time.monotonic()
            for file, result in extra.review(scanner.scan_files(queue, started=started), expected=len(queue)):
                status, virus = result["status"], result.get("virus")
                # Pattern rules misfire more than signatures: unless the user asked for such
                # matches to be quarantined they are recorded as suspicious and left in place.
                if status == "found" and result.get("engine") == "yara" and not yara_quarantine:
                    status = "suspicious"
                # File names are bytes on disk and need not be valid text.
                shown = display(file)
                digest = None
                if status in ("found", "suspicious"):
                    try:
                        digest = result.get("sha256") or sha256(file)
                        detections.append(digest)
                    except OSError:
                        pass
                rows.append((datetime.now().isoformat(timespec="seconds"), shown, status, virus, digest))
                if key and shown == str(file):
                    # The signature predates the scan, so a file changed meanwhile is checked again next time.
                    if status == "clean" and file in signatures:
                        clean.append((shown, signatures[file]))
                    else:
                        stale.append(shown)
                # Written before quarantining, which records the file through its own connection.
                if status == "found" or time.monotonic() - committed >= COMMIT_INTERVAL:
                    flush()
                    committed = time.monotonic()
                self.result.emit(shown, status, virus or "")
                if status in ("clean", "found"):
                    totals[status] += 1
                if status == "error":
                    report_error(f"{shown}: {virus}")
                if status == "found":
                    log.warning("Detection %s in %s", virus, shown)
                if status == "suspicious":
                    totals["flagged"] += 1
                    log.warning("Suspicious: %s matches %s (left in place)", shown, virus)
                if status == "found" and self.quarantine_found:
                    try:
                        quarantine.quarantine(file, virus)
                        totals["quarantined"] += 1
                        GuardianNotifier.notify("Guardian", f"Threat quarantined: {display(file.name)}")
                    except Exception as exc:
                        report_error(f"Could not quarantine {shown}: {exc}")
                scanned += 1
                self.progress.emit(scanned)
                wait_while_paused()
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
                    flush()
                    db.add_scan_run(self.name, scanned, totals["found"], totals["errors"], cancelled, duration)
                except Exception as exc:
                    report_error(f"Could not record scan: {exc}")
                db.close()
            log.info("%s %s: %d scanned, %d found, %d quarantined, %d errors in %.1fs", self.name,
                     "cancelled" if cancelled else "finished", scanned, totals["found"], totals["quarantined"], totals["errors"], duration)
            self.summary.emit(dict(totals, scanned=scanned, cancelled=cancelled, duration=duration, detections=detections))
            self.finished.emit(scanned)
