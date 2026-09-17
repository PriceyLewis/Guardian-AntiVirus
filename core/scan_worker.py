import os
from pathlib import Path
from threading import Event
from PySide6.QtCore import QObject, Signal
from core.paths import QUARANTINE
from core.scanner import GuardianScanner
from core.quarantine import QuarantineManager
from core.notifier import GuardianNotifier
from database.database import GuardianDatabase


class ScanWorker(QObject):
    progress = Signal(int)
    maximum = Signal(int)
    current_file = Signal(str)
    finished = Signal(int)
    error = Signal(str)

    def __init__(self, folders):
        super().__init__()
        self.folders = folders
        self.cancelled = Event()

    def run(self):
        db = None
        scanned = 0
        try:
            scanner = GuardianScanner()
            db = GuardianDatabase()
            quarantine = QuarantineManager()
            files = set()
            def walk_error(exc):
                self.error.emit(str(exc))
            for folder in self.folders:
                for directory, dirs, names in os.walk(folder, onerror=walk_error, followlinks=False):
                    if self.cancelled.is_set():
                        return
                    base = Path(directory)
                    if base.resolve().is_relative_to(QUARANTINE.resolve()):
                        dirs[:] = []
                        continue
                    dirs[:] = [d for d in dirs if not (base / d).is_symlink()]
                    for name in names:
                        path = (base / name).absolute()
                        if not path.is_symlink() and path.is_file():
                            files.add(path)
            self.maximum.emit(len(files))
            for file in sorted(files):
                if self.cancelled.is_set():
                    break
                self.current_file.emit(str(file))
                result = scanner.scan_file(file)
                status, virus = result["status"], result.get("virus")
                db.add_scan(str(file), status, virus)
                if status == "error":
                    self.error.emit(f"{file}: {virus}")
                if status == "found":
                    try:
                        quarantine.quarantine(file, virus)
                        GuardianNotifier.notify("Guardian", f"Threat quarantined: {file.name}")
                    except Exception as exc:
                        self.error.emit(f"Could not quarantine {file}: {exc}")
                scanned += 1
                self.progress.emit(scanned)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            if db:
                db.close()
            self.finished.emit(scanned)
