from pathlib import Path

from PySide6.QtCore import QObject, Signal

from core.scanner import GuardianScanner
from core.quarantine import QuarantineManager
from core.notifier import GuardianNotifier
from database.database import GuardianDatabase


class ScanWorker(QObject):
    progress = Signal(int)
    maximum = Signal(int)
    current_file = Signal(str)
    finished = Signal(int)

    def __init__(self, folders):
        super().__init__()
        self.folders = folders

    def run(self):
        scanner = GuardianScanner()
        db = GuardianDatabase()
        quarantine = QuarantineManager()

        files = []

        # Collect all files
        for folder in self.folders:
            folder = Path(folder)

            if folder.exists():
                files.extend(
                    [f for f in folder.rglob("*") if f.is_file()]
                )

        self.maximum.emit(len(files))

        scanned = 0

        for file in files:

            self.current_file.emit(file.name)

            try:
                result = scanner.scan_file(file)

                status = result.get("status", "error")
                virus = result.get("virus")

            except Exception:
                status = "error"
                virus = None

            # Save scan to database
            db.add_scan(
                str(file),
                status,
                virus
            )

            # Quarantine infected files
            if status == "found":
                quarantine.quarantine(file, virus)

                GuardianNotifier.notify(
                    "Guardian",
                    f"Threat quarantined:\n{file.name}"
                )

            scanned += 1

            self.progress.emit(scanned)

        self.finished.emit(scanned)