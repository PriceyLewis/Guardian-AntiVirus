from pathlib import Path
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.scanner import GuardianScanner
from core.quarantine import QuarantineManager
from core.notifier import GuardianNotifier
from database.database import GuardianDatabase


class GuardianWatcher(FileSystemEventHandler):

    def __init__(self):
        self.scanner = GuardianScanner()
        self.db = GuardianDatabase()
        self.quarantine = QuarantineManager()

    def on_created(self, event):

        if event.is_directory:
            return

        file = Path(event.src_path)

        # Give the download time to finish
        time.sleep(2)

        try:
            result = self.scanner.scan_file(file)

            status = result.get("status", "error")
            virus = result.get("virus")

        except Exception:
            status = "error"
            virus = None

        self.db.add_scan(str(file), status, virus)

        if status == "found":

            self.quarantine.quarantine(file, virus)

            GuardianNotifier.notify(
                "Guardian",
                f"Threat quarantined:\n{file.name}"
            )


class Watcher:

    def __init__(self):

        self.observer = Observer()

    def start(self):

        handler = GuardianWatcher()

        folders = [
            Path.home() / "Downloads",
            Path.home() / "Desktop",
            Path.home() / "Documents",
        ]

        for folder in folders:

            if folder.exists():

                self.observer.schedule(
                    handler,
                    str(folder),
                    recursive=True
                )

        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()