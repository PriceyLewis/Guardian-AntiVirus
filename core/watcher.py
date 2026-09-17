from pathlib import Path
from threading import Event
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from core.scanner import GuardianScanner
from core.quarantine import QuarantineManager
from core.notifier import GuardianNotifier
from database.database import GuardianDatabase
from core.paths import QUARANTINE


class GuardianWatcher(FileSystemEventHandler):
    def __init__(self):
        self.scanner = None
        self.stopping = Event()
        self.quarantine = QuarantineManager()
        self.last_error = None

    def on_created(self, event):
        if not event.is_directory:
            self.scan(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.scan(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.scan(event.dest_path)

    def on_closed(self, event):
        if not event.is_directory:
            self.scan(event.src_path)

    def scan(self, path):
        if self.stopping.is_set():
            return
        file = Path(path)
        if file.is_symlink() or not file.is_file() or file.resolve().is_relative_to(QUARANTINE.resolve()):
            return
        db = None
        try:
            if self.scanner is None:
                self.scanner = GuardianScanner()
            result = self.scanner.scan_file(file)
            if self.stopping.is_set():
                return
            db = GuardianDatabase()  # Created and closed on the observer's thread.
            db.add_scan(str(file.absolute()), result["status"], result.get("virus"))
            if result["status"] == "error":
                self.last_error = result.get("virus") or "Scan failed"
            if result["status"] == "found":
                self.quarantine.quarantine(file, result.get("virus"))
                GuardianNotifier.notify("Guardian", f"Threat quarantined: {file.name}")
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            if db:
                db.close()


class Watcher:
    def __init__(self):
        self.observer = None
        self.handler = None
        self.retired = []

    def start(self):
        if self.observer and self.observer.is_alive():
            self.handler.stopping.clear()
            self.handler.last_error = None
            return
        # A previous observer may still be finishing an engine call.
        if any(observer.is_alive() for observer in self.retired):
            raise RuntimeError("Monitoring is stopping. Try enabling it again in a moment.")
        self.retired.clear()
        self.observer = Observer()
        self.handler = GuardianWatcher()
        count = 0
        for name in ("Downloads", "Desktop", "Documents"):
            folder = Path.home() / name
            if folder.is_dir():
                self.observer.schedule(self.handler, str(folder), recursive=True)
                count += 1
        if not count:
            raise RuntimeError("No Downloads, Desktop or Documents folders found")
        try:
            self.observer.start()
        except Exception:
            self.observer.stop()
            if self.observer.is_alive():
                self.observer.join()
            raise

    def stop(self, wait=False):
        if self.handler:
            self.handler.stopping.set()
        if not wait:
            return
        if self.observer:
            self.observer.stop()
            self.retired.append(self.observer)
            self.observer = None
        if wait:
            for observer in self.retired:
                if observer.ident is not None:
                    observer.join()
            self.retired.clear()
