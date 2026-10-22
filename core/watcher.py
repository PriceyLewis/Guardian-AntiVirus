import time
from pathlib import Path
from threading import Event, Lock, Thread
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from core.scanner import GuardianScanner
from core.quarantine import QuarantineManager
from core.notifier import GuardianNotifier
from database.database import GuardianDatabase
from core.paths import QUARANTINE, is_excluded, is_guardian_storage

# Browsers write here first and rename on completion, which raises a move event.
PARTIAL_DOWNLOADS = (".part", ".partial", ".crdownload", ".download")
# A file must be quiet this long before it is scanned, so active writes finish first.
SETTLE_SECONDS = 1.0


class GuardianWatcher(FileSystemEventHandler):
    def __init__(self):
        self.scanner = None
        self.stopping = Event()
        self.quarantine = QuarantineManager()
        self.last_error = None
        # (mtime, size) of the last scanned version, so one write that raises
        # created, modified and closed events is only scanned once.
        self.scanned = {}
        self.pending = {}
        self.lock = Lock()
        self.closed = Event()
        self.thread = None

    def on_created(self, event):
        if not event.is_directory:
            self.queue(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.queue(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.queue(event.dest_path)

    def on_closed(self, event):
        if not event.is_directory:
            self.queue(event.src_path)

    def queue(self, path):
        """Schedule a scan once the file stops changing; keeps the observer thread free."""
        if self.stopping.is_set() or self.closed.is_set() or str(path).lower().endswith(PARTIAL_DOWNLOADS):
            return
        with self.lock:
            self.pending[str(path)] = time.monotonic() + SETTLE_SECONDS
            if self.thread is None:
                self.thread = Thread(target=self.process, name="guardian-monitor", daemon=True)
                self.thread.start()

    def process(self):
        while not self.closed.wait(0.2):
            now = time.monotonic()
            with self.lock:
                due = [path for path, at in self.pending.items() if at <= now]
                for path in due:
                    del self.pending[path]
            for path in due:
                if self.closed.is_set():
                    return
                self.scan(path)

    def close(self):
        self.closed.set()
        with self.lock:
            self.pending.clear()
            thread = self.thread
        if thread:
            thread.join()

    def scan(self, path):
        if self.stopping.is_set():
            return
        file = Path(path)
        try:
            if file.is_symlink() or not file.is_file() or is_guardian_storage(file, QUARANTINE):
                return
            stat = file.stat()
        except OSError:
            return
        signature = (stat.st_mtime_ns, stat.st_size)
        if self.scanned.get(file) == signature:
            return
        db = None
        try:
            db = GuardianDatabase()  # Created and closed on the scanning thread.
            if is_excluded(file, db.get_exclusions()):
                return
            if self.scanner is None:
                self.scanner = GuardianScanner()
            result = self.scanner.scan_file(file)
            if self.stopping.is_set():
                return
            db.add_scan(str(file.absolute()), result["status"], result.get("virus"))
            if result["status"] == "error":
                self.last_error = result.get("virus") or "Scan failed"
            else:
                if len(self.scanned) > 10000:
                    self.scanned.clear()
                self.scanned[file] = signature
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
        self.schedule()
        try:
            self.observer.start()
        except Exception:
            self.observer.stop()
            if self.observer.is_alive():
                self.observer.join()
            raise

    def schedule(self):
        db = GuardianDatabase()
        try:
            folders = [Path(f) for f in db.get_monitored_folders()]
        finally:
            db.close()
        count = 0
        for folder in folders:
            if folder.is_dir():
                self.observer.schedule(self.handler, str(folder), recursive=True)
                count += 1
        if not count:
            raise RuntimeError("None of the monitored folders exist. Add one in Settings.")

    def reschedule(self):
        """Apply an edited monitored-folder list without restarting the observer."""
        if self.observer and self.observer.is_alive():
            self.observer.unschedule_all()
            self.schedule()

    def stop(self, wait=False):
        if self.handler:
            self.handler.stopping.set()
            with self.handler.lock:
                self.handler.pending.clear()
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
            if self.handler:
                self.handler.close()
