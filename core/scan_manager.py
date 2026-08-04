from pathlib import Path

from PySide6.QtCore import QThread

from core.scan_worker import ScanWorker


class ScanManager:

    def __init__(self):
        self.thread = None
        self.worker = None

    def start_scan(
        self,
        folders,
        progress_callback=None,
        maximum_callback=None,
        current_file_callback=None,
        finished_callback=None,
    ):

        self.thread = QThread()
        self.worker = ScanWorker(folders)

        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)

        if maximum_callback:
            self.worker.maximum.connect(maximum_callback)

        if progress_callback:
            self.worker.progress.connect(progress_callback)

        if current_file_callback:
            self.worker.current_file.connect(current_file_callback)

        if finished_callback:
            self.worker.finished.connect(finished_callback)

        self.worker.finished.connect(self.thread.quit)

        self.thread.start()

    def quick_scan(self, **kwargs):

        folders = [
            Path.home() / "Downloads",
            Path.home() / "Desktop",
            Path.home() / "Documents",
        ]

        self.start_scan(folders, **kwargs)

    def full_scan(self, **kwargs):

        folders = [
            Path.home()
        ]

        self.start_scan(folders, **kwargs)

    def custom_scan(self, folder, **kwargs):

        self.start_scan([Path(folder)], **kwargs)