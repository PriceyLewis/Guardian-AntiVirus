from datetime import datetime
from PySide6.QtCore import Slot
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QProgressBar, QFileDialog
from core.scan_manager import ScanManager
from database.database import GuardianDatabase
from ui.widgets import StatCard, ProtectionCard, RecentActivityCard
from ui.components import heading, card, label, button


class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        self.db = GuardianDatabase()
        self.scan_manager = ScanManager()
        self.scan_errors = []
        self.last_summary = None
        self.scan_active = False
        self.closing = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(18)
        heading(layout, "Overview", "Your scans, protection activity and quarantined files in one place.")
        self.protection = ProtectionCard()
        layout.addWidget(self.protection)
        stats = QHBoxLayout()
        self.files_card = StatCard("Files processed", 0)
        self.threats_card = StatCard("Detections", 0)
        self.quarantine_card = StatCard("In quarantine", 0)
        for item in (self.files_card, self.threats_card, self.quarantine_card):
            stats.addWidget(item)
        layout.addLayout(stats)
        frame, group = card("Start a scan", "Choose the area you want to check. Quarantined files and symbolic links are excluded.")
        self.buttons = QWidget()
        self.buttons.setObjectName("scanButtons")
        actions = QGridLayout(self.buttons)
        actions.setContentsMargins(0, 0, 0, 0)
        self.buttons.quick = button("Quick scan", self.quick_scan, "primary")
        self.buttons.full = button("Home scan", self.full_scan)
        self.buttons.custom = button("Choose folder…", self.custom_scan)
        for i, (control, text) in enumerate([(self.buttons.quick, "Downloads, Desktop & Documents"), (self.buttons.full, "All files in your home folder"), (self.buttons.custom, "A folder you select")]):
            actions.addWidget(control, 0, i)
            actions.addWidget(label(text), 1, i)
            actions.setColumnStretch(i, 1)
        group.addWidget(self.buttons)
        row = QHBoxLayout()
        self.scan_state = label("Ready to scan", "sectionTitle")
        row.addWidget(self.scan_state, 1)
        self.cancel_button = button("Cancel scan", self.cancel_scan)
        self.cancel_button.setEnabled(False)
        row.addWidget(self.cancel_button)
        group.addLayout(row)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        group.addWidget(self.progress)
        self.current_file = label("Scan results will appear here.")
        self.current_file.setMinimumWidth(0)
        group.addWidget(self.current_file)
        self.result_text = label("")
        self.result_text.hide()
        group.addWidget(self.result_text)
        self.error_text = label("")
        self.error_text.setObjectName("warning")
        self.error_text.hide()
        group.addWidget(self.error_text)
        layout.addWidget(frame)
        self.activity = RecentActivityCard()
        layout.addWidget(self.activity)
        layout.addStretch()
        self.refresh_dashboard()

    def refresh_dashboard(self):
        self.files_card.set_value(self.db.get_scan_count())
        self.threats_card.set_value(self.db.get_threat_count())
        self.quarantine_card.set_value(self.db.get_quarantine_count())
        self.activity.update_activity(self.db.recent_scans(5))

    def start_scan(self, scan_function, name="Scan"):
        if self.scan_active or (self.scan_manager.thread and self.scan_manager.thread.isRunning()):
            return
        self.scan_errors = []
        self.last_summary = None
        self.scan_active = True
        self.buttons.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress.setRange(0, 0)
        self.scan_state.setText(name + " · Preparing")
        self.current_file.setText("Collecting files…")
        self.result_text.clear()
        self.result_text.hide()
        self.error_text.hide()
        self.error_text.clear()
        scan_function(progress_callback=self.update_progress, maximum_callback=self.set_maximum,
                      current_file_callback=self.set_current_file, finished_callback=self.scan_finished,
                      error_callback=self.scan_error, summary_callback=self.receive_summary)

    def quick_scan(self):
        self.start_scan(self.scan_manager.quick_scan, "Quick scan")

    def full_scan(self):
        self.start_scan(self.scan_manager.full_scan, "Home scan")

    def custom_scan(self):
        if self.scan_active:
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose folder to scan")
        if folder:
            self.start_scan(lambda **kwargs: self.scan_manager.custom_scan(folder, **kwargs), "Custom scan")

    def cancel_scan(self):
        self.scan_manager.cancel()
        self.cancel_button.setEnabled(False)
        self.scan_state.setText("Stopping after the current file…")

    @Slot(int)
    def set_maximum(self, maximum):
        self.progress.setRange(0, max(maximum, 1))

    @Slot(str)
    def set_current_file(self, path):
        self.current_file.setText(path if len(path) < 140 else "…" + path[-139:])
        self.current_file.setToolTip(path)

    @Slot(str)
    def scan_error(self, message):
        if len(self.scan_errors) < 3:
            self.scan_errors.append(message)

    @Slot(int)
    def update_progress(self, scanned):
        self.progress.setValue(scanned)

    @Slot(dict)
    def receive_summary(self, summary):
        self.last_summary = summary

    @Slot(int)
    def scan_finished(self, scanned):
        if self.closing:
            return
        self.scan_active = False
        self.buttons.setEnabled(True)
        self.cancel_button.setEnabled(False)
        summary = self.last_summary or {"cancelled": False, "errors": len(self.scan_errors), "found": 0, "clean": 0, "quarantined": 0}
        state = "Scan cancelled" if summary["cancelled"] else ("Finished with errors" if summary["errors"] else "Scan complete")
        self.scan_state.setText(state)
        if not summary["cancelled"]:
            self.progress.setRange(0, max(scanned, 1))
            self.progress.setValue(scanned)
        self.current_file.setText("No files checked." if not scanned else f"{scanned:,} files processed")
        self.result_text.show()
        self.error_text.setVisible(bool(self.scan_errors))
        self.result_text.setText(f"Clean: {summary['clean']}   •   Detections: {summary['found']}   •   Quarantined: {summary['quarantined']}   •   Errors: {summary['errors']}")
        self.error_text.setText("\n".join(self.scan_errors))
        self.protection.last_scan.setText(state + " · " + datetime.now().strftime("%d %b, %H:%M"))
        self.refresh_dashboard()
