import time
from datetime import datetime
from threading import Thread
from PySide6.QtCore import QProcess, Qt, Signal, Slot
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QProgressBar, QFileDialog, QLineEdit
from core.scan_manager import ScanManager
from core.notifier import GuardianNotifier
from core.scanner import daemon_socket, describe_engine
from config import load_config
from database.database import GuardianDatabase
from ui.widgets import StatCard, ProtectionCard, RecentActivityCard
import sys
import core.paths as paths
from core import clamav, daemon, engines, updates, virustotal
from core.quarantine import sha256
from ui.components import heading, card, label, button, open_in_browser, steps_dialog


class DashboardPage(QWidget):
    # Path and SHA-256 (or empty text and an error) of a file fingerprinted for a lookup.
    fingerprinted = Signal(str, str, str)
    # A newer release found by the daily check (a dict), from a background thread.
    update_found = Signal(object)

    def __init__(self):
        super().__init__()
        self.db = GuardianDatabase()
        self.scan_manager = ScanManager()
        self.scan_errors = []
        self.last_summary = None
        self.scan_active = False
        self.scan_name = "Scan"
        self.closing = False
        self.daemon_connected = False
        self.daemon_checked = -DAEMON_CHECK_INTERVAL
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(18)
        heading(layout, "Overview", "Your scans, protection activity and quarantined files in one place.")
        frame, group = card()
        self.update_card = frame
        self.update_text = label("", "sectionTitle")
        group.addWidget(self.update_text)
        self.update_detail = label("")
        group.addWidget(self.update_detail)
        row = QHBoxLayout()
        self.update_button = button("Update now", self.install_update, "primary")
        self.restart_button = button("Restart Guardian", self.restart)
        self.notes_button = button("What's new", self.open_release_notes)
        for control in (self.update_button, self.restart_button, self.notes_button):
            row.addWidget(control)
        row.addStretch()
        group.addLayout(row)
        frame.hide()
        self.release = None
        self.update_process = None
        self.update_found.connect(self.show_update)
        layout.addWidget(frame)
        self.protection = ProtectionCard()
        self.daemon_button = button("Set up faster scanning…", self.show_daemon_steps)
        self.daemon_button.hide()
        self.protection.layout().addWidget(self.daemon_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.protection)
        stats = QHBoxLayout()
        self.files_card = StatCard("Files processed", 0)
        self.threats_card = StatCard("Detections", 0)
        self.quarantine_card = StatCard("In quarantine", 0)
        for item in (self.files_card, self.threats_card, self.quarantine_card):
            stats.addWidget(item)
        layout.addLayout(stats)
        frame, group = card("Start a scan", "Choose the area you want to check, or drop files and folders onto this window. Quarantined files, excluded folders and symbolic links are skipped.")
        self.buttons = QWidget()
        self.buttons.setObjectName("scanButtons")
        actions = QGridLayout(self.buttons)
        actions.setContentsMargins(0, 0, 0, 0)
        self.buttons.quick = button("Quick scan", self.quick_scan, "primary")
        self.buttons.full = button("Home scan", self.full_scan)
        self.buttons.custom = button("Choose folder…", self.custom_scan)
        self.buttons.files = button("Choose files…", self.file_scan)
        for i, (control, text) in enumerate([(self.buttons.quick, "Downloads, Desktop & Documents"), (self.buttons.full, "All files in your home folder"), (self.buttons.custom, "A folder you select"), (self.buttons.files, "Specific files you select")]):
            actions.addWidget(control, 0, i)
            actions.addWidget(label(text), 1, i)
            actions.setColumnStretch(i, 1)
        group.addWidget(self.buttons)
        row = QHBoxLayout()
        self.scan_state = label("Ready to scan", "sectionTitle")
        row.addWidget(self.scan_state, 1)
        self.pause_button = button("Pause", self.toggle_pause)
        self.pause_button.setEnabled(False)
        row.addWidget(self.pause_button)
        self.paused = False
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
        self.detections = []
        self.detections_button = button("Check detections on VirusTotal", self.lookup_detections)
        self.detections_button.setToolTip("Opens VirusTotal's report for each detected file in your browser. Only SHA-256 fingerprints are sent.")
        self.detections_button.hide()
        group.addWidget(self.detections_button, 0, Qt.AlignmentFlag.AlignLeft)
        self.error_text = label("")
        self.error_text.setObjectName("warning")
        self.error_text.hide()
        group.addWidget(self.error_text)
        layout.addWidget(frame)
        frame, group = card("Second opinion", "Look a file or link up on VirusTotal, which shows what about 70 antivirus engines say. Opens in your browser; files are never uploaded, only their SHA-256 fingerprint is sent.")
        row = QHBoxLayout()
        self.lookup_file_button = button("Look up a file…", self.lookup_file)
        row.addWidget(self.lookup_file_button)
        self.link = QLineEdit()
        self.link.setPlaceholderText("…or paste a link, e.g. https://example.com/download")
        self.link.setClearButtonEnabled(True)
        self.link.returnPressed.connect(self.lookup_link)
        row.addWidget(self.link, 1)
        row.addWidget(button("Look up link", self.lookup_link))
        group.addLayout(row)
        self.lookup_text = label("")
        self.lookup_text.hide()
        group.addWidget(self.lookup_text)
        self.fingerprinted.connect(self.file_fingerprinted)
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
        # This runs every few seconds on the interface thread, so ask the daemon only now and then.
        if time.monotonic() - self.daemon_checked >= DAEMON_CHECK_INTERVAL:
            self.daemon_connected = bool(daemon_socket(timeout=0.5))
            self.daemon_checked = time.monotonic()
            self.protection.second.setText(describe_second_opinion(engines.status(), self.db.get_suspicious_count()))
        connected = self.daemon_connected
        self.protection.engine.setText(describe_engine(connected, load_config()["archives"]))
        self.daemon_button.setVisible(not connected and not clamav.private_database())
        run = self.db.last_scan_run()
        if run:
            timestamp, name, scanned, found, errors, cancelled, duration = run
            state = "cancelled" if cancelled else ("finished with errors" if errors else "complete")
            when = datetime.fromisoformat(timestamp).strftime("%d %b, %H:%M")
            self.protection.last_scan.setText(f"Last scan: {name} {state} · {when} · {scanned:,} files in {format_duration(duration)}")

    def start_scan(self, scan_function, name="Scan", background=False):
        if self.scan_active or (self.scan_manager.thread and self.scan_manager.thread.isRunning()):
            return
        self.scan_errors = []
        self.last_summary = None
        self.scan_name = name
        self.scan_active = True
        self.buttons.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.pause_button.setEnabled(True)
        self.pause_button.setText("Pause")
        self.paused = False
        self.progress.setRange(0, 0)
        self.scan_state.setText(name + " · Preparing")
        self.current_file.setText("Collecting files…")
        self.result_text.clear()
        self.result_text.hide()
        self.detections_button.hide()
        self.error_text.hide()
        self.error_text.clear()
        scan_function(progress_callback=self.update_progress, maximum_callback=self.set_maximum,
                      current_file_callback=self.set_current_file, finished_callback=self.scan_finished,
                      error_callback=self.scan_error, summary_callback=self.receive_summary, background=background)

    def quick_scan(self, background=False):
        self.start_scan(self.scan_manager.quick_scan, "Quick scan", background)

    def full_scan(self, background=False):
        self.start_scan(self.scan_manager.full_scan, "Home scan", background)

    def custom_scan(self):
        if self.scan_active:
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose folder to scan")
        if folder:
            self.start_scan(lambda **kwargs: self.scan_manager.custom_scan(folder, **kwargs), "Custom scan")

    def file_scan(self):
        if self.scan_active:
            return
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files to scan")
        if files:
            self.scan_paths(files)

    def scan_paths(self, paths):
        """Scan any mix of files and folders, e.g. dropped onto the window."""
        self.start_scan(lambda **kwargs: self.scan_manager.scan_paths(paths, **kwargs), "Custom scan")

    def check_for_updates(self, force=False):
        """Ask GitHub about new releases in the background, at most once a day unless forced."""
        if not force and (not load_config()["check_updates"] or not updates.due()):
            return
        def work():
            release = updates.check()
            if release and not self.closing:
                self.update_found.emit(release)
        self.update_thread = Thread(target=work, name="guardian-update-check", daemon=True)
        self.update_thread.start()

    @Slot(object)
    def show_update(self, release):
        self.release = release
        kind = updates.install_kind()
        self.update_text.setText(f"Guardian {release['version']} is available")
        self.update_detail.setText(f"You have version {updates.VERSION}. "
                                   + ("Updating keeps your settings, history and quarantine." if kind == "environment" else updates.how_to_update(kind)))
        self.update_button.setVisible(kind == "environment")
        self.update_button.setEnabled(True)
        self.restart_button.hide()
        self.update_card.show()

    def install_update(self):
        if not self.release or self.update_process is not None:
            return
        command = updates.update_command(self.release)
        self.update_button.setEnabled(False)
        self.update_detail.setText("Downloading and installing… this can take a minute.")
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        process.finished.connect(self.update_finished)
        process.errorOccurred.connect(self.update_error)
        self.update_process = process
        process.start(command[0], command[1:])

    def update_finished(self, code, status):
        if self.update_process is None:
            return
        output = bytes(self.update_process.readAllStandardOutput()).decode(errors="replace")
        self.update_installed(code == 0 and status == QProcess.ExitStatus.NormalExit, output)

    def update_error(self, error):
        # finished is not emitted when the installer cannot start at all.
        if error == QProcess.ProcessError.FailedToStart:
            self.update_installed(False, "Could not start the installer.")

    def update_installed(self, success, output):
        if self.update_process is None:
            return
        self.update_process.deleteLater()
        self.update_process = None
        if success:
            self.update_text.setText(f"Guardian {self.release['version']} is installed")
            self.update_detail.setText("Restart Guardian to start using it.")
            self.update_button.hide()
            self.restart_button.show()
        else:
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            self.update_detail.setText("The update failed: " + (lines[-1] if lines else "unknown error") + " " + updates.how_to_update("system"))
            self.update_button.setEnabled(True)

    def restart(self):
        # The new instance waits for this one to release its lock.
        QProcess.startDetached(sys.executable, [str(paths.ROOT / "guardian.py"), "--restarted"])
        window = self.window()
        window.allow_close = True
        QApplication.instance().quit()

    def open_release_notes(self):
        open_in_browser(self.release["url"] if self.release else updates.RELEASES)

    def show_daemon_steps(self):
        self.steps_dialog = steps_dialog(self, "Set up the ClamAV daemon", daemon.setup_steps(daemon.family()))

    def lookup_detections(self):
        # A browser tab each; more than a few at once is unhelpful.
        urls = [virustotal.file_url(digest) for digest in self.detections[:MAX_REPORTS]]
        opened = sum(1 for url in urls if url and open_in_browser(url))
        more = f" The other {len(self.detections) - MAX_REPORTS} can be checked from History." if len(self.detections) > MAX_REPORTS else ""
        self.current_file.setText((f"Opened {opened} VirusTotal report{'s' if opened != 1 else ''} in your browser." if opened else "Could not open a browser. Use Check on VirusTotal in History or Quarantine.") + more)

    def show_lookup(self, text):
        self.lookup_text.setText(text)
        self.lookup_text.show()

    def open_report(self, url, what):
        if open_in_browser(url):
            self.show_lookup(f"Opened VirusTotal's report for {what} in your browser.")
        else:
            self.show_lookup("Could not open a browser. Visit this address instead: " + url)

    def lookup_link(self):
        url = virustotal.link_url(self.link.text())
        if url:
            self.open_report(url, self.link.text().strip())
        else:
            self.show_lookup("Enter a web address starting with http:// or https://, or a domain such as example.com.")

    def lookup_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to look up")
        if path:
            self.fingerprint_file(path)

    def fingerprint_file(self, path):
        self.lookup_file_button.setEnabled(False)
        self.show_lookup("Calculating the file's fingerprint…")
        # Large files take a while to read; keep the window responsive.
        def work():
            try:
                result = (sha256(path), "")
            except OSError as exc:
                result = ("", exc.strerror or str(exc))
            if not self.closing:
                self.fingerprinted.emit(path, *result)
        self.fingerprint_thread = Thread(target=work, daemon=True)
        self.fingerprint_thread.start()

    @Slot(str, str, str)
    def file_fingerprinted(self, path, digest, error):
        self.lookup_file_button.setEnabled(True)
        if error:
            self.show_lookup(f"Could not read {path}: {error}")
        else:
            self.open_report(virustotal.file_url(digest), path)
            self.lookup_text.setText(self.lookup_text.text() + " If VirusTotal has no report, no one has submitted this file before; that alone does not mean it is safe.")

    def toggle_pause(self):
        if not self.scan_active or not self.scan_manager.pause(not self.paused):
            return
        self.paused = not self.paused
        self.pause_button.setText("Resume" if self.paused else "Pause")
        self.scan_state.setText(self.scan_name + (" · Paused" if self.paused else " · Scanning"))
        if self.paused:
            self.current_file.setText("Paused. Files already checked are kept; choose Resume to carry on.")

    def cancel_scan(self):
        self.scan_manager.cancel()
        self.cancel_button.setEnabled(False)
        self.pause_button.setEnabled(False)
        self.scan_state.setText("Stopping after the current file…")

    @Slot(int)
    def set_maximum(self, maximum):
        self.progress.setRange(0, max(maximum, 1))
        # Files are collected; from here the engines are at work.
        if self.scan_active and not self.paused:
            self.scan_state.setText(self.scan_name + " · Scanning")

    @Slot(str)
    def set_current_file(self, path):
        if self.paused:
            return
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
        # The scan itself may have found the daemon gone.
        self.daemon_checked = -DAEMON_CHECK_INTERVAL
        self.scan_active = False
        self.buttons.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.pause_button.setEnabled(False)
        self.pause_button.setText("Pause")
        self.paused = False
        summary = self.last_summary or {"cancelled": False, "errors": len(self.scan_errors), "found": 0, "clean": 0, "quarantined": 0}
        state = "Scan cancelled" if summary["cancelled"] else ("Finished with errors" if summary["errors"] else "Scan complete")
        self.scan_state.setText(state)
        if not summary["cancelled"]:
            self.progress.setRange(0, max(scanned, 1))
            self.progress.setValue(scanned)
        self.current_file.setText("No files checked." if not scanned else f"{scanned:,} files processed")
        self.result_text.show()
        self.error_text.setVisible(bool(self.scan_errors))
        took = f"   •   Took {format_duration(summary['duration'])}" if "duration" in summary else ""
        unchanged = f" ({summary['unchanged']:,} unchanged, not rechecked)" if summary.get("unchanged") else ""
        self.detections = list(summary.get("detections", []))
        self.detections_button.setVisible(bool(self.detections))
        flagged = f"   •   Suspicious: {summary['flagged']} (see History)" if summary.get("flagged") else ""
        skipped = f"   •   Skipped: {summary['skipped']:,} large or media" if summary.get("skipped") else ""
        self.result_text.setText(f"Clean: {summary['clean']}{unchanged}   •   Detections: {summary['found']}   •   Quarantined: {summary['quarantined']}{flagged}   •   Errors: {summary['errors']}{skipped}{took}")
        self.error_text.setText("\n".join(self.scan_errors))
        self.refresh_dashboard()
        # Tray-started and scheduled scans may finish while the window is hidden.
        if not self.window().isVisible():
            found = f"{summary['found']} threat{'s' if summary['found'] != 1 else ''} found" if summary["found"] else "no threats found"
            GuardianNotifier.notify("Guardian", f"{self.scan_name}: {state.lower()}, {scanned:,} file{'s' if scanned != 1 else ''} checked, {found}.")


def describe_second_opinion(state, suspicious=0):
    """One line for the Overview page on what the extra engines have to work with."""
    parts = []
    if state["hash_lookup"] and state["hashes"]:
        parts.append(f"{state['hashes']:,} known-malware fingerprints")
    if state["yara_scan"] and state["yara_installed"] and state["rule_files"]:
        parts.append("YARA-X rules loaded")
    if not parts:
        wanted = state["hash_lookup"] or state["yara_scan"]
        text = "Second opinion: not set up · download threat lists in Settings" if wanted else "Second opinion: switched off"
    else:
        text = "Second opinion: " + " · ".join(parts)
    if suspicious:
        text += f" · {suspicious} suspicious file{'' if suspicious == 1 else 's'} to review in History"
    return text


# Seconds between checks for the daemon's socket.
DAEMON_CHECK_INTERVAL = 10
# Detections opened as VirusTotal reports by one click.
MAX_REPORTS = 3


def format_duration(seconds):
    seconds = int(round(seconds or 0))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"
