import re
from PySide6.QtCore import Qt, Signal, QSignalBlocker, QProcess, QTimer
from PySide6.QtWidgets import QWidget, QFrame, QVBoxLayout, QHBoxLayout, QCheckBox, QMessageBox, QListWidget, QFileDialog
from config import load_config, DEFAULTS
from core.definitions import describe
from database.database import GuardianDatabase
from core.preferences import apply_preferences
from core.startup import startup_path
from ui.components import heading, card, label, button


class FolderList(QFrame):
    """Card listing user-managed folders stored in one of the database folder tables."""

    def __init__(self, table, title, description, empty_text, changed):
        super().__init__()
        self.setObjectName("card")
        self.table = table
        self.empty_text = empty_text
        self.changed = changed
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(label(title, "sectionTitle"))
        layout.addWidget(label(description))
        self.list = QListWidget()
        self.list.setMinimumHeight(90)
        self.list.setMaximumHeight(150)
        layout.addWidget(self.list)
        actions = QHBoxLayout()
        actions.addWidget(button("Add folder…", self.add))
        self.remove_button = button("Remove", self.remove)
        actions.addWidget(self.remove_button)
        actions.addStretch()
        layout.addLayout(actions)
        self.list.itemSelectionChanged.connect(lambda: self.remove_button.setEnabled(bool(self.list.selectedItems())))
        self.load()

    def load(self):
        db = GuardianDatabase()
        try:
            folders = db.get_folders(self.table)
        finally:
            db.close()
        self.list.clear()
        self.list.addItems(folders)
        if not folders:
            self.list.addItem(self.empty_text)
            self.list.item(0).setFlags(self.list.item(0).flags() & ~Qt.ItemFlag.ItemIsSelectable & ~Qt.ItemFlag.ItemIsEnabled)
        self.remove_button.setEnabled(False)

    def folders(self):
        return [self.list.item(i).text() for i in range(self.list.count()) if self.list.item(i).flags() & Qt.ItemFlag.ItemIsEnabled]

    def add(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose folder")
        if not folder:
            return
        db = GuardianDatabase()
        try:
            db.add_folder(self.table, folder)
        finally:
            db.close()
        self.load()
        self.changed(self.table, "Added " + folder)

    def remove(self):
        items = self.list.selectedItems()
        if not items:
            return
        folder = items[0].text()
        db = GuardianDatabase()
        try:
            db.remove_folder(self.table, folder)
        finally:
            db.close()
        self.load()
        self.changed(self.table, "Removed " + folder)


class SettingsPage(QWidget):
    changed = Signal(dict)
    monitored_changed = Signal()
    definitions_updated = Signal()

    def __init__(self):
        super().__init__()
        self.runtime_apply = None
        self.process = None
        self.controls = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(18)
        heading(layout, "Settings", "Changes save automatically. Each option explains when it takes effect.")
        for title, description, rows in [
            ("Protection", "Monitoring covers the folders listed under Monitored folders.", [
                ("realtime", "Monitor files in real time", "Scan created, changed and moved files. Turning this off stops new monitoring work; an engine call may still be finishing."),
                ("archives", "Inspect archives", "Apply to subsequent scans. When off, Guardian uses clamscan with archive inspection disabled. Daemon limits still apply when on."),
                ("scheduled_scan", "Run a daily quick scan", "While Guardian is running, start a quick scan when no scan has run in the last 24 hours.")]),
            ("Desktop", "Control how Guardian fits into your desktop.", [
                ("notifications", "Show desktop notifications", "Receive a notification when a threat is quarantined. Requires a working desktop notification service."),
                ("startup", "Start Guardian at login", "Create a login entry for this installation and Python environment. Takes effect at your next desktop login."),
                ("close_to_tray", "Keep running when the window closes", "Hide to the system tray when available. Otherwise closing the window exits Guardian.")])]:
            frame, group = card(title, description)
            for key, text, detail in rows:
                toggle = QCheckBox(text)
                toggle.setAccessibleDescription(detail)
                self.controls[key] = toggle
                setattr(self, key, toggle)
                group.addWidget(toggle)
                group.addWidget(label(detail))
            layout.addWidget(frame)
        self.monitored = FolderList("monitored_folders", "Monitored folders", "Real-time monitoring watches these folders and their subfolders.", "No folders monitored. Real-time monitoring needs at least one.", self.folders_changed)
        layout.addWidget(self.monitored)
        self.exclusions = FolderList("exclusions", "Excluded folders", "Scans and real-time monitoring skip these folders and everything inside them. Exclude only folders you trust.", "No folders excluded.", self.folders_changed)
        layout.addWidget(self.exclusions)
        frame, group = card("Checks & maintenance", "Check the installed command-line engine, update virus definitions and test desktop integration.")
        actions = QHBoxLayout()
        self.engine_button = button("Check scan engine", self.check_engine)
        self.update_button = button("Update definitions", self.update_definitions)
        self.notification_button = button("Test notification", self.test_notification)
        actions.addWidget(self.engine_button)
        actions.addWidget(self.update_button)
        actions.addWidget(self.notification_button)
        actions.addStretch()
        group.addLayout(actions)
        self.check_result = label("Engine and definition freshness have not been verified.")
        self.startup_status = label("")
        group.addWidget(self.check_result)
        group.addWidget(self.startup_status)
        layout.addWidget(frame)
        footer = QHBoxLayout()
        self.feedback = label("Settings saved", "feedback")
        footer.addWidget(self.feedback, 1)
        self.reset_button = button("Restore defaults", self.reset_defaults)
        footer.addWidget(self.reset_button)
        layout.addLayout(footer)
        layout.addStretch()
        self.load_settings()
        for toggle in self.controls.values():
            toggle.toggled.connect(self.save_settings)

    def load_settings(self):
        settings = load_config()
        for key, toggle in self.controls.items():
            blocker = QSignalBlocker(toggle)
            toggle.setChecked(settings[key])
            del blocker
        self.notification_button.setEnabled(settings["notifications"] and self.process is None)
        exists = startup_path().is_file()
        self.startup_status.setText("Login entry: " + ("installed" if exists else "not installed"))
        if exists != settings["startup"]:
            self.startup_status.setText("Login entry differs from saved preference. Toggle Start Guardian at login off/on to repair it.")

    def folders_changed(self, table, text):
        self.feedback.setText(text)
        if table == "monitored_folders":
            self.monitored_changed.emit()

    def save_settings(self):
        settings = {key: toggle.isChecked() for key, toggle in self.controls.items()}
        try:
            apply_preferences(settings, self.runtime_apply)
        except Exception as exc:
            self.feedback.setText("Could not apply settings: " + str(exc))
            self.load_settings()
            return False
        self.load_settings()
        self.feedback.setText("Settings saved and applied")
        self.changed.emit(settings)
        return True

    def reset_defaults(self):
        if QMessageBox.question(self, "Restore defaults", "Restore all settings to their defaults?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        for key, toggle in self.controls.items():
            blocker = QSignalBlocker(toggle)
            toggle.setChecked(DEFAULTS[key])
            del blocker
        self.save_settings()

    def check_engine(self):
        self.start_check("clamscan", ["--version"], "engine")

    def update_definitions(self):
        # Downloads can take minutes on a slow connection.
        self.start_check("freshclam", ["--stdout"], "update", timeout=5 * 60 * 1000)

    def test_notification(self):
        if load_config()["notifications"]:
            self.start_check("notify-send", ["--", "Guardian", "Desktop notifications are enabled."], "notification")

    def start_check(self, program, args, kind, timeout=10000):
        if self.process is not None:
            return
        self.check_kind = kind
        self.check_timed_out = False
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.finished.connect(self.check_finished)
        self.process.errorOccurred.connect(self.check_error)
        self.check_timer = QTimer(self)
        self.check_timer.setSingleShot(True)
        self.check_timer.timeout.connect(self.check_timeout)
        self.engine_button.setEnabled(False)
        self.update_button.setEnabled(False)
        self.notification_button.setEnabled(False)
        self.check_result.setText("Updating definitions…" if kind == "update" else "Checking…")
        self.process.start(program, args)
        self.check_timer.start(timeout)

    def check_timeout(self):
        self.check_timed_out = True
        if self.process:
            self.process.kill()

    def check_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            missing = "freshclam is not installed. Install your distribution's ClamAV FreshClam package." if self.check_kind == "update" else None
            self.finish_check(missing or "Check unavailable: " + self.process.errorString())

    def check_finished(self, code, exit_status):
        if self.process is None:
            return
        output = bytes(self.process.readAllStandardOutput()).decode(errors="replace").strip()
        if self.check_timed_out:
            text = "Check timed out. Try again or inspect your ClamAV installation."
        elif self.check_kind == "update":
            text = self.update_result(code == 0 and exit_status == QProcess.ExitStatus.NormalExit, output)
        elif code != 0 or exit_status != QProcess.ExitStatus.NormalExit:
            text = "Check failed: " + (output or "Desktop service or command returned an error.")
        elif self.check_kind == "engine":
            text = describe(output)[0] + " — Version check only; detection is not verified."
        else:
            text = "Notification request sent to your desktop. Check that it appeared."
        self.finish_check(text)

    def update_result(self, success, output):
        if success:
            self.definitions_updated.emit()
            return "Definitions are up to date."
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        detail = next((line for line in lines if "ERROR" in line), lines[-1] if lines else "freshclam returned an error")
        # Drop freshclam's "ERROR: <timestamp> ->" log prefix.
        detail = re.sub(r"^ERROR:\s*(?:.*?->\s*)?", "", detail).rstrip(".") + "."
        # Packaged FreshClam usually runs as a service that owns its log and database.
        return ("Update failed: " + detail + " If your system runs the FreshClam service, it updates definitions automatically; "
                "otherwise run 'sudo freshclam' in a terminal.")

    def finish_check(self, text):
        self.check_result.setText(text)
        self.check_timer.stop()
        self.check_timer.deleteLater()
        self.process.deleteLater()
        self.process = None
        self.engine_button.setEnabled(True)
        self.update_button.setEnabled(True)
        self.notification_button.setEnabled(load_config()["notifications"])

    def shutdown(self):
        if self.process:
            self.check_timer.stop()
            self.process.blockSignals(True)
            self.process.kill()
            self.process.waitForFinished(1000)
            self.process.deleteLater()
            self.process = None
