from PySide6.QtCore import Signal, QSignalBlocker, QProcess, QTimer
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QMessageBox
from config import load_config, DEFAULTS
from core.preferences import apply_preferences
from core.startup import startup_path
from ui.components import heading, card, label, button


class SettingsPage(QWidget):
    changed = Signal(dict)

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
            ("Protection", "Monitoring covers Downloads, Desktop and Documents when those folders exist.", [
                ("realtime", "Monitor files in real time", "Scan created, changed and moved files. Turning this off stops new monitoring work; an engine call may still be finishing."),
                ("archives", "Inspect archives", "Apply to subsequent scans. When off, Guardian uses clamscan with archive inspection disabled. Daemon limits still apply when on.")]),
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
        frame, group = card("Checks & maintenance", "Check the installed command-line engine and desktop integration.")
        actions = QHBoxLayout()
        self.engine_button = button("Check scan engine", self.check_engine)
        self.notification_button = button("Test notification", self.test_notification)
        actions.addWidget(self.engine_button)
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

    def test_notification(self):
        if load_config()["notifications"]:
            self.start_check("notify-send", ["--", "Guardian", "Desktop notifications are enabled."], "notification")

    def start_check(self, program, args, kind):
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
        self.notification_button.setEnabled(False)
        self.check_result.setText("Checking…")
        self.process.start(program, args)
        self.check_timer.start(10000)

    def check_timeout(self):
        self.check_timed_out = True
        if self.process:
            self.process.kill()

    def check_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.finish_check("Check unavailable: " + self.process.errorString())

    def check_finished(self, code, exit_status):
        if self.process is None:
            return
        output = bytes(self.process.readAllStandardOutput()).decode(errors="replace").strip()
        if self.check_timed_out:
            text = "Check timed out. Try again or inspect your ClamAV installation."
        elif code != 0 or exit_status != QProcess.ExitStatus.NormalExit:
            text = "Check failed: " + (output or "Desktop service or command returned an error.")
        elif self.check_kind == "engine":
            text = (output or "ClamAV command available") + " — Version check only; detection and definition freshness are not verified."
        else:
            text = "Notification request sent to your desktop. Check that it appeared."
        self.finish_check(text)

    def finish_check(self, text):
        self.check_result.setText(text)
        self.check_timer.stop()
        self.check_timer.deleteLater()
        self.process.deleteLater()
        self.process = None
        self.engine_button.setEnabled(True)
        self.notification_button.setEnabled(load_config()["notifications"])

    def shutdown(self):
        if self.process:
            self.check_timer.stop()
            self.process.disconnect()
            self.process.kill()
            self.process.waitForFinished(1000)
            self.process.deleteLater()
            self.process = None
