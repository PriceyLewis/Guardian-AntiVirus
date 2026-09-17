from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QCheckBox,
)

from config import load_config, save_config
from core.startup import set_startup
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QMessageBox


class SettingsPage(QWidget):
    changed = Signal(dict)

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        title = QLabel("Settings")
        title.setObjectName("title")
        layout.addWidget(title)

        self.realtime = QCheckBox("Enable Real-Time Protection")
        self.notifications = QCheckBox("Enable Notifications")
        self.archives = QCheckBox("Scan ZIP/RAR Archives")
        self.startup = QCheckBox("Start Guardian on Login")

        layout.addWidget(self.realtime)
        layout.addWidget(self.notifications)
        layout.addWidget(self.archives)
        layout.addWidget(self.startup)

        layout.addStretch()

        self.load_settings()

        self.realtime.stateChanged.connect(self.save_settings)
        self.notifications.stateChanged.connect(self.save_settings)
        self.archives.stateChanged.connect(self.save_settings)
        self.startup.stateChanged.connect(self.save_settings)

    def load_settings(self):
        settings = load_config()

        self.realtime.setChecked(
            settings["realtime"]
        )

        self.notifications.setChecked(
            settings["notifications"]
        )

        self.archives.setChecked(
            settings["archives"]
        )

        self.startup.setChecked(
            settings["startup"]
        )

    def save_settings(self):
        settings = {
            "realtime": self.realtime.isChecked(),
            "notifications": self.notifications.isChecked(),
            "archives": self.archives.isChecked(),
            "startup": self.startup.isChecked(),
        }

        try:
            set_startup(settings["startup"])
            save_config(settings)
        except OSError as exc:
            QMessageBox.critical(self, "Settings could not be saved", str(exc))
            return
        self.changed.emit(settings)
