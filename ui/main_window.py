from PySide6.QtGui import QCloseEvent
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QSystemTrayIcon
from config import load_config
from core.watcher import Watcher
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QScrollArea,
    QWidget,
)

from ui.dashboard import DashboardPage
from ui.history import HistoryPage
from ui.quarantine import QuarantinePage
from ui.settings import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.allow_close = False

        self.setWindowTitle("Guardian Antivirus")
        self.resize(1280, 800)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)

        # Sidebar
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(220)

        pages = [
            "Dashboard",
            "Quick Scan",
            "Home Scan",
            "History",
            "Quarantine",
            "Settings"
        ]

        for page in pages:
            QListWidgetItem(page, self.sidebar)

        # Main pages
        self.stack = QStackedWidget()

        self.stack.addWidget(DashboardPage())
        self.stack.addWidget(QLabel("Quick Scan"))
        self.stack.addWidget(QLabel("Full Scan"))
        self.stack.addWidget(HistoryPage())
        self.stack.addWidget(QuarantinePage())
        self.stack.addWidget(SettingsPage())

        self.sidebar.currentRowChanged.connect(
            self.navigate
        )

        self.watcher = Watcher()
        self.watcher_error = None
        self.stack.widget(5).changed.connect(self.apply_settings)
        self.apply_settings(load_config())
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_protection)
        self.timer.start(3000)
        self.sidebar.setCurrentRow(0)

        layout.addWidget(self.sidebar)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.stack)
        layout.addWidget(scroll, 1)

    def navigate(self, row):
        if row in (1, 2):
            self.sidebar.setCurrentRow(0)
            dashboard = self.stack.widget(0)
            (dashboard.quick_scan if row == 1 else dashboard.full_scan)()
            return
        self.stack.setCurrentIndex(row)
        page = self.stack.widget(row)
        if hasattr(page, "refresh"):
            page.refresh()
        if row == 0:
            page.refresh_dashboard()

    def apply_settings(self, settings):
        try:
            if settings["realtime"]:
                self.watcher.start()
            else:
                self.watcher.stop()
            self.watcher_error = None
        except Exception as exc:
            self.watcher_error = str(exc)
        self.refresh_protection()

    def refresh_protection(self):
        active = self.watcher.observer and self.watcher.observer.is_alive()
        error = self.watcher_error or (self.watcher.handler.last_error if self.watcher.handler else None)
        status = "Monitoring selected folders; engine not verified" if active else "Real-time monitoring off"
        if error:
            status = "Protection needs attention: " + str(error)
        card = self.stack.widget(0).protection
        card.status.setText(status)
        card.status.setWordWrap(True)
        card.realtime.setText("Real-Time Monitoring: " + ("Running" if active else "Off"))
        if hasattr(self, "tray"):
            self.tray.status_action.setText(status)

    def shutdown(self):
        self.timer.stop()
        self.watcher.stop()
        self.stack.widget(0).scan_manager.shutdown()
        for row in (0, 3, 4):
            self.stack.widget(row).db.close()

    def closeEvent(self, event: QCloseEvent):
        if self.allow_close or not QSystemTrayIcon.isSystemTrayAvailable():
            event.accept()
        else:
            self.hide()
            event.ignore()
