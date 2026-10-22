from datetime import datetime, timedelta
from PySide6.QtGui import QCloseEvent
from PySide6.QtCore import QProcess, QTimer
from PySide6.QtWidgets import QSystemTrayIcon
from config import load_config
from core.definitions import describe
from core.watcher import Watcher
from PySide6.QtWidgets import (
    QHBoxLayout,
    QVBoxLayout,
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


class PageStack(QStackedWidget):
    """Each page scrolls independently without imposing its height on other pages."""
    def addWidget(self, page):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(page)
        return super().addWidget(scroll)

    def widget(self, index):
        container = super().widget(index)
        return container.widget() if container else None


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.allow_close = False
        self.tray_hint_shown = False

        self.setWindowTitle("Guardian Antivirus")
        self.resize(1180, 820)
        self.setMinimumSize(880, 640)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)

        # Sidebar
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(185)
        self.sidebar.setObjectName("sidebar")

        pages = [
            "Overview",
            "Quick Scan",
            "Home Scan",
            "History",
            "Quarantine",
            "Settings"
        ]

        for page in pages:
            QListWidgetItem(page, self.sidebar)

        # Main pages
        self.stack = PageStack()

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
        self.stack.widget(5).runtime_apply = self.apply_settings
        self.stack.widget(5).changed.connect(lambda _: self.refresh_protection())
        try:
            self.apply_settings(load_config())
        except Exception as exc:
            self.watcher_error = str(exc)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_protection)
        self.timer.start(3000)
        self.definitions_process = None
        self.definitions_timer = QTimer(self)
        self.definitions_timer.timeout.connect(self.check_definitions)
        self.definitions_timer.start(6 * 60 * 60 * 1000)
        self.check_definitions()
        self.schedule_timer = QTimer(self)
        self.schedule_timer.timeout.connect(self.run_scheduled_scan)
        self.schedule_timer.start(60 * 1000)
        self.sidebar.setCurrentRow(0)

        sidebar_layout = QVBoxLayout()
        brand = QLabel("GUARDIAN")
        brand.setObjectName("brand")
        sidebar_layout.addWidget(brand)
        sidebar_layout.addWidget(self.sidebar, 1)
        footer = QLabel("ClamAV for your desktop\nBeta · Linux")
        footer.setObjectName("muted")
        sidebar_layout.addWidget(footer)
        layout.addLayout(sidebar_layout)
        layout.addWidget(self.stack, 1)

    def navigate(self, row):
        if row in (1, 2):
            self.sidebar.setCurrentRow(0)
            dashboard = self.stack.widget(0)
            (dashboard.quick_scan if row == 1 else dashboard.full_scan)()
            return
        self.stack.setCurrentIndex(row)
        self.stack.updateGeometry()
        page = self.stack.widget(row)
        if row == 5:
            page.load_settings()
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
            raise
        self.refresh_protection()

    def refresh_protection(self):
        active = self.watcher.observer and self.watcher.observer.is_alive() and not self.watcher.handler.stopping.is_set()
        error = self.watcher_error or (self.watcher.handler.last_error if active else None)
        status = "Folder monitoring is running" if active else "Real-time monitoring off"
        if error:
            status = "Protection needs attention: " + str(error)
        card = self.stack.widget(0).protection
        card.status.setText(status)
        card.status.setProperty("attention", bool(error) or not active)
        card.status.style().unpolish(card.status)
        card.status.style().polish(card.status)
        card.status.setWordWrap(True)
        card.realtime.setText("Real-Time Monitoring: " + ("Running" if active else "Off"))
        dashboard = self.stack.widget(0)
        # Monitoring writes history in the background; keep visible counts current.
        if self.stack.currentIndex() == 0 and not dashboard.scan_active and not dashboard.closing:
            dashboard.refresh_dashboard()
        if hasattr(self, "tray"):
            self.tray.status_action.setText("Scan in progress" if self.stack.widget(0).scan_active else status)

    def check_definitions(self):
        if self.definitions_process is not None:
            return
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        process.finished.connect(lambda *_: self.definitions_checked(bytes(process.readAllStandardOutput()).decode(errors="replace")))
        process.errorOccurred.connect(self.definitions_error)
        self.definitions_process = process
        process.start("clamscan", ["--version"])

    def definitions_error(self, error):
        # finished is not emitted when clamscan is missing.
        if error == QProcess.ProcessError.FailedToStart:
            self.definitions_checked("")

    def definitions_checked(self, output):
        if self.definitions_process is None:
            return
        self.definitions_process.deleteLater()
        self.definitions_process = None
        text, attention = describe(output)
        label = self.stack.widget(0).protection.definitions
        label.setText(text)
        label.setProperty("attention", attention)
        label.style().unpolish(label)
        label.style().polish(label)

    def run_scheduled_scan(self):
        dashboard = self.stack.widget(0)
        if not load_config()["scheduled_scan"] or dashboard.scan_active or dashboard.closing:
            return
        # Any run counts, so cancelling a scheduled scan postpones it to tomorrow.
        run = dashboard.db.last_scan_run()
        if run and datetime.now() - datetime.fromisoformat(run[0]) < timedelta(days=1):
            return
        dashboard.quick_scan()

    def shutdown(self):
        self.timer.stop()
        self.definitions_timer.stop()
        self.schedule_timer.stop()
        if self.definitions_process is not None:
            process, self.definitions_process = self.definitions_process, None
            process.blockSignals(True)
            process.kill()
            process.waitForFinished(1000)
        self.stack.widget(0).closing = True
        self.stack.widget(5).shutdown()
        self.watcher.stop(wait=True)
        self.stack.widget(0).scan_manager.shutdown()
        for row in (0, 3, 4):
            self.stack.widget(row).db.close()

    def closeEvent(self, event: QCloseEvent):
        if self.allow_close or not load_config()["close_to_tray"] or not QSystemTrayIcon.isSystemTrayAvailable():
            from PySide6.QtWidgets import QApplication
            QApplication.instance().quit()
            event.accept()
        else:
            self.hide()
            event.ignore()
            if hasattr(self, "tray") and not self.tray_hint_shown:
                self.tray_hint_shown = True
                self.tray.showMessage("Guardian is still running", "Guardian keeps protecting your folders from the system tray. Use the tray menu to quit.", QSystemTrayIcon.MessageIcon.Information, 4000)
