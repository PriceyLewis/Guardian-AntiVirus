from datetime import datetime, timedelta
from PySide6.QtGui import QCloseEvent, QKeySequence, QShortcut
from PySide6.QtCore import QProcess, QTimer
from PySide6.QtWidgets import QSystemTrayIcon
from config import load_config
from core.definitions import describe
from core.quarantine import QuarantineManager
from core.watcher import Watcher
from PySide6.QtWidgets import (
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QApplication,
    QScrollArea,
    QWidget,
)

from ui.dashboard import DashboardPage
from ui.history import HistoryPage
from ui.quarantine import QuarantinePage
from ui.settings import SettingsPage
from ui.theme import apply_theme, resolve


def scan_due(run, days, hour, now):
    """True when no scan ran since the latest scheduled slot.

    With hour -1 a slot opens every `days` days after the previous run; otherwise
    slots open at that hour, and a missed slot runs as soon as Guardian is open.
    """
    if not run:
        return True
    last = datetime.fromisoformat(run[0])
    if hour < 0:
        return now - last >= timedelta(days=days)
    slot = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if slot > now:
        slot -= timedelta(days=1)
    return last < slot - timedelta(days=days - 1)


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
        self.paused_until = None
        self.setAcceptDrops(True)

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
        # Ctrl+1-4 open Overview, History, Quarantine and Settings.
        self.page_shortcuts = {0: "Ctrl+1", 3: "Ctrl+2", 4: "Ctrl+3", 5: "Ctrl+4"}
        for row, keys in self.page_shortcuts.items():
            self.sidebar.item(row).setToolTip(keys)
            QShortcut(QKeySequence(keys), self, lambda row=row: self.sidebar.setCurrentRow(row))
        # Explicit keys: Qt's standard Quit and Refresh bindings are empty on some platforms.
        QShortcut(QKeySequence("Ctrl+F"), self, self.focus_search)
        QShortcut(QKeySequence("F5"), self, self.refresh_page)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.quit_guardian)

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
        self.stack.widget(5).changed.connect(self.settings_changed)
        self.stack.widget(5).monitored_changed.connect(self.monitored_folders_changed)
        self.stack.widget(5).definitions_updated.connect(self.check_definitions)
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
        # An explicit monitoring choice in Settings replaces any tray pause.
        self.paused_until = None
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

    def current_page(self):
        return self.stack.widget(self.stack.currentIndex())

    def focus_search(self):
        page = self.current_page()
        if hasattr(page, "search"):
            page.search.setFocus()
            page.search.selectAll()

    def refresh_page(self):
        page = self.current_page()
        (page.refresh_dashboard if self.stack.currentIndex() == 0 else getattr(page, "refresh", lambda: None))()

    def quit_guardian(self):
        self.allow_close = True
        QApplication.instance().quit()

    def settings_changed(self, settings):
        app = QApplication.instance()
        # Only restyle when the effective theme changes; it repaints every widget.
        if app.styleSheet() and resolve(app, settings["theme"]) != app.property("guardianTheme"):
            apply_theme(app, settings["theme"])
        self.refresh_protection()

    def pause_monitoring(self, minutes=60):
        if not load_config()["realtime"]:
            return
        self.watcher.stop()
        self.paused_until = datetime.now() + timedelta(minutes=minutes)
        self.refresh_protection()

    def resume_monitoring(self):
        self.paused_until = None
        if load_config()["realtime"]:
            try:
                self.watcher.start()
                self.watcher_error = None
            except Exception as exc:
                self.watcher_error = str(exc)
        self.refresh_protection()

    def monitored_folders_changed(self):
        try:
            if self.watcher.observer and self.watcher.observer.is_alive():
                self.watcher.reschedule()
            elif load_config()["realtime"] and not self.paused_until:
                self.watcher.start()
            self.watcher_error = None
        except Exception as exc:
            self.watcher_error = str(exc)
        self.refresh_protection()

    def dragEnterEvent(self, event):
        urls = event.mimeData().urls()
        if urls and all(url.isLocalFile() for url in urls) and not self.stack.widget(0).scan_active:
            event.acceptProposedAction()

    def dropEvent(self, event):
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if paths:
            event.acceptProposedAction()
            self.sidebar.setCurrentRow(0)
            self.stack.widget(0).scan_paths(paths)

    def refresh_protection(self):
        if self.paused_until and datetime.now() >= self.paused_until:
            self.resume_monitoring()
            return
        active = self.watcher.observer and self.watcher.observer.is_alive() and not self.watcher.handler.stopping.is_set()
        error = self.watcher_error or (self.watcher.handler.last_error if active else None)
        status = "Folder monitoring is running" if active else "Real-time monitoring off"
        if self.paused_until:
            status = "Monitoring paused until " + self.paused_until.strftime("%H:%M")
        if error:
            status = "Protection needs attention: " + str(error)
        card = self.stack.widget(0).protection
        card.status.setText(status)
        card.status.setProperty("attention", bool(error) or not active)
        card.status.style().unpolish(card.status)
        card.status.style().polish(card.status)
        card.status.setWordWrap(True)
        card.realtime.setText("Real-Time Monitoring: " + ("Running" if active else ("Paused" if self.paused_until else "Off")))
        dashboard = self.stack.widget(0)
        # Monitoring writes history in the background; keep visible counts current.
        if self.stack.currentIndex() == 0 and not dashboard.scan_active and not dashboard.closing:
            dashboard.refresh_dashboard()
        if hasattr(self, "tray"):
            self.tray.status_action.setText("Scan in progress" if self.stack.widget(0).scan_active else status)
            self.tray.pause_action.setVisible(bool(active))
            self.tray.resume_action.setVisible(bool(self.paused_until))

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

    def run_scheduled_scan(self, now=None):
        dashboard = self.stack.widget(0)
        settings = load_config()
        if QuarantineManager().purge_older_than(settings["quarantine_retention_days"]):
            self.stack.widget(4).refresh()
        if dashboard.scan_active or dashboard.closing:
            return
        now = now or datetime.now()
        hour = settings["scan_hour"]
        if hour >= 0 and now.hour < hour:
            return
        # The daily scan counts any run, so cancelling it postpones it to the next slot.
        for enabled, name, days, start in ((settings["scheduled_scan"], None, 1, dashboard.quick_scan),
                                           (settings["weekly_home_scan"], "Home scan", 7, dashboard.full_scan)):
            if enabled and scan_due(dashboard.db.last_scan_run(name), days, hour, now):
                start()
                return

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
            QApplication.instance().quit()
            event.accept()
        else:
            self.hide()
            event.ignore()
            if hasattr(self, "tray") and not self.tray_hint_shown:
                self.tray_hint_shown = True
                self.tray.showMessage("Guardian is still running", "Guardian keeps protecting your folders from the system tray. Use the tray menu to quit.", QSystemTrayIcon.MessageIcon.Information, 4000)
