from PySide6.QtWidgets import (
    QApplication,
    QMenu,
    QSystemTrayIcon,
)
from PySide6.QtGui import QAction, QIcon


class GuardianTray(QSystemTrayIcon):

    def __init__(self, window):
        super().__init__()

        self.window = window

        # Use Guardian icon
        self.setIcon(QIcon("assets/icons/guardian.png"))
        self.setToolTip("Guardian Antivirus")

        menu = QMenu()

        self.status_action = QAction("🟢 Protected")
        self.status_action.setEnabled(False)

        open_action = QAction("Open Guardian")
        quick_scan_action = QAction("Run Quick Scan")
        history_action = QAction("View History")
        quit_action = QAction("Quit Guardian")

        open_action.triggered.connect(self.show_window)
        quick_scan_action.triggered.connect(self.quick_scan)
        history_action.triggered.connect(self.show_history)
        quit_action.triggered.connect(self.quit_guardian)

        menu.addAction(self.status_action)
        menu.addSeparator()

        menu.addAction(open_action)
        menu.addAction(quick_scan_action)
        menu.addAction(history_action)

        menu.addSeparator()

        menu.addAction(quit_action)

        self.setContextMenu(menu)

        self.activated.connect(self.on_click)

    def on_click(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_window()

    def show_window(self):
        self.window.showNormal()
        self.window.raise_()
        self.window.activateWindow()

    def quick_scan(self):
        self.window.sidebar.setCurrentRow(0)

        dashboard = self.window.stack.widget(0)

        if hasattr(dashboard, "quick_scan"):
            dashboard.quick_scan()

    def show_history(self):
        self.window.sidebar.setCurrentRow(3)
        self.show_window()

    def quit_guardian(self):
        self.window.allow_close = True
        QApplication.quit()

    def set_protected(self):
        self.status_action.setText("🟢 Protected")

    def set_scanning(self):
        self.status_action.setText("🟡 Scanning...")

    def set_threat(self):
        self.status_action.setText("🔴 Threat Detected")