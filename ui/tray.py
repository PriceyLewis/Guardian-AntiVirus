from PySide6.QtWidgets import (
    QMenu,
    QSystemTrayIcon,
)
from PySide6.QtGui import QAction, QIcon
from core.startup import ICON


class GuardianTray(QSystemTrayIcon):

    def __init__(self, window):
        super().__init__()

        self.window = window

        # Use Guardian icon
        self.setIcon(QIcon(str(ICON)))
        self.setToolTip("Guardian Antivirus")

        menu = QMenu()
        self.menu = menu
        # Actions are parented to the menu; unparented local QActions are
        # garbage collected and silently vanish from the tray menu.

        self.status_action = QAction("Protection not verified", menu)
        self.status_action.setEnabled(False)

        open_action = QAction("Open Guardian", menu)
        quick_scan_action = QAction("Run Quick Scan", menu)
        history_action = QAction("View History", menu)
        self.pause_action = QAction("Pause monitoring for 1 hour", menu)
        self.resume_action = QAction("Resume monitoring", menu)
        self.resume_action.setVisible(False)
        quit_action = QAction("Quit Guardian", menu)

        open_action.triggered.connect(self.show_window)
        quick_scan_action.triggered.connect(self.quick_scan)
        history_action.triggered.connect(self.show_history)
        self.pause_action.triggered.connect(lambda: self.window.pause_monitoring())
        self.resume_action.triggered.connect(self.window.resume_monitoring)
        quit_action.triggered.connect(self.quit_guardian)

        menu.addAction(self.status_action)
        menu.addSeparator()

        menu.addAction(open_action)
        menu.addAction(quick_scan_action)
        menu.addAction(history_action)
        menu.addAction(self.pause_action)
        menu.addAction(self.resume_action)

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
        self.window.stack.widget(0).quick_scan()
        self.show_window()

    def show_history(self):
        self.window.sidebar.setCurrentRow(3)
        self.show_window()

    def quit_guardian(self):
        self.window.quit_guardian()
