from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
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
            "Full Scan",
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
            self.stack.setCurrentIndex
        )

        self.sidebar.setCurrentRow(0)

        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)

    def closeEvent(self, event: QCloseEvent):
        if self.allow_close:
            event.accept()
        else:
            self.hide()
            event.ignore()