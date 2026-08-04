from datetime import datetime

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QFileDialog,
)

from core.scan_manager import ScanManager
from database.database import GuardianDatabase

from ui.widgets import (
    StatCard,
    ProtectionCard,
    ScanButtonPanel,
    RecentActivityCard,
)


class DashboardPage(QWidget):

    def __init__(self):
        super().__init__()

        self.db = GuardianDatabase()
        self.scan_manager = ScanManager()

        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        # Header
        title = QLabel("Guardian Antivirus")
        title.setObjectName("title")

        subtitle = QLabel("Your computer is protected")
        subtitle.setObjectName("subtitle")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Protection
        self.protection = ProtectionCard()
        layout.addWidget(self.protection)

        # Statistics
        stats = QHBoxLayout()

        self.files_card = StatCard("Files Scanned", 0)
        self.threats_card = StatCard("Threats", 0)
        self.quarantine_card = StatCard("Quarantined", 0)

        stats.addWidget(self.files_card)
        stats.addWidget(self.threats_card)
        stats.addWidget(self.quarantine_card)

        layout.addLayout(stats)

        # Scan buttons
        self.buttons = ScanButtonPanel()

        self.buttons.quick.clicked.connect(self.quick_scan)
        self.buttons.full.clicked.connect(self.full_scan)
        self.buttons.custom.clicked.connect(self.custom_scan)

        layout.addWidget(self.buttons)

        # Progress
        self.progress = QProgressBar()
        self.progress.setValue(0)

        self.current_file = QLabel("Ready")
        self.current_file.setObjectName("subtitle")

        layout.addWidget(self.progress)
        layout.addWidget(self.current_file)

        # Recent Activity
        self.activity = RecentActivityCard()

        layout.addWidget(self.activity)

        layout.addStretch()

        self.refresh_dashboard()

    def refresh_dashboard(self):

        self.files_card.set_value(
            self.db.get_scan_count()
        )

        self.threats_card.set_value(
            self.db.get_threat_count()
        )

        self.quarantine_card.set_value(
            self.db.get_quarantine_count()
        )

        self.activity.update_activity(
            self.db.recent_scans(5)
        )

    def start_scan(self, scan_function):

        self.progress.setValue(0)
        self.current_file.setText("Preparing scan...")

        if hasattr(self.window(), "tray"):
            self.window().tray.set_scanning()

        scan_function(
            progress_callback=self.update_progress,
            maximum_callback=self.progress.setMaximum,
            current_file_callback=self.current_file.setText,
            finished_callback=self.scan_finished,
        )

    def quick_scan(self):
        self.start_scan(
            self.scan_manager.quick_scan
        )

    def full_scan(self):
        self.start_scan(
            self.scan_manager.full_scan
        )

    def custom_scan(self):

        folder = QFileDialog.getExistingDirectory(
            self,
            "Choose Folder"
        )

        if not folder:
            return

        self.progress.setValue(0)

        self.current_file.setText(
            "Preparing custom scan..."
        )

        if hasattr(self.window(), "tray"):
            self.window().tray.set_scanning()

        self.scan_manager.custom_scan(
            folder,
            progress_callback=self.update_progress,
            maximum_callback=self.progress.setMaximum,
            current_file_callback=self.current_file.setText,
            finished_callback=self.scan_finished,
        )

    def update_progress(self, scanned):

        self.progress.setValue(scanned)

        self.files_card.set_value(scanned)

    def scan_finished(self, scanned):

        self.current_file.setText("✅ Scan complete")

        self.protection.last_scan.setText(
            "Last Scan: " +
            datetime.now().strftime("%d %b %Y %H:%M")
        )

        if hasattr(self.window(), "tray"):
            self.window().tray.set_protected()

        self.refresh_dashboard()

        QMessageBox.information(
            self,
            "Guardian",
            f"Scan complete.\n\nFiles scanned: {scanned}"
        )