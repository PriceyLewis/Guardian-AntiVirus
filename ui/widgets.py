from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QListWidget,
)


class Card(QFrame):

    def __init__(self):
        super().__init__()

        self.setObjectName("card")


class StatCard(Card):

    def __init__(self, title, value):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        self.title = QLabel(title)
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setObjectName("cardTitle")

        self.value = QLabel(str(value))
        self.value.setAlignment(Qt.AlignCenter)
        self.value.setObjectName("cardValue")

        layout.addStretch()
        layout.addWidget(self.title)
        layout.addWidget(self.value)
        layout.addStretch()

    def set_value(self, value):
        self.value.setText(str(value))


class ProtectionCard(Card):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        title = QLabel("Protection Status")
        title.setObjectName("sectionTitle")

        self.status = QLabel("Checking monitoring status")
        self.status.setObjectName("status")

        self.realtime = QLabel("Real-Time Protection     Checking")
        self.definitions = QLabel("ClamAV definitions: managed by your system. Check engine details in Settings.")
        self.last_scan = QLabel("No scan completed in this session")

        for label in (
            self.realtime,
            self.definitions,
            self.last_scan,
        ):
            label.setObjectName("subtitle")

        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addWidget(self.status)
        layout.addSpacing(15)
        layout.addWidget(self.realtime)
        layout.addWidget(self.definitions)
        layout.addWidget(self.last_scan)


class ScanButtonPanel(Card):

    def __init__(self):
        super().__init__()

        layout = QHBoxLayout(self)
        layout.setSpacing(15)

        self.quick = QPushButton("Quick Scan")
        self.full = QPushButton("Home Scan")
        self.custom = QPushButton("Custom Scan")

        layout.addWidget(self.quick)
        layout.addWidget(self.full)
        layout.addWidget(self.custom)


class RecentActivityCard(Card):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        header = QHBoxLayout()

        title = QLabel("Recent Activity")
        title.setObjectName("sectionTitle")

        header.addWidget(title)
        header.addStretch()

        self.list = QListWidget()
        self.list.setMinimumHeight(120)
        self.list.setMaximumHeight(165)

        layout.addLayout(header)
        layout.addWidget(self.list)

    def update_activity(self, rows):

        self.list.clear()

        if not rows:
            self.list.addItem("No recent scans.")
            return

        for timestamp, filepath, status, virus in rows:

            filename = filepath.split("/")[-1]

            if status == "found":
                text = f"❌ {filename}   ({virus})"
            elif status == "clean":
                text = f"✅ {filename}"
            else:
                text = f"⚠ {filename}"

            self.list.addItem(text)
            self.list.item(self.list.count() - 1).setToolTip(filepath)
