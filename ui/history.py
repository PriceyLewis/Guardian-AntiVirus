from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
)

from database.database import GuardianDatabase


class HistoryPage(QWidget):

    def __init__(self):
        super().__init__()

        self.db = GuardianDatabase()

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Header
        header = QHBoxLayout()

        title = QLabel("Scan History")
        title.setObjectName("title")

        refresh = QPushButton("🔄 Refresh")
        refresh.clicked.connect(self.refresh)

        header.addWidget(title)
        header.addStretch()
        header.addWidget(refresh)

        layout.addLayout(header)

        # Search
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by filename...")
        self.search.textChanged.connect(self.filter_table)

        layout.addWidget(self.search)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels([
            "Time",
            "File",
            "Status",
            "Virus"
        ])

        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.table)

        self.refresh()

    def refresh(self):

        self.rows = self.db.recent_scans(500)

        self.populate_table(self.rows)

    def populate_table(self, rows):

        self.table.setRowCount(len(rows))

        for row, (timestamp, filepath, status, virus) in enumerate(rows):

            filename = filepath.split("/")[-1]

            if status == "found":
                status = "❌ Threat"
            elif status == "clean":
                status = "✅ Clean"
            else:
                status = "⚠ Error"

            values = [
                timestamp,
                filename,
                status,
                virus or "-"
            ]

            for col, value in enumerate(values):
                self.table.setItem(
                    row,
                    col,
                    QTableWidgetItem(str(value))
                )

        self.table.resizeColumnsToContents()

    def filter_table(self):

        text = self.search.text().lower()

        if not text:
            self.populate_table(self.rows)
            return

        filtered = []

        for row in self.rows:

            if text in row[1].lower():
                filtered.append(row)

        self.populate_table(filtered)