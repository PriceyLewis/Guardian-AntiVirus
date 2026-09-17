import csv
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QTableWidget, QTableWidgetItem, QComboBox, QFileDialog, QMessageBox, QHeaderView
from database.database import GuardianDatabase
from ui.components import heading, label, button


class HistoryPage(QWidget):
    def __init__(self):
        super().__init__()
        self.db = GuardianDatabase()
        self.rows = []
        self.filtered_rows = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(18)
        heading(layout, "Scan history", "Review the latest 500 file results. Errors mean a file was not successfully checked.")
        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search file paths or threat names…")
        self.search.setClearButtonEnabled(True)
        self.filter = QComboBox()
        for text, value in [("All results", ""), ("Clean", "clean"), ("Detections", "found"), ("Errors", "error")]:
            self.filter.addItem(text, value)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.filter)
        self.export_button = button("Export CSV", self.export_csv)
        toolbar.addWidget(self.export_button)
        toolbar.addWidget(button("Refresh", self.refresh))
        layout.addLayout(toolbar)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "File path", "Result", "Details"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 160)
        self.table.setColumnWidth(2, 105)
        self.table.setMinimumHeight(260)
        layout.addWidget(self.table, 1)
        self.empty = label("No scan results yet. Start a scan from Overview.")
        layout.addWidget(self.empty)
        self.count = label("")
        layout.addWidget(self.count)
        self.search.textChanged.connect(self.filter_table)
        self.filter.currentIndexChanged.connect(self.filter_table)
        self.refresh()

    def refresh(self):
        self.rows = self.db.recent_scans(500)
        self.filter_table()

    def filter_table(self):
        text = self.search.text().casefold()
        status = self.filter.currentData()
        self.filtered_rows = [r for r in self.rows if (not status or r[2] == status) and text in (r[1] + " " + (r[3] or "")).casefold()]
        self.populate_table(self.filtered_rows)

    def populate_table(self, rows):
        self.table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for col, value in enumerate(values):
                if col == 2:
                    value = {"found": "Detection", "clean": "Clean", "error": "Error"}.get(value, value)
                item = QTableWidgetItem(str(value or "—"))
                item.setToolTip(str(value or ""))
                self.table.setItem(row, col, item)
        self.empty.setVisible(not rows)
        self.empty.setText("No results match your filters." if self.rows else "No scan results yet. Start a scan from Overview.")
        self.count.setText(f"Showing {len(rows)} of {len(self.rows)} recent results")
        self.export_button.setEnabled(bool(rows))

    def write_csv(self, path):
        # Neutralise spreadsheet formulas in untrusted filenames and engine text.
        def safe(value):
            value = str(value or "")
            return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value
        with Path(path).open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Time", "File path", "Result", "Details"])
            writer.writerows([safe(value) for value in row] for row in self.filtered_rows)

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export visible results", "guardian-history.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            self.write_csv(path)
            self.count.setText(f"Exported {len(self.filtered_rows)} results")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
