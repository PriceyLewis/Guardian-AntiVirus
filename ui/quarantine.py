from pathlib import Path
from core.quarantine import QuarantineManager

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
)

from database.database import GuardianDatabase


class QuarantinePage(QWidget):

    def __init__(self):
        super().__init__()

        self.db = GuardianDatabase()

        layout = QVBoxLayout(self)

        title = QLabel("Quarantine")
        title.setObjectName("title")

        self.table = QTableWidget()
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "ID",
            "Date",
            "Original File",
            "Quarantine File",
            "Virus"
        ])

        restore_btn = QPushButton("🔄 Restore Selected")
        delete_btn = QPushButton("🗑 Delete Selected")

        restore_btn.clicked.connect(self.restore_file)
        delete_btn.clicked.connect(self.delete_file)

        layout.addWidget(title)
        layout.addWidget(self.table)

        layout.addWidget(restore_btn)
        layout.addWidget(delete_btn)

        self.refresh()

    def refresh(self):

        files = self.db.get_quarantined_files()

        self.table.setRowCount(len(files))

        for row, values in enumerate(files):

            for col, value in enumerate(values):

                if value is None:
                    value = ""

                self.table.setItem(
                    row,
                    col,
                    QTableWidgetItem(str(value))
                )

        self.table.resizeColumnsToContents()

    def restore_file(self):

        row = self.table.currentRow()

        if row < 0:
            QMessageBox.warning(
                self,
                "Guardian",
                "Please select a file."
            )
            return

        if QMessageBox.question(self, "Restore file", "Restore this potentially infected file? Monitoring may quarantine it again.") != QMessageBox.StandardButton.Yes:
            return
        try:
            QuarantineManager().restore(int(self.table.item(row, 0).text()))
        except Exception as exc:
            QMessageBox.critical(self, "Restore failed", str(exc))
        self.refresh()

    def delete_file(self):
        row = self.table.currentRow()
        if row < 0:
            return
        if QMessageBox.question(self, "Delete file", "Permanently delete the selected quarantined file?") != QMessageBox.StandardButton.Yes:
            return
        try:
            QuarantineManager().delete(int(self.table.item(row, 0).text()))
        except Exception as exc:
            QMessageBox.critical(self, "Delete failed", str(exc))
        self.refresh()
