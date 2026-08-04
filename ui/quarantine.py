from pathlib import Path
import shutil

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

        quarantine_path = Path(
            self.table.item(row, 3).text()
        )

        original_path = Path(
            self.table.item(row, 2).text()
        )

        quarantine_id = int(
            self.table.item(row, 0).text()
        )

        try:

            original_path.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            shutil.move(
                quarantine_path,
                original_path
            )

            self.db.delete_quarantine(
                quarantine_id
            )

            QMessageBox.information(
                self,
                "Guardian",
                "File restored successfully."
            )

        except Exception as e:

            QMessageBox.critical(
                self,
                "Guardian",
                str(e)
            )

        self.refresh()

    def delete_file(self):

        row = self.table.currentRow()

        if row < 0:
            QMessageBox.warning(
                self,
                "Guardian",
                "Please select a file."
            )
            return

        quarantine_path = Path(
            self.table.item(row, 3).text()
        )

        quarantine_id = int(
            self.table.item(row, 0).text()
        )

        try:

            if quarantine_path.exists():
                quarantine_path.unlink()

            self.db.delete_quarantine(
                quarantine_id
            )

            QMessageBox.information(
                self,
                "Guardian",
                "File deleted permanently."
            )

        except Exception as e:

            QMessageBox.critical(
                self,
                "Guardian",
                str(e)
            )

        self.refresh()