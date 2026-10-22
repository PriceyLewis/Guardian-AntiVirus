from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QCheckBox, QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QLineEdit, QMessageBox, QHeaderView, QFileDialog
from core.quarantine import QuarantineManager
from database.database import GuardianDatabase
from ui.components import heading, label, button, write_csv


class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        self.db = GuardianDatabase()
        self.rows = []
        self.visible_rows = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(18)
        heading(layout, "Quarantine", "Detected files are isolated here. Restore only files you trust; monitoring may detect them again. Select several rows with Ctrl or Shift; press Delete to delete the selection.")
        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search files, detections or SHA-256…")
        self.search.setClearButtonEnabled(True)
        toolbar.addWidget(self.search, 1)
        self.export_button = button("Export report", self.export_report)
        toolbar.addWidget(self.export_button)
        toolbar.addWidget(button("Refresh", self.refresh))
        layout.addLayout(toolbar)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Date", "Original file", "Detection", "SHA-256"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 160)
        self.table.setColumnWidth(3, 130)
        self.table.setMinimumHeight(260)
        layout.addWidget(self.table, 1)
        self.empty = label("Quarantine is empty.")
        layout.addWidget(self.empty)
        status = QHBoxLayout()
        self.usage = label("")
        status.addWidget(self.usage, 1)
        self.keep_mode = QCheckBox("Restore original permissions")
        self.keep_mode.setToolTip("Restore files with their original permissions, such as executable. When off, restored files are readable only by you.")
        status.addWidget(self.keep_mode)
        layout.addLayout(status)
        self.feedback = label("")
        layout.addWidget(self.feedback)
        actions = QHBoxLayout()
        self.copy_button = button("Copy SHA-256", self.copy_hash)
        actions.addWidget(self.copy_button)
        actions.addStretch()
        self.restore_button = button("Restore selected", self.restore_file)
        self.delete_button = button("Delete permanently", self.delete_file, "danger")
        actions.addWidget(self.restore_button)
        actions.addWidget(self.delete_button)
        layout.addLayout(actions)
        self.search.textChanged.connect(self.filter_table)
        self.table.itemSelectionChanged.connect(self.update_actions)
        QShortcut(QKeySequence("Del"), self.table, self.delete_file)
        self.refresh()

    def refresh(self):
        self.rows = self.db.get_quarantined_files()
        self.filter_table()

    def filter_table(self):
        text = self.search.text().casefold()
        rows = [r for r in self.rows if text in (r[2] + " " + (r[4] or "") + " " + (r[5] or "")).casefold()]
        self.visible_rows = rows
        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            # Records from before fingerprints were stored have no hash.
            digest = row[5] or ""
            for col, (value, tip) in enumerate(((str(row[1]).replace("T", " "), row[1]), (row[2], row[2]), (row[4], row[4]), (digest[:12] + "…" if digest else "", digest))):
                item = QTableWidgetItem(str(value or "—"))
                item.setToolTip(str(tip or ""))
                item.setData(Qt.ItemDataRole.UserRole, row[0])
                self.table.setItem(index, col, item)
        self.empty.setVisible(not rows)
        self.empty.setText("No files match your search." if self.rows else "Quarantine is empty. Detected files will appear here.")
        self.export_button.setEnabled(bool(rows))
        size = QuarantineManager().disk_usage()
        self.usage.setText(f"{len(self.rows)} file{'s' if len(self.rows) != 1 else ''} in quarantine · {format_size(size)} on disk" if self.rows else "")
        self.update_actions()

    def update_actions(self):
        count = len(self.selected_ids())
        self.restore_button.setEnabled(bool(count))
        self.delete_button.setEnabled(bool(count))
        self.restore_button.setText(f"Restore {count} selected" if count > 1 else "Restore selected")
        self.copy_button.setEnabled(count == 1 and bool(self.selected_hash()))

    def selected_ids(self):
        ids = []
        for index in self.table.selectionModel().selectedRows():
            record = self.table.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
            if record not in ids:
                ids.append(record)
        return ids

    def selected_id(self):
        ids = self.selected_ids()
        return ids[0] if ids else None

    def selected_hash(self):
        ids = self.selected_ids()
        row = next((r for r in self.rows if ids and r[0] == ids[0]), None)
        return row[5] if row else None

    def copy_hash(self):
        digest = self.selected_hash()
        if digest:
            QApplication.clipboard().setText(digest)
            self.feedback.setText("SHA-256 copied. Paste it into a service such as VirusTotal to look the file up without uploading it.")

    def restore_file(self):
        self.perform_action("restore")

    def delete_file(self):
        self.perform_action("delete")

    def perform_action(self, action):
        records = self.selected_ids()
        if not records:
            return
        count = len(records)
        files = "this potentially infected file" if count == 1 else f"these {count} potentially infected files"
        if action == "restore":
            text = f"Restore {files}? Existing files will not be overwritten."
        else:
            text = f"Permanently delete {'this quarantined file' if count == 1 else f'these {count} quarantined files'}? This cannot be undone."
        if QMessageBox.question(self, "Confirm " + action, text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        manager = QuarantineManager()
        failures = []
        for record in records:
            try:
                if action == "restore":
                    manager.restore(record, original_mode=self.keep_mode.isChecked())
                else:
                    manager.delete(record)
            except Exception as exc:
                original = next((r[2] for r in self.rows if r[0] == record), str(record))
                failures.append(f"{original}: {exc}")
        done = count - len(failures)
        verb = "restored" if action == "restore" else "permanently deleted"
        self.feedback.setText(f"{done} file{'s' if done != 1 else ''} {verb}." if done else "")
        if failures:
            QMessageBox.critical(self, "Action failed", "\n".join(failures))
        self.refresh()

    def export_report(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export quarantine report", "guardian-quarantine.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            self.write_report(path)
            self.feedback.setText(f"Exported {len(self.visible_rows)} quarantine records")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))

    def write_report(self, path):
        write_csv(path, ["Date", "Original file", "Detection", "SHA-256"], [(r[1], r[2], r[4], r[5]) for r in self.visible_rows])


def format_size(size):
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:,} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
