from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QLineEdit, QMessageBox, QHeaderView
from core.quarantine import QuarantineManager
from database.database import GuardianDatabase
from ui.components import heading, label, button


class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        self.db = GuardianDatabase()
        self.rows = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(18)
        heading(layout, "Quarantine", "Detected files are isolated here. Restore only files you trust; monitoring may detect them again.")
        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search quarantined files…")
        self.search.setClearButtonEnabled(True)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(button("Refresh", self.refresh))
        layout.addLayout(toolbar)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Date", "Original file", "Detection"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 160)
        self.table.setMinimumHeight(260)
        layout.addWidget(self.table, 1)
        self.empty = label("Quarantine is empty.")
        layout.addWidget(self.empty)
        self.feedback = label("")
        layout.addWidget(self.feedback)
        actions = QHBoxLayout()
        actions.addStretch()
        self.restore_button = button("Restore selected", self.restore_file)
        self.delete_button = button("Delete permanently", self.delete_file, "danger")
        actions.addWidget(self.restore_button)
        actions.addWidget(self.delete_button)
        layout.addLayout(actions)
        self.search.textChanged.connect(self.filter_table)
        self.table.itemSelectionChanged.connect(self.update_actions)
        self.refresh()

    def refresh(self):
        self.rows = self.db.get_quarantined_files()
        self.filter_table()

    def filter_table(self):
        text = self.search.text().casefold()
        rows = [r for r in self.rows if text in (r[2] + " " + (r[4] or "")).casefold()]
        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            for col, value in enumerate((row[1], row[2], row[4])):
                item = QTableWidgetItem(str(value or "—"))
                item.setToolTip(str(value or ""))
                item.setData(Qt.ItemDataRole.UserRole, row[0])
                self.table.setItem(index, col, item)
        self.empty.setVisible(not rows)
        self.empty.setText("No files match your search." if self.rows else "Quarantine is empty. Detected files will appear here.")
        self.update_actions()

    def update_actions(self):
        selected = bool(self.table.selectedItems())
        self.restore_button.setEnabled(selected)
        self.delete_button.setEnabled(selected)

    def selected_id(self):
        items = self.table.selectedItems()
        return items[0].data(Qt.ItemDataRole.UserRole) if items else None

    def restore_file(self):
        self.perform_action("restore")

    def delete_file(self):
        self.perform_action("delete")

    def perform_action(self, action):
        record = self.selected_id()
        if record is None:
            return
        text = "Restore this potentially infected file? Existing files will not be overwritten." if action == "restore" else "Permanently delete this quarantined file? This cannot be undone."
        if QMessageBox.question(self, "Confirm " + action, text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        try:
            getattr(QuarantineManager(), action)(record)
            self.feedback.setText("File restored." if action == "restore" else "File permanently deleted.")
        except Exception as exc:
            QMessageBox.critical(self, "Action failed", str(exc))
        self.refresh()
