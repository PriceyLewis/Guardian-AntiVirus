import csv
from pathlib import Path
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QPushButton


def label(text, name="muted"):
    widget = QLabel(text)
    widget.setObjectName(name)
    widget.setWordWrap(True)
    return widget


def heading(layout, title, description):
    layout.addWidget(label(title, "title"))
    layout.addWidget(label(description))


def card(title=None, description=None):
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(20, 18, 20, 18)
    layout.setSpacing(12)
    if title:
        layout.addWidget(label(title, "sectionTitle"))
    if description:
        layout.addWidget(label(description))
    return frame, layout


def button(text, callback, style="secondary"):
    control = QPushButton(text)
    control.setObjectName(style)
    control.clicked.connect(callback)
    return control


def write_csv(path, header, rows):
    # Neutralise spreadsheet formulas in untrusted filenames and engine text.
    def safe(value):
        value = str(value or "")
        return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value
    with Path(path).open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows([safe(value) for value in row] for row in rows)
