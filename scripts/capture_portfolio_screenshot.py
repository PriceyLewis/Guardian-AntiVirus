import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("GUARDIAN_DATA_DIR", "/tmp/guardian-portfolio-data")

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from config import DEFAULTS, save_config
from core.paths import ROOT
from ui.main_window import MainWindow


def main():
    settings = DEFAULTS.copy()
    settings.update({
        "realtime": False,
        "notifications": False,
        "startup": False,
        "close_to_tray": False,
    })
    save_config(settings)

    app = QApplication([])
    app.setWindowIcon(QIcon(str(ROOT / "assets/icons/Guardian.png")))

    theme = ROOT / "assets/themes/dark.qss"
    if theme.exists():
        app.setStyleSheet(theme.read_text())

    window = MainWindow()
    window.resize(1180, 820)
    window.show()
    app.processEvents()

    output = ROOT / "docs" / "screenshots" / "guardian-overview.png"
    output.parent.mkdir(parents=True, exist_ok=True)

    if not window.grab().save(str(output), "PNG"):
        raise RuntimeError("Qt could not save the portfolio screenshot")

    window.shutdown()
    window.close()
    app.processEvents()
    print(f"Saved {output}")


if __name__ == "__main__":
    main()
