import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon

from ui.main_window import MainWindow
from core.watcher import Watcher
from core.tray import GuardianTray
from config import load_config


def main():
    app = QApplication(sys.argv)

    # Guardian icon
    app.setWindowIcon(QIcon("assets/icons/guardian.png"))

    # Theme
    theme = Path("assets/themes/dark.qss")
    if theme.exists():
        with open(theme, "r") as f:
            app.setStyleSheet(f.read())

    # Main window
    window = MainWindow()
    window.show()

    # System tray
    tray = GuardianTray(window)
    tray.show()

    # Give the window access to the tray
    window.tray = tray

    # Load settings
    settings = load_config()

    # Start real-time protection only if enabled
    watcher = None

    if settings.get("realtime", True):
        watcher = Watcher()
        watcher.start()

    # Run application
    exit_code = app.exec()

    # Clean up
    if watcher:
        watcher.stop()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()