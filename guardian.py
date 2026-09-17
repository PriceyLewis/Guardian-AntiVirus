import sys
from PySide6.QtWidgets import QApplication, QSystemTrayIcon
from PySide6.QtGui import QIcon
from core.paths import ROOT
from ui.main_window import MainWindow
from ui.tray import GuardianTray


def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(ROOT / "assets/icons/Guardian.png")))
    theme = ROOT / "assets/themes/dark.qss"
    if theme.exists():
        app.setStyleSheet(theme.read_text())
    window = MainWindow()
    window.show()
    tray = GuardianTray(window)
    window.tray = tray
    if QSystemTrayIcon.isSystemTrayAvailable():
        app.setQuitOnLastWindowClosed(False)
        tray.show()
    window.refresh_protection()
    app.aboutToQuit.connect(window.shutdown)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
