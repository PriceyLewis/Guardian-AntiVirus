import sys
from PySide6.QtCore import QLockFile
from PySide6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon
from PySide6.QtGui import QIcon
from core.paths import DATA, ROOT
from ui.main_window import MainWindow
from ui.tray import GuardianTray


def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(ROOT / "assets/icons/Guardian.png")))
    theme = ROOT / "assets/themes/dark.qss"
    if theme.exists():
        app.setStyleSheet(theme.read_text())
    # Two instances would run duplicate monitors against the same history.
    DATA.mkdir(parents=True, exist_ok=True)
    lock = QLockFile(str(DATA / "guardian.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        QMessageBox.information(None, "Guardian Antivirus", "Guardian is already running. Open it from the system tray.")
        return 0
    window = MainWindow()
    tray = GuardianTray(window)
    window.tray = tray
    tray_available = QSystemTrayIcon.isSystemTrayAvailable()
    if tray_available:
        app.setQuitOnLastWindowClosed(False)
        tray.show()
    # Login autostart passes --minimized so Guardian starts quietly in the tray.
    if "--minimized" not in sys.argv[1:] or not tray_available:
        window.show()
    window.refresh_protection()
    app.aboutToQuit.connect(window.shutdown)
    try:
        return app.exec()
    finally:
        lock.unlock()


if __name__ == "__main__":
    sys.exit(main())
