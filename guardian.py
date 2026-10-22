import os
import sys
from PySide6.QtCore import QLockFile
from PySide6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon
from PySide6.QtGui import QIcon
from core.log import log, setup_logging
from core.migrate import migrate_legacy_data
from core.paths import DATA
from core.startup import ICON
from ui.main_window import MainWindow
from ui.tray import GuardianTray
from ui.theme import apply_theme, follow_system


USAGE = """usage: guardian [--minimized]
       guardian --scan [--report-only] PATH...
       guardian --install-menu-entry | --remove-menu-entry"""


def main():
    setup_logging()
    if not os.environ.get("GUARDIAN_DATA_DIR"):
        try:
            migrate_legacy_data()
        except OSError as exc:
            log.error("Could not move data from the old location: %s", exc)
    if sys.argv[1:2] == ["--scan"]:
        from core.cli import run_scan
        return run_scan(sys.argv[2:])
    if sys.argv[1:2] in (["--install-menu-entry"], ["--remove-menu-entry"]):
        from core.startup import set_menu_entry
        entry = set_menu_entry(sys.argv[1] == "--install-menu-entry")
        print(("Added " if sys.argv[1] == "--install-menu-entry" else "Removed ") + str(entry))
        return 0
    if sys.argv[1:2] in (["--help"], ["-h"]):
        print(USAGE)
        return 0
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(ICON)))
    apply_theme(app)
    follow_system(app)
    # Two instances would run duplicate monitors against the same history.
    DATA.mkdir(parents=True, exist_ok=True)
    lock = QLockFile(str(DATA / "guardian.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        QMessageBox.information(None, "Guardian Antivirus", "Guardian is already running. Open it from the system tray.")
        return 0
    log.info("Guardian started (data in %s)", DATA)
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
