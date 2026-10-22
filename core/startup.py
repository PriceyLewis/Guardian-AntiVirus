import os
import sys
from pathlib import Path
from core.paths import ROOT

ICON = ROOT / "assets" / "icons" / "Guardian.png"


def startup_path():
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "autostart" / "guardian.desktop"


def menu_entry_path():
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "applications" / "guardian.desktop"


def desktop_entry(*args):
    """Desktop entry that runs this installation with this Python environment."""
    def quote(value):
        value = str(value).replace("%", "%%")
        for char in ("\\", '"', "`", "$" ):
            value = value.replace(char, "\\" + char)
        return '"' + value + '"'
    command = " ".join([quote(sys.executable), quote(ROOT / "guardian.py"), *args])
    return ("[Desktop Entry]\nType=Application\nName=Guardian Antivirus\nComment=Scan files and monitor folders with ClamAV\n"
            "Exec=" + command + "\nIcon=" + str(ICON) + "\nCategories=System;Security;\nTerminal=false\n")


def set_startup(enabled):
    entry = startup_path()
    if not enabled:
        entry.unlink(missing_ok=True)
        return
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(desktop_entry("--minimized"))


def set_menu_entry(enabled):
    """Add or remove Guardian in the desktop's application menu."""
    entry = menu_entry_path()
    if not enabled:
        entry.unlink(missing_ok=True)
        return entry
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(desktop_entry())
    return entry
