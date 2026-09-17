import os
import sys
from pathlib import Path
from core.paths import ROOT


def set_startup(enabled):
    folder = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "autostart"
    entry = folder / "guardian.desktop"
    if not enabled:
        entry.unlink(missing_ok=True)
        return
    def quote(value):
        value = str(value).replace("%", "%%")
        for char in ("\\", '"', "`", "$" ):
            value = value.replace(char, "\\" + char)
        return '"' + value + '"'
    folder.mkdir(parents=True, exist_ok=True)
    entry.write_text("[Desktop Entry]\nType=Application\nName=Guardian Antivirus\nExec=" + quote(sys.executable) + " " + quote(ROOT / "guardian.py") + "\nTerminal=false\n")
