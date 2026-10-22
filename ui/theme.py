from PySide6.QtCore import Qt
from config import load_config
from core.paths import ROOT

THEMES = ROOT / "assets" / "themes"


def resolve(app, choice=None):
    """Map the saved choice (system, dark or light) to a stylesheet name."""
    choice = choice or load_config()["theme"]
    if choice != "system":
        return choice
    # Qt reports Unknown on desktops without a preference; Guardian's default is dark.
    return "light" if app.styleHints().colorScheme() == Qt.ColorScheme.Light else "dark"


def apply_theme(app, choice=None):
    name = resolve(app, choice)
    sheet = THEMES / f"{name}.qss"
    if sheet.exists():
        app.setStyleSheet(sheet.read_text())
    app.setProperty("guardianTheme", name)
    return name


def follow_system(app):
    """Re-apply when the desktop switches between light and dark."""
    app.styleHints().colorSchemeChanged.connect(lambda _: load_config()["theme"] == "system" and apply_theme(app))
