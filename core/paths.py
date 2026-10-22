import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def default_data_dir():
    """XDG data location, e.g. ~/.local/share/guardian."""
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "guardian"


DATA = Path(os.environ["GUARDIAN_DATA_DIR"]) if os.environ.get("GUARDIAN_DATA_DIR") else default_data_dir()
# Versions before 1.1 kept their data beside the code.
LEGACY_DATA = ROOT
QUARANTINE = DATA / "quarantine"
DATABASE_DIR = DATA / "database"
LOGS = DATA / "logs"


def is_guardian_storage(path, quarantine=QUARANTINE):
    """True for Guardian's own quarantine, database, log and config files.

    Scanning these would re-trigger monitoring on every history write.
    """
    path = Path(path).resolve()
    if any(path.is_relative_to(Path(folder).resolve()) for folder in (quarantine, DATABASE_DIR, LOGS)):
        return True
    return path.parent == DATA.resolve() and (path.name == "config.json" or path.name.startswith((".config-", "guardian.lock")))


def is_excluded(path, exclusions):
    """True when path is inside one of the user's excluded folders."""
    path = Path(path).resolve()
    return any(path.is_relative_to(Path(folder).resolve()) for folder in exclusions)
