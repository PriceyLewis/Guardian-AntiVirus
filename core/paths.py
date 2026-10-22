import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("GUARDIAN_DATA_DIR", ROOT))
QUARANTINE = DATA / "quarantine"
DATABASE_DIR = DATA / "database"


def is_guardian_storage(path, quarantine=QUARANTINE):
    """True for Guardian's own quarantine, database and config files.

    Scanning these would re-trigger monitoring on every history write.
    """
    path = Path(path).resolve()
    if any(path.is_relative_to(Path(folder).resolve()) for folder in (quarantine, DATABASE_DIR)):
        return True
    return path.parent == DATA.resolve() and (path.name == "config.json" or path.name.startswith((".config-", "guardian.lock")))
