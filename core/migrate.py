"""Move data written by pre-1.1 versions (beside the code) to the data directory."""
import os
import shutil
import sqlite3
from pathlib import Path
from core.log import log
from core.paths import DATA, LEGACY_DATA


def migrate_legacy_data(legacy=LEGACY_DATA, target=DATA):
    """Return the names moved. Never overwrites data already in target."""
    legacy, target = Path(legacy), Path(target)
    if legacy.resolve() == target.resolve() or (target / "database" / "guardian.db").exists():
        return []
    # database/ in the old layout is also a Python package, so only its data files move.
    items = [legacy / "config.json", legacy / "quarantine", *sorted((legacy / "database").glob("guardian.db*"))]
    items = [item for item in items if item.exists()]
    if not items:
        return []
    (target / "database").mkdir(parents=True, exist_ok=True)
    moved = []
    for item in items:
        destination = target / item.relative_to(legacy)
        if destination.exists():
            continue
        shutil.move(str(item), str(destination))
        moved.append(str(item.relative_to(legacy)))
    database = target / "database" / "guardian.db"
    if "quarantine" in moved and database.exists():
        _rewrite_quarantine_paths(database, legacy / "quarantine", target / "quarantine")
    log.info("Moved data from %s to %s: %s", legacy, target, ", ".join(moved))
    return moved


def _rewrite_quarantine_paths(database, old, new):
    conn = sqlite3.connect(database)
    try:
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if "quarantine" not in tables:
            return
        for record, path in conn.execute("SELECT id, quarantine_path FROM quarantine").fetchall():
            if path and Path(path).parent == old:
                conn.execute("UPDATE quarantine SET quarantine_path=? WHERE id=?", (os.fspath(new / Path(path).name), record))
        conn.commit()
    finally:
        conn.close()
