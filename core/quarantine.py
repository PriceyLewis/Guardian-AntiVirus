from pathlib import Path
import os
import shutil
import uuid
from core.paths import QUARANTINE
from database.database import GuardianDatabase


class QuarantineManager:
    def __init__(self):
        self.folder = QUARANTINE
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.folder.chmod(0o700)

    def quarantine(self, filepath, virus=None):
        source = Path(filepath).absolute()
        if source.is_symlink() or not source.is_file():
            raise ValueError("Only regular files can be quarantined")
        destination = self.folder / (uuid.uuid4().hex + ".quarantine")
        db = GuardianDatabase()
        try:
            shutil.move(str(source), str(destination))
            destination.chmod(0o600)
            db.add_quarantine(str(source), str(destination), virus)
        except Exception:
            if destination.exists() and not source.exists():
                shutil.move(str(destination), str(source))
            raise
        finally:
            db.close()
        return destination

    def _record(self, db, record_id):
        row = next((r for r in db.get_quarantined_files() if r[0] == record_id), None)
        if row is None:
            raise ValueError("Quarantine record no longer exists")
        path = Path(row[3]).absolute()
        if path.is_symlink() or path.parent.resolve() != self.folder.resolve():
            raise ValueError("Invalid quarantine path")
        return row, path

    def restore(self, record_id):
        db = GuardianDatabase()
        try:
            row, source = self._record(db, record_id)
            target = Path(row[2])
            target.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive creation never overwrites a replacement or a symlink.
            with source.open("rb") as src, target.open("xb") as dst:
                try:
                    shutil.copyfileobj(src, dst)
                except Exception:
                    target.unlink()
                    raise
            target.chmod(0o600)
            source.unlink()
            db.delete_quarantine(record_id)
        finally:
            db.close()

    def delete(self, record_id):
        db = GuardianDatabase()
        try:
            _, source = self._record(db, record_id)
            source.unlink(missing_ok=True)
            db.delete_quarantine(record_id)
        finally:
            db.close()
