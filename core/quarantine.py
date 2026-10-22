from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import shutil
import uuid
from core.log import log
from core.paths import QUARANTINE
from database.database import GuardianDatabase


def sha256(path):
    """Fingerprint for looking a detection up in VirusTotal or similar services."""
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
        # Permission bits only; setuid, setgid and sticky bits are never kept.
        mode = source.stat().st_mode & 0o777
        db = GuardianDatabase()
        try:
            shutil.move(str(source), str(destination))
            destination.chmod(0o600)
            db.add_quarantine(str(source), str(destination), virus, sha256(destination), mode)
        except Exception:
            if destination.exists() and not source.exists():
                shutil.move(str(destination), str(source))
            raise
        finally:
            db.close()
        log.info("Quarantined %s (%s)", source, virus)
        return destination

    def _record(self, db, record_id):
        row = next((r for r in db.get_quarantined_files() if r[0] == record_id), None)
        if row is None:
            raise ValueError("Quarantine record no longer exists")
        path = Path(row[3]).absolute()
        if path.is_symlink() or path.parent.resolve() != self.folder.resolve():
            raise ValueError("Invalid quarantine path")
        return row, path

    def restore(self, record_id, original_mode=False):
        """Restore privately (0600) unless original_mode asks for the recorded permissions."""
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
            target.chmod((row[6] & 0o777) if original_mode and row[6] is not None else 0o600)
            source.unlink()
            db.delete_quarantine(record_id)
        finally:
            db.close()
        log.info("Restored %s from quarantine", target)

    def delete(self, record_id):
        db = GuardianDatabase()
        try:
            row, source = self._record(db, record_id)
            source.unlink(missing_ok=True)
            db.delete_quarantine(record_id)
        finally:
            db.close()
        log.info("Deleted quarantined copy of %s", row[2])

    def purge_older_than(self, days):
        """Permanently delete records older than days; returns the number removed."""
        if not days:
            return 0
        db = GuardianDatabase()
        try:
            records = db.quarantined_before((datetime.now() - timedelta(days=days)).isoformat(timespec="seconds"))
        finally:
            db.close()
        removed = 0
        for record in records:
            try:
                self.delete(record)
                removed += 1
            except Exception as exc:
                log.warning("Could not purge quarantine record %s: %s", record, exc)
        return removed

    def disk_usage(self):
        return sum(item.stat().st_size for item in self.folder.glob("*.quarantine") if item.is_file())
