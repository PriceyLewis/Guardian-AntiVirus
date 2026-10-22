import sqlite3
from datetime import datetime
from pathlib import Path

from core.paths import DATABASE_DIR

DATABASE = DATABASE_DIR / "guardian.db"
# User-managed folder lists; names are fixed so they are safe to interpolate.
FOLDER_TABLES = ("exclusions", "monitored_folders")
DEFAULT_MONITORED = ("Downloads", "Desktop", "Documents")


class GuardianDatabase:

    def __init__(self):
        DATABASE.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(DATABASE, timeout=30)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            filepath TEXT,
            status TEXT,
            virus TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS quarantine(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            original_path TEXT,
            quarantine_path TEXT,
            virus TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            name TEXT,
            scanned INTEGER,
            found INTEGER,
            errors INTEGER,
            cancelled INTEGER,
            duration REAL
        )
        """)

        # Older installs lack the fingerprint and permission columns.
        columns = [row[1] for row in cursor.execute("PRAGMA table_info(quarantine)")]
        for column, kind in (("sha256", "TEXT"), ("mode", "INTEGER")):
            if column not in columns:
                cursor.execute(f"ALTER TABLE quarantine ADD COLUMN {column} {kind}")

        seed_monitored = not cursor.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='monitored_folders'"
        ).fetchone()
        for table in FOLDER_TABLES:
            cursor.execute(f"CREATE TABLE IF NOT EXISTS {table}(path TEXT PRIMARY KEY)")
        if seed_monitored:
            cursor.executemany(
                "INSERT OR IGNORE INTO monitored_folders(path) VALUES (?)",
                [(str(Path.home() / name),) for name in DEFAULT_MONITORED],
            )

        self.conn.commit()

    def add_scan(self, filepath, status, virus=None):
        cursor = self.conn.cursor()

        cursor.execute("""
        INSERT INTO scans
        (timestamp, filepath, status, virus)
        VALUES (?, ?, ?, ?)
        """, (
            datetime.now().isoformat(timespec="seconds"),
            filepath,
            status,
            virus
        ))

        self.conn.commit()

    def add_quarantine(self, original, quarantine, virus, sha256=None, mode=None):
        cursor = self.conn.cursor()

        cursor.execute("""
        INSERT INTO quarantine
        (timestamp, original_path, quarantine_path, virus, sha256, mode)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(timespec="seconds"),
            original,
            quarantine,
            virus,
            sha256,
            mode
        ))

        self.conn.commit()

    def recent_scans(self, limit=25):
        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT
            timestamp,
            filepath,
            status,
            virus
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """, (limit,))

        return cursor.fetchall()

    def get_scan_count(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        return cursor.fetchone()[0]

    def get_threat_count(self):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM scans WHERE status='found'"
        )
        return cursor.fetchone()[0]

    def get_quarantine_count(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM quarantine")
        return cursor.fetchone()[0]

    def get_quarantined_files(self):
        cursor = self.conn.cursor()

        cursor.execute("""
        SELECT
            id,
            timestamp,
            original_path,
            quarantine_path,
            virus,
            sha256,
            mode
        FROM quarantine
        ORDER BY id DESC
        """)

        return cursor.fetchall()

    def quarantined_before(self, cutoff):
        """Record ids quarantined before an ISO timestamp."""
        return [row[0] for row in self.conn.execute("SELECT id FROM quarantine WHERE timestamp < ?", (cutoff,))]

    def delete_quarantine(self, quarantine_id):
        cursor = self.conn.cursor()

        cursor.execute(
            "DELETE FROM quarantine WHERE id=?",
            (quarantine_id,)
        )

        self.conn.commit()

    def add_scan_run(self, name, scanned, found, errors, cancelled, duration):
        self.conn.execute("""
        INSERT INTO scan_runs
        (timestamp, name, scanned, found, errors, cancelled, duration)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(timespec="seconds"), name, scanned, found, errors, int(cancelled), duration))
        self.conn.commit()

    def last_scan_run(self, name=None):
        query = "SELECT timestamp, name, scanned, found, errors, cancelled, duration FROM scan_runs"
        if name:
            return self.conn.execute(query + " WHERE name=? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
        return self.conn.execute(query + " ORDER BY id DESC LIMIT 1").fetchone()

    @staticmethod
    def _folder_table(table):
        if table not in FOLDER_TABLES:
            raise ValueError("Unknown folder list: " + str(table))
        return table

    def get_folders(self, table):
        table = self._folder_table(table)
        return [row[0] for row in self.conn.execute(f"SELECT path FROM {table} ORDER BY path")]

    def add_folder(self, table, path):
        table = self._folder_table(table)
        self.conn.execute(f"INSERT OR IGNORE INTO {table}(path) VALUES (?)", (str(path),))
        self.conn.commit()

    def remove_folder(self, table, path):
        table = self._folder_table(table)
        self.conn.execute(f"DELETE FROM {table} WHERE path=?", (str(path),))
        self.conn.commit()

    def get_exclusions(self):
        return self.get_folders("exclusions")

    def add_exclusion(self, path):
        self.add_folder("exclusions", path)

    def get_monitored_folders(self):
        return self.get_folders("monitored_folders")

    def clear_scans(self):
        self.conn.execute("DELETE FROM scans")
        self.conn.commit()

    def close(self):
        self.conn.close()
