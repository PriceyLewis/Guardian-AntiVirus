import sqlite3
from datetime import datetime

from core.paths import DATABASE_DIR

DATABASE = DATABASE_DIR / "guardian.db"


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

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS exclusions(
            path TEXT PRIMARY KEY
        )
        """)

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

    def add_quarantine(self, original, quarantine, virus):
        cursor = self.conn.cursor()

        cursor.execute("""
        INSERT INTO quarantine
        (timestamp, original_path, quarantine_path, virus)
        VALUES (?, ?, ?, ?)
        """, (
            datetime.now().isoformat(timespec="seconds"),
            original,
            quarantine,
            virus
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
            virus
        FROM quarantine
        ORDER BY id DESC
        """)

        return cursor.fetchall()

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

    def last_scan_run(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT timestamp, name, scanned, found, errors, cancelled, duration FROM scan_runs ORDER BY id DESC LIMIT 1")
        return cursor.fetchone()

    def get_exclusions(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT path FROM exclusions ORDER BY path")
        return [row[0] for row in cursor.fetchall()]

    def add_exclusion(self, path):
        self.conn.execute("INSERT OR IGNORE INTO exclusions(path) VALUES (?)", (str(path),))
        self.conn.commit()

    def remove_exclusion(self, path):
        self.conn.execute("DELETE FROM exclusions WHERE path=?", (str(path),))
        self.conn.commit()

    def clear_scans(self):
        self.conn.execute("DELETE FROM scans")
        self.conn.commit()

    def close(self):
        self.conn.close()
