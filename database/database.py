import sqlite3
from datetime import datetime, timedelta
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

        # Files found clean by the engine version stored under meta 'engine'.
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS clean_cache(
            path TEXT PRIMARY KEY,
            size INTEGER,
            mtime INTEGER,
            ctime INTEGER,
            inode INTEGER
        )
        """)
        cursor.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")
        # Files the user has judged safe after a pattern-rule match, by content.
        cursor.execute("CREATE TABLE IF NOT EXISTS ignored(sha256 TEXT PRIMARY KEY, path TEXT, added TEXT)")

        if "sha256" not in [row[1] for row in cursor.execute("PRAGMA table_info(scans)")]:
            cursor.execute("ALTER TABLE scans ADD COLUMN sha256 TEXT")

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

    def add_scan(self, filepath, status, virus=None, sha256=None):
        self.record_scans([(datetime.now().isoformat(timespec="seconds"), filepath, status, virus, sha256)])

    def record_scans(self, rows, clean=(), stale=()):
        """Store (timestamp, filepath, status, virus, sha256) rows in one short transaction.

        clean holds (path, signature) pairs to remember as unchanged-and-clean;
        stale holds paths to forget. Bulk scans collect results and call this
        about once a second: a commit per file forces a disk sync each time,
        while a transaction left open between results would lock out other writers.
        """
        self.conn.executemany("INSERT INTO scans(timestamp, filepath, status, virus, sha256) VALUES (?, ?, ?, ?, ?)", rows)
        self.conn.executemany("INSERT OR REPLACE INTO clean_cache(path, size, mtime, ctime, inode) VALUES (?, ?, ?, ?, ?)",
                              [(path, *signature) for path, signature in clean])
        self.conn.executemany("DELETE FROM clean_cache WHERE path=?", [(path,) for path in stale])
        self.commit()

    def commit(self):
        self.conn.commit()

    def detection_hash(self, filepath):
        """SHA-256 of the most recent detection at a path, from history or quarantine."""
        for query in ("SELECT sha256 FROM scans WHERE filepath=? AND status IN ('found', 'suspicious', 'ignored') AND sha256 IS NOT NULL ORDER BY id DESC LIMIT 1",
                      "SELECT sha256 FROM quarantine WHERE original_path=? AND sha256 IS NOT NULL ORDER BY id DESC LIMIT 1"):
            row = self.conn.execute(query, (filepath,)).fetchone()
            if row:
                return row[0]
        return None

    def ignored_hashes(self):
        return frozenset(row[0] for row in self.conn.execute("SELECT sha256 FROM ignored"))

    def ignore_file(self, sha256, path):
        """Stop reporting pattern-rule matches for a file with this content."""
        self.conn.execute("INSERT OR REPLACE INTO ignored(sha256, path, added) VALUES (?, ?, ?)",
                          (sha256, path, datetime.now().isoformat(timespec="seconds")))
        self.conn.execute("UPDATE scans SET status='ignored' WHERE status='suspicious' AND sha256=?", (sha256,))
        self.conn.commit()

    def clear_ignored(self):
        """Forget every ignored file. Remembered clean results go too, so those files are judged afresh."""
        count = self.conn.execute("DELETE FROM ignored").rowcount
        self.conn.execute("DELETE FROM clean_cache")
        self.conn.commit()
        return count

    def mark_quarantined(self, filepath):
        """A suspicious file the user chose to quarantine now counts as a detection."""
        self.conn.execute("UPDATE scans SET status='found' WHERE status='suspicious' AND filepath=?", (filepath,))
        self.conn.commit()

    def get_suspicious_count(self):
        return self.conn.execute("SELECT COUNT(DISTINCT filepath) FROM scans WHERE status='suspicious'").fetchone()[0]

    def prune_scans(self, days):
        """Delete per-file history older than days; returns the number of rows removed."""
        if not days:
            return 0
        cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
        removed = self.conn.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,)).rowcount
        self.conn.execute("DELETE FROM scan_runs WHERE timestamp < ?", (cutoff,))
        self.conn.commit()
        return removed

    def cache_engine(self, key):
        """Start using the clean-file cache for an engine version, emptying it if that changed.

        New signatures may recognise a file that older ones passed.
        """
        row = self.conn.execute("SELECT value FROM meta WHERE key='engine'").fetchone()
        if not row or row[0] != key:
            self.conn.execute("DELETE FROM clean_cache")
            self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('engine', ?)", (key,))
            self.conn.commit()

    def cached_clean(self, path):
        """(size, mtime, ctime, inode) the file had when it was last found clean, or None."""
        return self.conn.execute("SELECT size, mtime, ctime, inode FROM clean_cache WHERE path=?", (path,)).fetchone()

    def clear_clean_cache(self):
        self.conn.execute("DELETE FROM clean_cache")
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
