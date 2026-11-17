"""Where Guardian's ClamAV keeps its virus definitions, and the commands that use them.

A normal install uses the system's ClamAV: definitions in /var/lib/clamav, kept
current by the FreshClam service, and the clamd daemon when it runs. Inside a
Flatpak none of that is reachable, so Guardian carries its own clamscan and
freshclam and keeps a private definitions folder in its data directory, which
it updates itself. GUARDIAN_CLAMAV_DB selects a private folder anywhere.
"""
import os
import time
from pathlib import Path
import core.paths as paths

# Distributions keep the system-wide definitions here.
SYSTEM_DATABASE = Path("/var/lib/clamav")
MIRROR = "database.clamav.net"
# Seconds between automatic definition updates when Guardian maintains them.
UPDATE_INTERVAL = 24 * 60 * 60
DEFINITION_SUFFIXES = (".cvd", ".cld")


def flatpak_id():
    """The Flatpak application ID when running inside one, else None."""
    return os.environ.get("FLATPAK_ID") or None


def private_database():
    """Guardian's own definitions folder, or None when the system's is used."""
    configured = os.environ.get("GUARDIAN_CLAMAV_DB")
    if configured:
        return Path(configured)
    if flatpak_id():
        return paths.DATA / "clamav"
    return None


def database_dirs():
    """Folders whose signature files define what the engine detects."""
    private = private_database()
    return (str(private),) if private else (str(SYSTEM_DATABASE),)


def scan_args():
    """Extra clamscan arguments that point it at the right definitions."""
    private = private_database()
    return ["--database=" + str(private)] if private else []


def version_command():
    return ["clamscan", "--version", *scan_args()]


def freshclam_command():
    """Command that updates the definitions Guardian scans with."""
    private = private_database()
    if not private:
        return ["freshclam", "--stdout"]
    private.mkdir(parents=True, exist_ok=True)
    config = private / "freshclam.conf"
    # freshclam will not start without a configuration file naming a mirror.
    config.write_text(f"DatabaseDirectory {private}\nDatabaseMirror {MIRROR}\nConnectTimeout 30\nReceiveTimeout 120\n")
    return ["freshclam", "--stdout", "--config-file=" + str(config), "--datadir=" + str(private)]


def has_definitions(folder=None):
    folder = Path(folder) if folder else private_database() or SYSTEM_DATABASE
    try:
        return any(entry.name.endswith(DEFINITION_SUFFIXES) for entry in os.scandir(folder))
    except OSError:
        return False


def definitions_due(now=None):
    """True when Guardian maintains its own definitions and they are missing or a day old."""
    private = private_database()
    if not private:
        return False
    try:
        newest = max(entry.stat().st_mtime for entry in os.scandir(private) if entry.name.endswith(DEFINITION_SUFFIXES + (".dat",)))
    except (OSError, ValueError):
        return True
    return (now or time.time()) - newest >= UPDATE_INTERVAL
