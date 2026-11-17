"""Tell the user when a newer Guardian release exists, and install it where Guardian can.

Once a day Guardian asks GitHub for the latest release. Nothing else is sent.
Installs made by install.sh or pipx live in their own Python environment, which
Guardian can upgrade itself; a Flatpak is updated by Flatpak, and a source
checkout by git.
"""
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path
import core.paths as paths
from core.clamav import flatpak_id
from core.version import VERSION

REPOSITORY = "PriceyLewis/Guardian-AntiVirus"
LATEST = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASES = f"https://github.com/{REPOSITORY}/releases"
CHECK_INTERVAL = 24 * 60 * 60
TIMEOUT = 20


def parse(version):
    """(1, 2, 0) from 'v1.2.0' or '1.2.0'; None for anything else."""
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.(\d+))?", (version or "").strip())
    return tuple(int(part or 0) for part in match.groups()) if match else None


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Guardian-AntiVirus", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read(1024 * 1024)


def latest_release(fetch=fetch):
    """{'version', 'tag', 'url'} of the newest published release, or None if there is none."""
    data = json.loads(fetch(LATEST))
    tag = data.get("tag_name", "")
    if data.get("draft") or data.get("prerelease") or not parse(tag):
        return None
    return {"version": tag.lstrip("v"), "tag": tag, "url": data.get("html_url") or RELEASES}


def newer(release, current=VERSION):
    return bool(release) and parse(release["version"]) > parse(current)


def install_kind():
    """'flatpak', 'checkout' (a git clone), 'environment' (install.sh or pipx) or 'system'."""
    if flatpak_id():
        return "flatpak"
    if (paths.ROOT / ".git").exists():
        return "checkout"
    # A virtual environment of its own, as pipx and install.sh create, is Guardian's to upgrade.
    if sys.prefix != sys.base_prefix and os.access(sys.prefix, os.W_OK):
        return "environment"
    return "system"


def update_command(release, with_yara=None):
    """pip command that upgrades this environment to the given release."""
    if with_yara is None:
        from core.engines import yara_x
        with_yara = yara_x is not None
    name = "guardian-antivirus[yara]" if with_yara else "guardian-antivirus"
    source = f"https://github.com/{REPOSITORY}/archive/refs/tags/{release['tag']}.tar.gz"
    return [sys.executable, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check", f"{name} @ {source}"]


def how_to_update(kind):
    """What the user should do when Guardian cannot update itself."""
    return {
        "flatpak": "Update it from your software centre, or run 'flatpak update' in a terminal.",
        "checkout": "Run 'git pull' in your Guardian folder.",
        "system": "Run the installer again: curl -fsSL https://raw.githubusercontent.com/PriceyLewis/Guardian-AntiVirus/main/install.sh | sh",
    }.get(kind, "")


def stamp():
    return paths.DATA / ".last-update-check"


def due(now=None):
    try:
        return (now or time.time()) - stamp().stat().st_mtime >= CHECK_INTERVAL
    except OSError:
        return True


def mark_checked():
    stamp().parent.mkdir(parents=True, exist_ok=True)
    stamp().touch()


def check(fetch=fetch):
    """The newer release, or None. Network errors count as 'nothing new' and are retried tomorrow."""
    mark_checked()
    try:
        release = latest_release(fetch)
    except Exception:
        return None
    return release if newer(release) else None
