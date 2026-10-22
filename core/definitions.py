"""Describe ClamAV signature freshness from `clamscan --version` output."""
from datetime import datetime

STALE_DAYS = 7


def parse_version(output):
    """Parse e.g. 'ClamAV 1.5.4/27500/Tue Oct 21 08:23:45 2026'.

    Without an official signature database clamscan prints only 'ClamAV 1.5.4'.
    """
    line = output.strip().splitlines()[0] if output.strip() else ""
    parts = line.split("/")
    info = {"engine": parts[0].strip(), "version": None, "updated": None}
    if len(parts) >= 3:
        info["version"] = parts[1].strip()
        try:
            info["updated"] = datetime.strptime(parts[2].strip(), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            pass
    return info


def describe(output, now=None):
    """Return (text, needs_attention) for the dashboard."""
    info = parse_version(output)
    if not info["engine"].startswith("ClamAV"):
        return "ClamAV not found. Install ClamAV to enable scanning.", True
    if not info["version"]:
        return info["engine"] + " · no official signature database. Run freshclam to download definitions.", True
    if not info["updated"]:
        return f"{info['engine']} · definitions version {info['version']}", False
    age = ((now or datetime.now()) - info["updated"]).days
    when = "today" if age < 1 else ("1 day ago" if age == 1 else f"{age} days ago")
    text = f"{info['engine']} · definitions {info['version']}, updated {when}"
    if age > STALE_DAYS:
        return text + ". Definitions are out of date; check that FreshClam is running.", True
    return text, False
