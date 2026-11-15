"""Status and setup guidance for extra, community-maintained ClamAV signatures.

freshclam can fetch additional signature files alongside the official ones.
Its configuration is root-owned, so Guardian reports what is configured and
explains the steps rather than escalating privileges itself.
"""
from pathlib import Path
from core.onaccess import read_config
from core.scanner import DATABASE_DIRS

# Debian/Ubuntu, then Fedora/RHEL and Arch.
FRESHCLAM_CONFIGS = ("/etc/clamav/freshclam.conf", "/etc/freshclam.conf")
# Free sources that freshclam can download directly, without an account.
SOURCES = (
    ("URLhaus (abuse.ch)", "https://urlhaus.abuse.ch/downloads/urlhaus.ndb",
     "Recognises files that contain links to sites currently distributing malware."),
)


def status(configs=FRESHCLAM_CONFIGS, folders=DATABASE_DIRS):
    path, options = read_config(configs)
    urls = options.get("DatabaseCustomURL", [])
    installed = [name for name, url, _ in SOURCES
                 if any((Path(folder) / url.rsplit("/", 1)[-1]).is_file() for folder in folders)]
    return {"config": path, "urls": urls, "installed": installed,
            "pending": [name for name, url, _ in SOURCES if url in urls and name not in installed]}


def describe(state):
    """Return (text, needs_attention)."""
    if state["installed"]:
        return "In use: " + ", ".join(state["installed"]) + ". Detections from these sources end in .UNOFFICIAL.", False
    if state["pending"]:
        return "Configured but not downloaded yet: " + ", ".join(state["pending"]) + ". Update definitions, then check again.", True
    return "Not in use. Scans rely on ClamAV's official signatures only.", False


def setup_steps(state):
    config = state["config"] or "/etc/clamav/freshclam.conf (Debian/Ubuntu) or /etc/freshclam.conf (Fedora, Arch)"
    lines = [
        "Extra signature sources catch threats the official ClamAV database misses.",
        "They are maintained by third parties, so expect more false positives; a",
        "detection ending in .UNOFFICIAL came from one of them. Look such files up",
        "on VirusTotal before deleting anything you care about.",
        "",
        f"1. Add a line to {config} for each source you want (needs administrator rights):",
        "",
    ]
    for name, url, purpose in SOURCES:
        lines += [f"# {name}: {purpose}", f"DatabaseCustomURL {url}", ""]
    lines += [
        "2. Download them and let the scanner pick them up:",
        "",
        "sudo systemctl restart clamav-freshclam",
        "",
        "   If that service does not exist on your system, run 'sudo freshclam' instead.",
        "",
        "3. Return here and choose Check again.",
        "",
        "For larger collections such as SaneSecurity, install the 'fangfrisch' tool,",
        "which downloads and verifies several community sources on a schedule.",
    ]
    return "\n".join(lines)
