"""Addresses of VirusTotal's public report pages, opened in the user's browser.

No API key is involved and no file is ever uploaded: a file is identified by
its SHA-256 fingerprint only, and a link by its address.
"""
import re
import subprocess
from urllib.parse import quote, urlsplit

SITE = "https://www.virustotal.com/gui/"
DOMAIN = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", re.IGNORECASE)


def file_url(sha256):
    """Report page for a file fingerprint, or None if it is not a SHA-256."""
    digest = (sha256 or "").strip().lower()
    return SITE + "file/" + digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None


def link_url(text):
    """Report page for a web address or bare domain, or None if it is neither."""
    text = (text or "").strip()
    if DOMAIN.fullmatch(text):
        return SITE + "domain/" + text.lower()
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host or any(c.isspace() for c in text):
        return None
    # The site's search page expects the address percent-encoded twice.
    return SITE + "search/" + quote(quote(text, safe=""), safe="")


def open_externally(url):
    """Open a report without touching the GUI, for use from background threads."""
    try:
        subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False

