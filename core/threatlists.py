"""Download the free threat lists the second-opinion engines use.

Everything is fetched over HTTPS without an account or key and saved in
Guardian's own data folder, so no administrator rights are needed. Users can
also drop their own *.txt hash lists and *.yar rule files into the same folders.
"""
import io
import os
import re
import urllib.error
import urllib.request
import zipfile
import core.paths as paths
from core.engines import NEVER_MALWARE, SHA256_LINE, _replace, hash_folder, rule_folder, yara_x
from core.log import log

TIMEOUT = 60
# Refuse anything implausibly large rather than fill the disk.
MAX_DOWNLOAD = 400 * 1024 * 1024
AGENT = "Guardian-AntiVirus"
# MalwareBazaar (abuse.ch): SHA-256 of malware samples. The full export seeds the
# list once; the much smaller recent export is merged in on later updates.
BAZAAR_FULL = "https://bazaar.abuse.ch/export/txt/sha256/full/"
BAZAAR_RECENT = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
# YARA Forge 'core': community rules filtered for quality and a low false-positive rate.
FORGE_CORE = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("download is larger than expected")
    return data


def unzip_one(data, suffix):
    """Contents of the single largest member with the given suffix; nothing is extracted to disk."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [m for m in archive.infolist() if m.filename.lower().endswith(suffix) and m.file_size <= MAX_DOWNLOAD]
        if not members:
            raise ValueError(f"no {suffix} file in the download")
        return archive.read(max(members, key=lambda m: m.file_size))


NEVER_LISTED = {digest.hex().encode() for digest in NEVER_MALWARE}
# A hash list is mostly fingerprints; an error or login page served in its place is not.
MIN_VALID_SHARE = 0.9
# A rule pack much smaller than the one installed is taken to be cut short.
MIN_RULE_SHARE = 0.5
RULE_LINE = re.compile(rb"(?m)^\s*(?:private\s+|global\s+)*rule\s+\w+")


def digests(data, strict=False):
    """SHA-256 fingerprints in a list. strict: refuse text that is not mostly a hash list."""
    found = set()
    other = 0
    for line in data.splitlines():
        match = SHA256_LINE.match(line)
        if match:
            found.add(match.group(1).lower())
        elif line.strip() and not line.lstrip().startswith(b"#"):
            other += 1
    if strict and other and other > (len(found) + other) * (1 - MIN_VALID_SHARE):
        raise ValueError("the server sent something that is not a hash list; the previous list was kept")
    return found - NEVER_LISTED


def update_hashes(fetch=fetch):
    target = hash_folder() / "malwarebazaar.txt"
    known = set()
    try:
        known = digests(target.read_bytes())
    except OSError:
        pass
    if known:
        fresh = digests(fetch(BAZAAR_RECENT), strict=True)
    else:
        data = fetch(BAZAAR_FULL)
        fresh = digests(unzip_one(data, ".txt") if data[:2] == b"PK" else data, strict=True)
    if not fresh and not known:
        raise ValueError("the list contained no SHA-256 fingerprints")
    merged = known | fresh
    if merged != known:
        _replace(str(target), lambda file: file.write(b"\n".join(sorted(merged)) + b"\n"))
    return f"{len(merged):,} fingerprints ({len(merged) - len(known):,} new)"


def update_rules(fetch=fetch):
    target = rule_folder() / "yara-forge-core.yar"
    text = unzip_one(fetch(FORGE_CORE), ".yar")
    count = len(RULE_LINE.findall(text))
    if not count:
        raise ValueError("the download contained no YARA rules")
    try:
        installed = len(RULE_LINE.findall(target.read_bytes()))
    except OSError:
        installed = 0
    if count < installed * MIN_RULE_SHARE:
        raise ValueError(f"the download has {count:,} rules where {installed:,} are installed, so it looks cut short; the previous rules were kept")
    if yara_x is not None:
        # A pack that does not compile would leave scans without any rules.
        try:
            yara_x.compile(text.decode("utf-8", "replace"))
        except Exception as exc:
            first = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
            raise ValueError(f"the downloaded rules do not compile ({first}); the previous rules were kept") from exc
    _replace(str(target), lambda file: file.write(text))
    return f"{count:,} rules"


def explain(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return f"the server refused the download (HTTP {exc.code}); it may now require an account"
        return f"the server answered HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"could not connect ({exc.reason})"
    return str(exc) or exc.__class__.__name__


# Seconds between automatic updates.
UPDATE_INTERVAL = 24 * 60 * 60


def stamp():
    return paths.THREATS / ".last-update"


def due(now=None):
    """True when the lists have not been refreshed, or tried, within the last day."""
    import time
    try:
        return (now or time.time()) - stamp().stat().st_mtime >= UPDATE_INTERVAL
    except OSError:
        return True


def update(fetch=fetch):
    """Refresh every list. Returns [(name, succeeded, message)]; one failure does not stop the others."""
    for folder in (hash_folder(), rule_folder()):
        os.makedirs(folder, exist_ok=True)
    # Recorded for failures too, so an unreachable server is retried daily rather than constantly.
    _replace(str(stamp()), lambda file: file.write(b""))
    outcome = []
    for name, action in (("MalwareBazaar hash list", update_hashes), ("YARA Forge core rules", update_rules)):
        try:
            outcome.append((name, True, action(fetch)))
        except Exception as exc:
            log.warning("Could not update %s: %s", name, exc)
            outcome.append((name, False, explain(exc)))
    return outcome
