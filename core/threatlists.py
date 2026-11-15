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
from core.engines import SHA256_LINE, _replace, hash_folder, rule_folder
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


def digests(data):
    return {match.group(1).lower() for match in map(SHA256_LINE.match, data.splitlines()) if match}


def update_hashes(fetch=fetch):
    target = hash_folder() / "malwarebazaar.txt"
    known = set()
    try:
        known = digests(target.read_bytes())
    except OSError:
        pass
    if known:
        fresh = digests(fetch(BAZAAR_RECENT))
    else:
        data = fetch(BAZAAR_FULL)
        fresh = digests(unzip_one(data, ".txt") if data[:2] == b"PK" else data)
    if not fresh and not known:
        raise ValueError("the list contained no SHA-256 fingerprints")
    merged = known | fresh
    if merged != known:
        _replace(str(target), lambda file: file.write(b"\n".join(sorted(merged)) + b"\n"))
    return f"{len(merged):,} fingerprints ({len(merged) - len(known):,} new)"


def update_rules(fetch=fetch):
    text = unzip_one(fetch(FORGE_CORE), ".yar")
    count = len(re.findall(rb"(?m)^\s*(?:private\s+|global\s+)*rule\s+\w+", text))
    if not count:
        raise ValueError("the download contained no YARA rules")
    _replace(str(rule_folder() / "yara-forge-core.yar"), lambda file: file.write(text))
    return f"{count:,} rules"


def explain(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return f"the server refused the download (HTTP {exc.code}); it may now require an account"
        return f"the server answered HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"could not connect ({exc.reason})"
    return str(exc) or exc.__class__.__name__


def update(fetch=fetch):
    """Refresh every list. Returns [(name, succeeded, message)]; one failure does not stop the others."""
    for folder in (hash_folder(), rule_folder()):
        os.makedirs(folder, exist_ok=True)
    outcome = []
    for name, action in (("MalwareBazaar hash list", update_hashes), ("YARA Forge core rules", update_rules)):
        try:
            outcome.append((name, True, action(fetch)))
        except Exception as exc:
            log.warning("Could not update %s: %s", name, exc)
            outcome.append((name, False, explain(exc)))
    return outcome
