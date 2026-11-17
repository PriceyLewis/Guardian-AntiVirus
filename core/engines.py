"""Second-opinion engines that run on files ClamAV found clean.

Hash lookup compares a file's SHA-256 with lists of known malware: an exact
match is as reliable as the list. YARA-X matches community pattern rules,
which catch variants no list has seen but are more prone to false positives.

Both read their data from Guardian's own threat-list folder, filled by
core.threatlists or by the user, so neither needs an account or API key.
"""
import hashlib
import io
import mmap
import os
import re
import tarfile
import tempfile
import zipfile
import time
from bisect import bisect_left
from collections import deque
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from multiprocessing import get_context
from threading import Lock, local
import core.paths as paths
from config import load_config
from core.log import log

try:
    import yara_x
except ImportError:  # Optional: scanning works without it.
    yara_x = None

SHA256_LINE = re.compile(rb"^\s*\"?([0-9a-fA-F]{64})\"?\s*(?:[,;#].*)?$")
RULE_SUFFIXES = (".yar", ".yara")
# Files up to this size are read once and given to both engines from memory.
IN_MEMORY_LIMIT = 32 * 1024 * 1024
# YARA skips larger files: rules target executables, scripts and documents, not disk images.
YARA_SIZE_LIMIT = 512 * 1024 * 1024
YARA_TIMEOUT = 60
HASH_NAME = "Guardian.KnownMalware.SHA256"
# Fingerprints that must never count as malware, whatever a list says: a list that
# named the empty file would have every empty file on the computer quarantined.
NEVER_MALWARE = frozenset({bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")})
# Archives are opened one level deep, within limits that a hostile archive cannot push past.
ARCHIVE_MEMBERS = 200
ARCHIVE_MEMBER_SIZE = 32 * 1024 * 1024
ARCHIVE_TOTAL_SIZE = 128 * 1024 * 1024
# YARA-X holds Python's interpreter lock while it scans, so threads do not speed it up.
# Large scans use separate processes instead; each loads its own copy of the rules.
PROCESSES = min(4, os.cpu_count() or 1)
PROCESS_THRESHOLD = 1000
# Seconds a loaded set of engines is used before checking whether lists or settings changed.
FRESH_SECONDS = 30


def hash_folder():
    return paths.THREATS / "hashes"


def rule_folder():
    return paths.THREATS / "yara"


def _files(folder, suffixes):
    try:
        return sorted(entry.path for entry in os.scandir(folder) if entry.is_file() and entry.name.lower().endswith(suffixes))
    except OSError:
        return []


def _fingerprint(files, extra=""):
    parts = [extra]
    for path in files:
        try:
            stat = os.stat(path)
            parts.append(f"{os.path.basename(path)}:{stat.st_size}:{stat.st_mtime_ns}")
        except OSError:
            pass
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def _replace(path, write):
    """Write a file through a temporary neighbour so readers never see half of it."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, name = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as file:
            write(file)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _ignored():
    from database.database import GuardianDatabase
    try:
        db = GuardianDatabase()
        try:
            return db.ignored_hashes()
        finally:
            db.close()
    except Exception:
        return frozenset()


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _head(path):
    with open(path, "rb") as file:
        return file.read(512)


class HashList:
    """Known-malware SHA-256 digests from every *.txt list, as one sorted binary file."""

    def __init__(self):
        self.sources = _files(hash_folder(), (".txt",))
        self.fingerprint = _fingerprint(self.sources)
        self.count = 0
        self.data = None
        if not self.sources:
            return
        store = str(paths.THREATS / "hashes.bin")
        stamp = store + ".key"
        try:
            with open(stamp) as file:
                current = file.read() == self.fingerprint
        except OSError:
            current = False
        try:
            if not current or not os.path.exists(store):
                self._build(store)
                _replace(stamp, lambda file: file.write(self.fingerprint.encode()))
            size = os.path.getsize(store)
            if size >= 32:
                with open(store, "rb") as file:
                    self.data = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
                self.count = size // 32
        except (OSError, ValueError) as exc:
            log.warning("Could not load hash lists: %s", exc)

    def _build(self, store):
        digests = set()
        for source in self.sources:
            try:
                with open(source, "rb") as file:
                    for line in file:
                        match = SHA256_LINE.match(line)
                        if match:
                            digests.add(bytes.fromhex(match.group(1).decode()))
            except OSError as exc:
                log.warning("Could not read hash list %s: %s", source, exc)
        digests -= NEVER_MALWARE
        _replace(store, lambda file: file.write(b"".join(sorted(digests))))

    def __contains__(self, digest):
        if not self.data:
            return False
        low, high = 0, self.count
        while low < high:
            middle = (low + high) // 2
            entry = self.data[middle * 32:middle * 32 + 32]
            if entry == digest:
                return True
            if entry < digest:
                low = middle + 1
            else:
                high = middle
        return False


class YaraRules:
    """Every rule file in the rule folder, compiled once and cached on disk."""

    def __init__(self):
        self.sources = _files(rule_folder(), RULE_SUFFIXES)
        self.fingerprint = _fingerprint(self.sources, getattr(yara_x, "__version__", None) or "yara-x")
        self.rules = None
        self.errors = []
        self.local = local()
        if yara_x is None or not self.sources:
            return
        cache = str(paths.THREATS / "rules.compiled")
        stamp = cache + ".key"
        try:
            with open(stamp) as file:
                if file.read() == self.fingerprint:
                    with open(cache, "rb") as compiled:
                        self.rules = yara_x.Rules.deserialize_from(compiled)
                    return
        except Exception:
            pass  # Missing or made by another version: compile again.
        compiler = yara_x.Compiler()
        loaded = 0
        for source in self.sources:
            # A namespace per file keeps rule names from different packs apart, and a
            # file that does not compile is left out instead of spoiling the rest.
            try:
                with open(source, encoding="utf-8", errors="replace") as file:
                    text = file.read()
                trial = yara_x.Compiler()
                trial.add_source(text)
                compiler.new_namespace(os.path.basename(source))
                compiler.add_source(text)
                loaded += 1
            except Exception as exc:
                self.errors.append(f"{os.path.basename(source)}: {str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__}")
        for error in self.errors:
            log.warning("YARA rule file skipped: %s", error)
        if not loaded:
            return
        try:
            self.rules = compiler.build()
            buffer = io.BytesIO()
            self.rules.serialize_into(buffer)
            _replace(cache, lambda file: file.write(buffer.getvalue()))
            _replace(stamp, lambda file: file.write(self.fingerprint.encode()))
        except Exception as exc:
            log.warning("Could not prepare YARA rules: %s", exc)

    def scanner(self):
        # Scanners hold per-scan state, so each thread gets its own over the shared rules.
        if not hasattr(self.local, "scanner"):
            self.local.scanner = yara_x.Scanner(self.rules)
            self.local.scanner.set_timeout(YARA_TIMEOUT)
        return self.local.scanner

    def match(self, path=None, data=None):
        """Name of the detection for a file, or None."""
        if not self.rules:
            return None
        results = self.scanner().scan(data) if data is not None else self.scanner().scan_file(os.fspath(path))
        names = [rule.identifier for rule in results.matching_rules]
        if not names:
            return None
        return "YARA." + names[0] + (f" (+{len(names) - 1} more)" if len(names) > 1 else "")


class SecondOpinion:
    """The extra engines the user has switched on, loaded on first use."""

    def __init__(self, use_hashes=None, use_yara=None, ignored=None, archives=None):
        settings = load_config()
        self.archives = settings["archives"] if archives is None else archives
        # SHA-256 of files the user chose to ignore after a pattern-rule match.
        self.ignored = _ignored() if ignored is None else frozenset(ignored)
        self.use_hashes = settings["hash_lookup"] if use_hashes is None else use_hashes
        self.use_yara = (settings["yara_scan"] if use_yara is None else use_yara) and yara_x is not None
        self.made = time.monotonic()
        self.lock = Lock()
        self.loaded = False
        self.hashes = None
        self.yara = None
        # Background scans keep to one thread instead of several worker processes.
        self.gentle = False
        self.identity = self._identity()

    def _identity(self):
        parts = []
        if self.use_hashes:
            parts.append("hashes=" + _fingerprint(_files(hash_folder(), (".txt",))))
        if self.use_yara:
            parts.append("yara=" + _fingerprint(_files(rule_folder(), RULE_SUFFIXES), getattr(yara_x, "__version__", None) or "yara-x"))
        if parts:
            parts.append(f"inside-archives={self.archives}")
        return "|".join(parts)

    def key(self):
        """Text that changes whenever these engines would judge a file differently."""
        return self.identity

    def expired(self):
        """True once settings or list files may have changed since this was made."""
        if time.monotonic() - self.made < FRESH_SECONDS:
            return False
        settings = load_config()
        fresh = ((settings["hash_lookup"], settings["yara_scan"] and yara_x is not None, settings["archives"]) == (self.use_hashes, self.use_yara, self.archives)
                 and self._identity() == self.identity and _ignored() == self.ignored)
        if fresh:
            self.made = time.monotonic()
        return not fresh

    def _load(self):
        with self.lock:
            if not self.loaded:
                if self.use_hashes:
                    self.hashes = HashList()
                if self.use_yara:
                    self.yara = YaraRules()
                self.loaded = True

    def active(self):
        """Whether any engine has data to check files against."""
        self._load()
        return bool((self.hashes and self.hashes.count) or (self.yara and self.yara.rules))

    def check(self, path):
        """Detection for a file ClamAV passed, as a result dict, or None if nothing matched.

        Problems reading the file are not errors here: ClamAV already scanned it.
        """
        if not self.active():
            return None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            with os.fdopen(fd, "rb") as file:
                size = os.fstat(file.fileno()).st_size
                data = file.read() if size <= IN_MEMORY_LIMIT else None
                digest = hashlib.sha256()
                if data is not None:
                    digest.update(data)
                elif self.hashes and self.hashes.count:
                    for block in iter(lambda: file.read(1024 * 1024), b""):
                        digest.update(block)
            if self.hashes and self.hashes.count and digest.digest() in self.hashes:
                return {"status": "found", "virus": HASH_NAME, "engine": "hash", "sha256": digest.hexdigest()}
            found = None
            if self.yara and self.yara.rules and size <= YARA_SIZE_LIMIT:
                name = self.yara.match(path, data)
                if name:
                    found = {"status": "found", "virus": name, "engine": "yara"}
            if not found and self.archives and size <= ARCHIVE_TOTAL_SIZE:
                found = self._check_archive(path, data)
            if found and found["engine"] == "yara" and self.ignored:
                found["sha256"] = digest.hexdigest() if data is not None or (self.hashes and self.hashes.count) else _sha256(path)
                if found["sha256"] in self.ignored:
                    return None
            return found
        except Exception as exc:
            log.warning("Second-opinion check failed for %s: %s", paths.display(path), exc)
        return None

    def _check_member(self, name, data):
        if self.hashes and self.hashes.count and hashlib.sha256(data).digest() in self.hashes:
            return {"status": "found", "virus": f"{HASH_NAME} (in archive: {name})", "engine": "hash"}
        if self.yara and self.yara.rules:
            match = self.yara.match(data=data)
            if match:
                return {"status": "found", "virus": f"{match} (in archive: {name})", "engine": "yara"}
        return None

    def _check_archive(self, path, data):
        """Check the files inside a zip or tar archive, as ClamAV does for its own signatures."""
        source = io.BytesIO(data) if data is not None else None
        head = data[:512] if data is not None else _head(path)
        total = 0
        try:
            if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
                with zipfile.ZipFile(source or path) as archive:
                    for member in archive.infolist()[:ARCHIVE_MEMBERS]:
                        # Declared sizes can lie, so the read itself is capped too.
                        if member.is_dir() or member.flag_bits & 1 or member.file_size > ARCHIVE_MEMBER_SIZE:
                            continue
                        with archive.open(member) as file:
                            content = file.read(ARCHIVE_MEMBER_SIZE + 1)
                        total += len(content)
                        if len(content) > ARCHIVE_MEMBER_SIZE or total > ARCHIVE_TOTAL_SIZE:
                            break
                        found = self._check_member(paths.display(member.filename)[:120], content)
                        if found:
                            return found
            elif head[:2] in (b"\x1f\x8b", b"BZ") or head[:6] == b"\xfd7zXZ\x00" or head[257:262] == b"ustar":
                with tarfile.open(name=None if source else path, fileobj=source, mode="r:*") as archive:
                    for count, member in enumerate(archive):
                        if count >= ARCHIVE_MEMBERS:
                            break
                        if not member.isfile() or member.size > ARCHIVE_MEMBER_SIZE:
                            continue
                        content = archive.extractfile(member).read(ARCHIVE_MEMBER_SIZE + 1)
                        total += len(content)
                        if len(content) > ARCHIVE_MEMBER_SIZE or total > ARCHIVE_TOTAL_SIZE:
                            break
                        found = self._check_member(paths.display(member.name)[:120], content)
                        if found:
                            return found
        except Exception:
            # Damaged, encrypted or merely archive-like files are ClamAV's to judge.
            return None
        return None

    def review(self, results, expected=0):
        """Pass (path, result) pairs through, giving the clean ones a second opinion.

        expected is roughly how many pairs will come; large scans are spread over
        processes. Results keep their order, and closing this generator also
        closes the one it reads.
        """
        if not self.active():
            yield from results
            return
        if expected >= PROCESS_THRESHOLD and PROCESSES > 1 and not self.gentle:
            # 'spawn' starts clean interpreters; forking a process that has threads and a GUI is unsafe.
            pool = ProcessPoolExecutor(PROCESSES, mp_context=get_context("spawn"), initializer=_start_process,
                                       initargs=(str(paths.THREATS), self.use_hashes, self.use_yara, sorted(self.ignored), self.archives))
            check, ahead = _process_check, 8 * PROCESSES
        else:
            pool = ThreadPoolExecutor(1, thread_name_prefix="guardian-second-opinion")
            check, ahead = self.check, 4
        waiting = deque()
        state = {"pool": pool, "check": check}

        def submit(path):
            try:
                return state["pool"].submit(state["check"], path)
            except Exception as exc:
                # The worker processes could not start or have died: carry on in this process.
                log.warning("Second-opinion workers stopped (%s); continuing without them", exc)
                state["pool"].shutdown(wait=False, cancel_futures=True)
                state.update(pool=ThreadPoolExecutor(1, thread_name_prefix="guardian-second-opinion"), check=self.check)
                return state["pool"].submit(self.check, path)

        def settle(entry):
            path, result, future = entry
            if not future:
                return path, result
            try:
                found = future.result()
            except Exception:
                # A worker process died; this file is still checked, here.
                found = self.check(path)
            return path, found or result

        try:
            for path, result in results:
                waiting.append((path, result, submit(path) if result["status"] == "clean" else None))
                if len(waiting) >= ahead:
                    yield settle(waiting.popleft())
            while waiting:
                yield settle(waiting.popleft())
        finally:
            state["pool"].shutdown(wait=True, cancel_futures=True)
            close = getattr(results, "close", None)
            if close:
                close()


_process_engines = None


def _start_process(threats, use_hashes, use_yara, ignored, archives):
    """Runs once in each worker process: point it at the same lists and choices as its parent."""
    global _process_engines
    from pathlib import Path
    paths.THREATS = Path(threats)
    _process_engines = SecondOpinion(use_hashes, use_yara, ignored, archives)


def _process_check(path):
    return _process_engines.check(path)


def status():
    """Counts for the settings page: what each engine currently has to work with."""
    settings = load_config()
    hashes = HashList()
    rules = _files(rule_folder(), RULE_SUFFIXES)
    newest = 0
    for path in hashes.sources + rules:
        try:
            newest = max(newest, os.stat(path).st_mtime)
        except OSError:
            pass
    return {"hash_lookup": settings["hash_lookup"], "yara_scan": settings["yara_scan"], "hashes": hashes.count,
            "hash_files": len(hashes.sources), "rule_files": len(rules), "yara_installed": yara_x is not None, "updated": newest}


def describe(state):
    """Return (text, needs_attention)."""
    parts = []
    attention = False
    if state["hashes"]:
        parts.append(f"Hash lookup: {state['hashes']:,} known-malware fingerprints" + ("" if state["hash_lookup"] else " (switched off)"))
    else:
        parts.append("Hash lookup: no lists downloaded yet")
    if not state["yara_installed"]:
        parts.append("YARA-X: not installed. Install it with 'pip install yara-x' in Guardian's Python environment.")
        attention = state["yara_scan"]
    elif state["rule_files"]:
        parts.append(f"YARA-X: {state['rule_files']} rule file{'s' if state['rule_files'] != 1 else ''}" + ("" if state["yara_scan"] else " (switched off)"))
    else:
        parts.append("YARA-X: no rules downloaded yet")
    if state["updated"]:
        parts.append("Last updated " + time.strftime("%d %b %Y, %H:%M", time.localtime(state["updated"])))
    return " · ".join(parts), attention
