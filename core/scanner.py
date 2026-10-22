from pathlib import Path
import subprocess
import pyclamd
from config import load_config

# Debian/Ubuntu, Arch and Fedora/RHEL default clamd socket locations.
CLAMD_SOCKETS = ("/var/run/clamav/clamd.ctl", "/run/clamav/clamd.ctl", "/run/clamd.scan/clamd.sock")
# Each clamscan process loads the whole signature database, so files are batched.
CLI_BATCH = 100


class GuardianScanner:
    def __init__(self):
        self.clamd = None
        for socket in CLAMD_SOCKETS:
            try:
                client = pyclamd.ClamdUnixSocket(filename=socket, timeout=30)
                if client.ping():
                    self.clamd = client
                    break
            except Exception:
                pass

    def scan_file(self, filepath):
        filepath = Path(filepath).absolute()
        if filepath.is_symlink() or not filepath.is_file():
            return {"status": "error", "virus": "Not a regular file"}
        # Archive policy is daemon-wide; use the CLI when archives are disabled.
        archives = load_config()["archives"]
        if self.clamd and archives:
            try:
                result = self.clamd.scan_file(str(filepath))
                if result is None:
                    return {"status": "clean", "virus": None}
                status, detail = next(iter(result.values()))
                if status == "FOUND":
                    return {"status": "found", "virus": detail}
                if status == "OK":
                    return {"status": "clean", "virus": None}
                # Daemon permission errors may be recoverable by a user scan.
            except Exception:
                self.clamd = None
        try:
            result = subprocess.run(
                ["clamscan", "--no-summary", "--scan-archive=" + ("yes" if archives else "no"), "--", str(filepath)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                return {"status": "clean", "virus": None}
            if result.returncode == 1:
                detections = [line for line in result.stdout.splitlines() if line.endswith(" FOUND")]
                if detections:
                    return {"status": "found", "virus": detections[0].rsplit(": ", 1)[-1][:-6]}
            return {"status": "error", "virus": (result.stderr or result.stdout).strip() or "ClamAV scan failed"}
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "error", "virus": str(exc)}

    def scan_files(self, filepaths):
        """Yield (path, result) pairs, batching clamscan runs when the daemon is unavailable."""
        archives = load_config()["archives"]
        batch = []
        for path in (Path(p).absolute() for p in filepaths):
            # Newlines would make clamscan's line-based output ambiguous.
            if (self.clamd and archives) or "\n" in str(path):
                yield from self._scan_batch(batch, archives)
                batch = []
                yield path, self.scan_file(path)
                continue
            batch.append(path)
            if len(batch) >= CLI_BATCH:
                yield from self._scan_batch(batch, archives)
                batch = []
        yield from self._scan_batch(batch, archives)

    def _scan_batch(self, paths, archives):
        if len(paths) <= 1:
            for path in paths:
                yield path, self.scan_file(path)
            return
        results = {}
        pending = {}
        for path in paths:
            if path.is_symlink() or not path.is_file():
                results[path] = {"status": "error", "virus": "Not a regular file"}
            else:
                pending[str(path)] = path
        if pending:
            try:
                run = subprocess.run(
                    ["clamscan", "--no-summary", "--scan-archive=" + ("yes" if archives else "no"), "--", *pending],
                    capture_output=True, text=True, timeout=120 + 10 * len(pending),
                )
                for line in run.stdout.splitlines():
                    name, _, detail = line.rpartition(": ")
                    if name not in pending or pending[name] in results:
                        continue
                    if detail in ("OK", "Empty file"):
                        results[pending[name]] = {"status": "clean", "virus": None}
                    elif detail.endswith(" FOUND"):
                        results[pending[name]] = {"status": "found", "virus": detail[:-6]}
                    else:
                        results[pending[name]] = {"status": "error", "virus": detail}
                failure = None if run.returncode == 0 else (run.stderr or run.stdout).strip() or "No result reported by ClamAV"
            except (OSError, subprocess.TimeoutExpired) as exc:
                failure = str(exc)
            # Only a zero exit status vouches for files clamscan did not list.
            for path in pending.values():
                if path not in results:
                    results[path] = {"status": "error", "virus": failure} if failure else {"status": "clean", "virus": None}
        for path in paths:
            yield path, results[path]
