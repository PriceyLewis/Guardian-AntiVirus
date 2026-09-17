from pathlib import Path
import subprocess
import pyclamd
from config import load_config


class GuardianScanner:
    def __init__(self):
        self.clamd = None
        try:
            client = pyclamd.ClamdUnixSocket(timeout=30)
            if client.ping():
                self.clamd = client
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
