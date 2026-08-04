from pathlib import Path
import subprocess

import pyclamd


class GuardianScanner:

    def __init__(self):
        self.clamd = None

        try:
            self.clamd = pyclamd.ClamdUnixSocket()

            if self.clamd.ping():
                print("Connected to ClamAV daemon.")

        except Exception:
            self.clamd = None
            print("ClamAV daemon unavailable. Using clamscan.")

    def scan_file(self, filepath):

        filepath = Path(filepath)

        if not filepath.exists():
            return {
                "status": "error",
                "virus": "File not found"
            }

        # --------------------------
        # Try clamd first
        # --------------------------

        if self.clamd:

            try:

                result = self.clamd.scan_file(str(filepath))

                if result is None:
                    return {
                        "status": "clean",
                        "virus": None
                    }

                _, (_, virus) = next(iter(result.items()))

                return {
                    "status": "found",
                    "virus": virus
                }

            except Exception:
                self.clamd = None

        # --------------------------
        # Fallback to clamscan
        # --------------------------

        try:

            result = subprocess.run(
                [
                    "clamscan",
                    "--no-summary",
                    str(filepath)
                ],
                capture_output=True,
                text=True,
            )

            output = result.stdout.strip()

            if "FOUND" in output:

                virus = output.split(":")[-1]
                virus = virus.replace("FOUND", "").strip()

                return {
                    "status": "found",
                    "virus": virus
                }

            if result.returncode == 0:

                return {
                    "status": "clean",
                    "virus": None
                }

            return {
                "status": "error",
                "virus": output
            }

        except Exception as e:

            return {
                "status": "error",
                "virus": str(e)
            }