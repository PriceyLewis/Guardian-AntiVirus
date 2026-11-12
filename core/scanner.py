import os
import queue
import socket
import subprocess
import tempfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from threading import Thread, local
import pyclamd
from config import load_config

# Debian/Ubuntu, Arch and Fedora/RHEL default clamd socket locations.
CLAMD_SOCKETS = ("/var/run/clamav/clamd.ctl", "/run/clamav/clamd.ctl", "/run/clamd.scan/clamd.sock")
DAEMON_TIMEOUT = 120
# clamd scans on several threads (MaxThreads); keep a few of them busy.
DAEMON_WORKERS = min(8, max(2, os.cpu_count() or 2))
# Each clamscan process loads the whole signature database (seconds of start-up and
# over a gigabyte of memory), so one scan shares as few processes as possible.
CLI_MAX_PROCESSES = 4
CLI_MIN_SHARE = 500
CLI_PROCESS_MEMORY = 2 * 1024 ** 3
# Seconds without any output before a clamscan run is abandoned.
CLI_IDLE_TIMEOUT = 900


def daemon_socket(timeout=5):
    """Path of the first clamd socket that answers a ping, or None."""
    for path in CLAMD_SOCKETS:
        try:
            if pyclamd.ClamdUnixSocket(filename=path, timeout=timeout).ping():
                return path
        except Exception:
            pass
    return None


def describe_engine(connected, archives):
    """Dashboard text saying which engine the next scan will use."""
    if not connected:
        return "Scan engine: ClamAV daemon not found · scans use clamscan, which is slower. Start the clamav-daemon service for faster scans."
    if not archives:
        return "Scan engine: ClamAV daemon connected, but not used while Inspect archives is off"
    return "Scan engine: ClamAV daemon connected · fast scanning"


class GuardianScanner:
    clamd = None
    # Path of the daemon's socket, when a real daemon answered.
    socket = None
    # Set once the daemon could not open a file by path; descriptors are passed from then on.
    pass_fd = False

    def __init__(self):
        self._local = local()
        self.socket = daemon_socket()
        if self.socket:
            self.clamd = pyclamd.ClamdUnixSocket(filename=self.socket, timeout=DAEMON_TIMEOUT)

    def scan_file(self, filepath):
        filepath = Path(filepath).absolute()
        if filepath.is_symlink() or not filepath.is_file():
            return {"status": "error", "virus": "Not a regular file"}
        # Archive policy is daemon-wide; use the CLI when archives are disabled.
        archives = load_config()["archives"]
        if self.clamd and archives:
            result = self._daemon_scan(filepath, self.clamd)
            if result:
                return result
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

    def _daemon_scan(self, path, client):
        """Ask clamd about one file; None means the command-line scanner should try."""
        try:
            if not self.pass_fd:
                result = client.scan_file(str(path))
                if result is None:
                    return {"status": "clean", "virus": None}
                status, detail = next(iter(result.values()))
                if status == "FOUND":
                    return {"status": "found", "virus": detail}
                if status == "OK":
                    return {"status": "clean", "virus": None}
                if not self.socket:
                    return None
                # Usually the daemon's own user may not read the file; an open
                # descriptor avoids starting clamscan for every such file.
                self.pass_fd = True
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError as exc:
                return {"status": "error", "virus": exc.strerror or str(exc)}
            try:
                detail = self._scan_descriptor(fd)
            finally:
                os.close(fd)
            if detail == "OK":
                return {"status": "clean", "virus": None}
            if detail.endswith(" FOUND"):
                return {"status": "found", "virus": detail[:-6]}
            return None
        except Exception:
            self.clamd = None
            return None

    def _scan_descriptor(self, fd):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(DAEMON_TIMEOUT)
            conn.connect(self.socket)
            conn.sendall(b"zFILDES\0")
            socket.send_fds(conn, [b"\0"], [fd])
            reply = b""
            while not reply.endswith(b"\0"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                reply += chunk
        # e.g. "fd[11]: Win.Test.EICAR_HDB-1 FOUND"
        return reply.rstrip(b"\0").decode(errors="replace").partition(": ")[2]

    def scan_files(self, filepaths, started=None):
        """Yield (path, result) pairs as they finish, which may not be in input order.

        The daemon is asked about several files at once; whatever it cannot answer
        shares clamscan processes. started, if given, receives the list of paths
        before each engine call.
        """
        archives = load_config()["archives"]
        paths = (Path(p).absolute() for p in filepaths)
        if self.clamd and archives:
            paths = yield from self._scan_daemon(paths, started)
        yield from self._scan_cli(list(paths), archives, started)

    def _scan_daemon(self, paths, started=None):
        """Yield daemon results; return the paths left for clamscan."""
        leftover = []
        running = {}
        with ThreadPoolExecutor(DAEMON_WORKERS) as pool:
            try:
                while True:
                    # Only as many files as workers are in flight, so closing stops promptly.
                    while self.clamd and len(running) < DAEMON_WORKERS:
                        path = next(paths, None)
                        if path is None:
                            break
                        if started:
                            started([path])
                        running[pool.submit(self._daemon_check, path)] = path
                    if not running:
                        break
                    for future in wait(running, return_when=FIRST_COMPLETED).done:
                        path = running.pop(future)
                        result = future.result()
                        if result is None:
                            leftover.append(path)
                        else:
                            yield path, result
            finally:
                for future in running:
                    future.cancel()
        leftover.extend(paths)
        return leftover

    def _daemon_check(self, path):
        if path.is_symlink() or not path.is_file():
            return {"status": "error", "virus": "Not a regular file"}
        return self._daemon_scan(path, self._thread_client())

    def _thread_client(self):
        """pyclamd clients keep per-call socket state, so each worker thread gets its own."""
        if not self.socket:
            return self.clamd
        if not hasattr(self._local, "client"):
            self._local.client = pyclamd.ClamdUnixSocket(filename=self.socket, timeout=DAEMON_TIMEOUT)
        return self._local.client

    def _scan_cli(self, paths, archives, started=None):
        if paths and started:
            started(paths)
        pending = {}
        for path in paths:
            # Newlines would make clamscan's line-based output ambiguous.
            if len(paths) == 1 or "\n" in str(path):
                yield path, self.scan_file(path)
            elif path.is_symlink() or not path.is_file():
                yield path, {"status": "error", "virus": "Not a regular file"}
            else:
                pending[str(path)] = path
        if not pending:
            return
        names = list(pending)
        count = cli_processes(len(names))
        lines = queue.Queue()
        runs = []
        try:
            for index in range(count):
                share = names[index::count]
                listing = tempfile.NamedTemporaryFile(prefix="guardian-scan-", suffix=".list")
                listing.write(b"\n".join(map(os.fsencode, share)) + b"\n")
                listing.flush()
                errors = tempfile.TemporaryFile()
                try:
                    process = subprocess.Popen(
                        ["clamscan", "--no-summary", "--stdout", "--scan-archive=" + ("yes" if archives else "no"),
                         "--file-list=" + listing.name],
                        stdout=subprocess.PIPE, stderr=errors, encoding="utf-8", errors="surrogateescape",
                    )
                except OSError as exc:
                    listing.close()
                    errors.close()
                    for name in share:
                        yield pending[name], {"status": "error", "virus": str(exc)}
                    continue
                runs.append({"process": process, "listing": listing, "errors": errors, "left": set(share)})
                Thread(target=self._read_lines, args=(len(runs) - 1, process, lines), daemon=True).start()
            active = len(runs)
            while active:
                try:
                    index, line = lines.get(timeout=CLI_IDLE_TIMEOUT)
                except queue.Empty:
                    for run in runs:
                        run["process"].kill()
                        for name in sorted(run["left"]):
                            yield pending[name], {"status": "error", "virus": "ClamAV scan timed out"}
                        run["left"] = set()
                    return
                run = runs[index]
                if line is not None:
                    name, _, detail = line.rstrip("\n").rpartition(": ")
                    if name not in run["left"]:
                        continue
                    run["left"].discard(name)
                    if detail in ("OK", "Empty file"):
                        yield pending[name], {"status": "clean", "virus": None}
                    elif detail.endswith(" FOUND"):
                        yield pending[name], {"status": "found", "virus": detail[:-6]}
                    else:
                        yield pending[name], {"status": "error", "virus": detail}
                    continue
                active -= 1
                failure = None
                if run["process"].wait() != 0:
                    run["errors"].seek(0)
                    failure = run["errors"].read().decode(errors="replace").strip()[-500:] or "No result reported by ClamAV"
                # Only a zero exit status vouches for files clamscan did not list.
                for name in sorted(run["left"]):
                    yield pending[name], {"status": "error", "virus": failure} if failure else {"status": "clean", "virus": None}
                run["left"] = set()
        finally:
            for run in runs:
                if run["process"].poll() is None:
                    run["process"].kill()
                run["process"].wait()
                run["process"].stdout.close()
                run["listing"].close()
                run["errors"].close()

    @staticmethod
    def _read_lines(index, process, lines):
        try:
            for line in process.stdout:
                lines.put((index, line))
        except (OSError, ValueError):
            pass
        lines.put((index, None))


def cli_processes(files):
    """How many clamscan processes to share files between.

    Each one loads its own copy of the signature database, so extra processes
    only pay off for large scans and need memory to spare.
    """
    try:
        with open("/proc/meminfo") as meminfo:
            available = next(int(line.split()[1]) for line in meminfo if line.startswith("MemAvailable:")) * 1024
    except (OSError, StopIteration, ValueError):
        available = 0
    return max(1, min(CLI_MAX_PROCESSES, os.cpu_count() or 1, files // CLI_MIN_SHARE, available // CLI_PROCESS_MEMORY))
