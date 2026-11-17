"""End-to-end checks against the real ClamAV engine.

Skipped unless GUARDIAN_REAL_CLAMAV=1; CI installs ClamAV and sets it. Daemon
checks also need GUARDIAN_REAL_CLAMD=1 and a running clamd whose definitions
include SIGNATURE below. Many of the bugs fixed in 1.2 only showed up here.
"""
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
import pytest
from test_guardian import isolated

pytestmark = pytest.mark.skipif(os.environ.get("GUARDIAN_REAL_CLAMAV") != "1", reason="set GUARDIAN_REAL_CLAMAV=1 to test against real ClamAV")
needs_daemon = pytest.mark.skipif(os.environ.get("GUARDIAN_REAL_CLAMD") != "1", reason="set GUARDIAN_REAL_CLAMD=1 with clamd running")

SAMPLE = b"Guardian real-engine test sample, harmless\n"
SIGNATURE = f"{hashlib.md5(SAMPLE).hexdigest()}:{len(SAMPLE)}:Guardian.Test.Sample\n"
ROOT = Path(__file__).resolve().parents[1]
# Names that broke, or could break, the line-based protocols of clamd and clamscan.
HOSTILE = [b" lead.bin", b"trail .bin", b"#hash.bin", b"-dash.bin", b"tab\tname.bin", b"quote'\".bin", b"star*?.bin",
           b"back\\slash.bin", b"cr\rname.bin", b"decoy\n.bin", b"x: OK", b"y: Sample FOUND", b"\xe2\x98\x83.bin",
           b"bad\xff.bin", b"a" * 250 + b".bin"]


@pytest.fixture
def database(tmp_path, monkeypatch):
    """A private definitions folder holding only the test signature."""
    folder = tmp_path / "definitions"
    folder.mkdir()
    (folder / "guardian-test.hdb").write_text(SIGNATURE)
    monkeypatch.setenv("GUARDIAN_CLAMAV_DB", str(folder))
    return folder


def hostile_tree(base):
    """Every hostile name holds the sample; 'decoy' (a prefix of 'decoy\\n.bin') is harmless."""
    root = os.fsencode(base / "hostile")
    os.makedirs(root)
    for name in HOSTILE:
        with open(root + b"/" + name, "wb") as file:
            file.write(SAMPLE)
    with open(root + b"/decoy", "wb") as file:
        file.write(b"harmless")
    deep = root
    for _ in range(8):
        deep += b"/" + b"d" * 200
    os.makedirs(deep)
    with open(deep + b"/deep.bin", "wb") as file:
        file.write(SAMPLE)
    os.chmod(root, 0o755)
    for directory, folders, names in os.walk(root):
        os.chmod(directory, 0o755)
        for name in names:
            os.chmod(os.path.join(directory, name), 0o644)
    return sorted(Path(os.fsdecode(os.path.join(d, n))) for d, _, names in os.walk(root) for n in names)


def wrong_verdicts(scanner, files):
    results = dict(scanner.scan_files(files))
    assert len(results) == len(files)
    return [(os.fsencode(path.name)[:40], result) for path, result in results.items()
            if (result["status"] == "found") != (path.name != "decoy")]


def test_clamscan_handles_hostile_file_names(isolated, database):
    from core.scanner import GuardianScanner
    files = hostile_tree(isolated)
    scanner = GuardianScanner()
    assert scanner.clamd is None
    assert wrong_verdicts(scanner, files) == []
    assert all(scanner.scan_file(path)["status"] == "found" for path in files if path.name in (" lead.bin", "deep.bin"))


@needs_daemon
@pytest.mark.parametrize("by_descriptor", [False, True])
def test_daemon_handles_hostile_file_names(isolated, monkeypatch, by_descriptor):
    monkeypatch.delenv("GUARDIAN_CLAMAV_DB", raising=False)
    monkeypatch.delenv("FLATPAK_ID", raising=False)
    from core.scanner import GuardianScanner
    files = hostile_tree(isolated)
    scanner = GuardianScanner()
    assert scanner.clamd, "clamd is not answering"
    scanner.pass_fd = by_descriptor
    assert wrong_verdicts(scanner, files) == []


def run_cli(isolated, *args, env=None):
    environment = dict(os.environ, GUARDIAN_DATA_DIR=str(isolated / "data"), QT_QPA_PLATFORM="offscreen", **(env or {}))
    return subprocess.run([sys.executable, str(ROOT / "guardian.py"), "--scan", *args], capture_output=True, text=True,
                          env=environment, timeout=600)


def test_command_line_scan_exit_codes_and_output(isolated, database):
    folder = isolated / "files"
    folder.mkdir()
    (folder / "clean.txt").write_text("nothing to see")
    run = run_cli(isolated, "--report-only", str(folder))
    assert run.returncode == 0 and "1 clean" in run.stdout, run.stdout + run.stderr
    (folder / "sample.bin").write_bytes(SAMPLE)
    run = run_cli(isolated, "--report-only", str(folder))
    assert run.returncode == 1 and f"{folder / 'sample.bin'}: FOUND Guardian.Test.Sample" in run.stdout, run.stdout + run.stderr
    run = run_cli(isolated, str(folder))
    assert run.returncode == 1 and "1 quarantined" in run.stdout and not (folder / "sample.bin").exists()
    assert run_cli(isolated, str(isolated / "missing")).returncode == 2


def test_unchanged_files_are_skipped_but_edits_are_caught(isolated, database):
    folder = isolated / "files"
    folder.mkdir()
    for index in range(50):
        (folder / f"f{index}.txt").write_text(f"file {index}")
    run_cli(isolated, "--report-only", str(folder))
    run = run_cli(isolated, "--report-only", str(folder))
    assert "50 unchanged since last scan" in run.stdout, run.stdout
    (folder / "f7.txt").write_bytes(SAMPLE)
    run = run_cli(isolated, "--report-only", str(folder))
    assert run.returncode == 1 and "f7.txt: FOUND" in run.stdout and "49 unchanged" in run.stdout, run.stdout


def test_engine_with_no_definitions_reports_errors_not_clean(isolated, tmp_path, monkeypatch):
    empty = tmp_path / "empty-definitions"
    empty.mkdir()
    (isolated / "file.txt").write_text("x")
    run = run_cli(isolated, "--report-only", str(isolated / "file.txt"), env={"GUARDIAN_CLAMAV_DB": str(empty)})
    assert run.returncode == 2 and "0 clean" in run.stdout and "1 error" in run.stdout, run.stdout
