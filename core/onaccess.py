"""Status and setup guidance for ClamAV on-access scanning (clamonacc).

Blocking files before they open needs root-owned clamd configuration and the
clamonacc service, so Guardian reports status and explains the steps rather
than escalating privileges itself.
"""
from pathlib import Path

# Debian/Ubuntu and Fedora/RHEL clamd configuration files.
CLAMD_CONFIGS = ("/etc/clamav/clamd.conf", "/etc/clamd.d/scan.conf")


def clamonacc_running(proc="/proc"):
    for entry in Path(proc).iterdir():
        if entry.name.isdigit():
            try:
                if (entry / "comm").read_text().strip() == "clamonacc":
                    return True
            except OSError:
                continue
    return False


def read_config(paths=CLAMD_CONFIGS):
    """Return (config path, {option: [values]}) for the first readable clamd config."""
    for path in paths:
        try:
            lines = Path(path).read_text().splitlines()
        except OSError:
            continue
        options = {}
        for line in lines:
            parts = line.split(None, 1)
            if len(parts) == 2 and not parts[0].startswith("#"):
                options.setdefault(parts[0], []).append(parts[1].strip())
        return path, options
    return None, {}


def status(proc="/proc", configs=CLAMD_CONFIGS):
    path, options = read_config(configs)
    return {
        "running": clamonacc_running(proc),
        "config": path,
        "prevention": options.get("OnAccessPrevention", ["no"])[-1].lower() in ("yes", "true", "1"),
        "paths": options.get("OnAccessIncludePath", []),
        "user": options.get("User", ["clamav"])[-1],
    }


def describe(state):
    """Return (text, needs_attention)."""
    if not state["running"]:
        return "Not active. Guardian detects threats after files are written; on-access blocking can stop them opening at all.", False
    paths = ", ".join(state["paths"]) or "no folders configured"
    if state["prevention"]:
        return f"Active and blocking infected files in: {paths}", False
    return f"Active in notify-only mode for: {paths}. Set OnAccessPrevention yes to block files.", True


def setup_steps(folders, state):
    config = state["config"] or "/etc/clamav/clamd.conf (Debian/Ubuntu) or /etc/clamd.d/scan.conf (Fedora)"
    fedora = "clamd.d" in config
    lines = [
        "On-access blocking uses ClamAV's clamonacc service and needs administrator rights.",
        "It stops any program from opening an infected file in these folders, system-wide.",
        "",
        f"1. Add these lines to {config}:",
        "",
        *[f"OnAccessIncludePath {folder}" for folder in folders],
        "OnAccessPrevention yes",
        f"OnAccessExcludeUname {state['user']}",
        "",
        "   The exclusion stops the ClamAV daemon blocking itself.",
        "",
        "2. Restart the daemon and enable on-access scanning:",
        "",
        "sudo systemctl restart " + ("clamd@scan" if fedora else "clamav-daemon"),
        "sudo systemctl enable --now clamav-clamonacc",
        "",
        "3. Return here and choose Check again.",
    ]
    return "\n".join(lines)
