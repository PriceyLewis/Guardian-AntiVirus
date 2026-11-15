"""Setup guidance for the ClamAV daemon, which keeps signatures loaded so scans start at once.

Installing and enabling a system service needs administrator rights, so
Guardian gives the exact commands rather than escalating privileges itself.
"""
from pathlib import Path


def family(os_release="/etc/os-release"):
    """'debian', 'fedora', 'arch' or None, from the distribution's ID and ID_LIKE."""
    try:
        lines = Path(os_release).read_text().splitlines()
    except OSError:
        return None
    values = {}
    for line in lines:
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("\"'").lower()
    names = [values.get("ID", ""), *values.get("ID_LIKE", "").split()]
    for name, group in (("debian", "debian"), ("ubuntu", "debian"), ("fedora", "fedora"), ("rhel", "fedora"),
                        ("centos", "fedora"), ("arch", "arch")):
        if name in names:
            return group
    return None


COMMANDS = {
    "debian": ("Debian, Ubuntu and Mint", [
        "sudo apt install clamav-daemon",
        "sudo systemctl enable --now clamav-daemon",
    ], "The daemon waits for virus definitions on first start; if it does not come up, run 'sudo systemctl restart clamav-freshclam' and try the second command again."),
    "fedora": ("Fedora and RHEL", [
        "sudo dnf install clamd clamav-update",
        "sudo freshclam",
        "sudo sed -i 's|^#LocalSocket /run/clamd.scan/clamd.sock|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf",
        "sudo systemctl enable --now clamd@scan",
    ], "The third command switches on the daemon's local socket in /etc/clamd.d/scan.conf, which is commented out by default."),
    "arch": ("Arch Linux", [
        "sudo pacman -S clamav",
        "sudo freshclam",
        "sudo systemctl enable --now clamav-daemon",
    ], ""),
}


def setup_steps(group):
    lines = [
        "The ClamAV daemon keeps virus definitions loaded in memory, so scans start",
        "immediately instead of loading them each time. It uses roughly a gigabyte of",
        "memory while running and needs administrator rights to install.",
        "",
    ]
    groups = [group] if group in COMMANDS else list(COMMANDS)
    if group not in COMMANDS:
        lines += ["Guardian could not tell which distribution this is. Use the commands for yours.", ""]
    for name in groups:
        title, commands, note = COMMANDS[name]
        lines += [f"Run these in a terminal ({title}):", "", *commands, ""]
        if note:
            lines += [note, ""]
    lines += ["Starting takes a minute or so the first time. Then return to Guardian's Overview page,",
              "which shows 'ClamAV daemon connected' once the daemon answers."]
    return "\n".join(lines)
