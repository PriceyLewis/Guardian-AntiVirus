#!/bin/sh
# Install Guardian Antivirus for the current user, with ClamAV from your distribution.
#
#   curl -fsSL https://raw.githubusercontent.com/PriceyLewis/Guardian-AntiVirus/main/install.sh | sh
#
# Supports Debian, Ubuntu and Mint (apt), Fedora and RHEL (dnf), Arch (pacman)
# and openSUSE (zypper). It asks for your password once, to install ClamAV and
# start its update service and scanning daemon; Guardian itself is installed
# for your user only, with pipx. Running it again updates Guardian to the
# newest release.
#
#   sh install.sh --uninstall   removes Guardian (ClamAV and your data are kept)
#   sh install.sh --no-system   skips the system packages (ClamAV already set up)
set -eu

REPOSITORY="https://github.com/PriceyLewis/Guardian-AntiVirus"
LATEST_API="https://api.github.com/repos/PriceyLewis/Guardian-AntiVirus/releases/latest"
SYSTEM=1
ACTION=install

for argument in "$@"; do
    case "$argument" in
        --uninstall) ACTION=uninstall ;;
        --no-system) SYSTEM=0 ;;
        -h|--help) echo "usage: install.sh [--no-system | --uninstall]"; exit 0 ;;
        *) echo "Unknown option: $argument" >&2; exit 2 ;;
    esac
done

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -eq 0 ] && [ "${GUARDIAN_ALLOW_ROOT:-0}" != 1 ]; then
    echo "Run this as your normal user, not with sudo: Guardian is installed for you, and it asks for your password when it needs it." >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif have sudo; then
    SUDO="sudo"
else
    SUDO=""
fi

# pipx puts the guardian command here.
BIN="${PIPX_BIN_DIR:-$HOME/.local/bin}"

if [ "$ACTION" = uninstall ]; then
    say "Removing Guardian"
    if [ -x "$BIN/guardian" ]; then "$BIN/guardian" --remove-menu-entry || true; fi
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/guardian.desktop"
    if have pipx; then pipx uninstall guardian-antivirus || true; fi
    echo "Guardian is removed. ClamAV, your scan history and quarantine (in ${XDG_DATA_HOME:-$HOME/.local/share}/guardian) were kept."
    exit 0
fi

if [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ] && [ "$SYSTEM" = 1 ]; then
    warn "sudo is not available, so ClamAV cannot be installed. Install ClamAV and pipx yourself, then run: sh install.sh --no-system"
    exit 1
fi

if have systemctl && [ -d /run/systemd/system ]; then
    SYSTEMD=1
else
    SYSTEMD=0
fi

service() {
    # Enable and start a system service when systemd runs them; otherwise say what to do.
    # $1 is the service, $2 what it gives the user.
    if [ "$SYSTEMD" = 1 ]; then
        $SUDO systemctl enable --now "$1" || warn "Could not start $1. Guardian still works, without $2."
    else
        warn "No systemd here: start $1 yourself for $2."
    fi
}

if [ "$SYSTEM" = 1 ]; then
    say "Installing ClamAV and Guardian's system requirements"
    if have apt-get; then
        $SUDO apt-get update
        $SUDO apt-get install -y clamav clamav-daemon clamav-freshclam pipx libnotify-bin libxcb-cursor0 libegl1
        FRESHCLAM=clamav-freshclam DAEMON=clamav-daemon
    elif have dnf; then
        $SUDO dnf install -y clamav clamd clamav-update pipx libnotify xcb-util-cursor
        # Fedora ships the daemon's socket switched off.
        $SUDO sed -i 's|^#LocalSocket /run/clamd.scan/clamd.sock|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf
        $SUDO sed -i 's|^Example|#Example|' /etc/freshclam.conf
        FRESHCLAM=clamav-freshclam DAEMON=clamd@scan
    elif have pacman; then
        $SUDO pacman -Sy --needed --noconfirm clamav python-pipx libnotify xcb-util-cursor
        FRESHCLAM=clamav-freshclam DAEMON=clamav-daemon
    elif have zypper; then
        $SUDO zypper --non-interactive install clamav python3-pipx libnotify-tools libxcb-cursor0
        FRESHCLAM=freshclam.timer DAEMON=clamd
    else
        warn "No supported package manager found. Install ClamAV and pipx, then run: sh install.sh --no-system"
        exit 1
    fi

    say "Downloading virus definitions (this can take a few minutes)"
    # The daemon will not start until definitions exist.
    if ls /var/lib/clamav/*.c[lv]d >/dev/null 2>&1; then
        echo "Definitions are already present."
    else
        $SUDO freshclam || warn "freshclam could not download definitions now; the update service will retry."
    fi
    service "$FRESHCLAM" "automatic definition updates"
    service "$DAEMON" "faster scans"
fi

latest_tag() {
    # The newest published release, e.g. v1.2.0; empty when there is none or GitHub cannot be reached.
    if have curl; then
        curl -fsSL "$LATEST_API" 2>/dev/null
    elif have wget; then
        wget -qO- "$LATEST_API" 2>/dev/null
    fi | sed -n 's/.*"tag_name": *"\(v[0-9][0-9.]*\)".*/\1/p' | head -n 1
}

if [ -n "${GUARDIAN_SOURCE:-}" ]; then
    SOURCE="$GUARDIAN_SOURCE"
else
    TAG="$(latest_tag || true)"
    if [ -n "$TAG" ]; then
        SOURCE="$REPOSITORY/archive/refs/tags/$TAG.tar.gz"
    else
        SOURCE="$REPOSITORY/archive/refs/heads/main.tar.gz"
    fi
fi

if ! have pipx; then
    warn "pipx is not installed. Install it with your package manager, then run this again."
    exit 1
fi

say "Installing Guardian ${TAG:-from the latest source}"
# YARA-X is optional; fall back to Guardian without it on systems it does not support.
if ! pipx install --force "guardian-antivirus[yara] @ $SOURCE"; then
    warn "Installing with YARA-X failed; installing Guardian without it."
    pipx install --force "guardian-antivirus @ $SOURCE"
fi
pipx ensurepath >/dev/null 2>&1 || true

say "Adding Guardian to your application menu"
"$BIN/guardian" --install-menu-entry

say "Downloading threat lists for the second-opinion engines"
"$BIN/guardian" --update-threat-lists || warn "Some threat lists could not be downloaded now; Guardian retries daily."

say "Guardian is installed"
echo "Open it from your application menu, or run: guardian"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "Open a new terminal first so the guardian command is found." ;;
esac
echo "To update later, run this installer again; Guardian also tells you on its Overview page when a new version is out."
echo "To remove it later: sh install.sh --uninstall"
