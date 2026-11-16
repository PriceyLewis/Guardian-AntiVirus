"""Find removable drives the desktop has mounted, so Guardian can offer to scan them."""
import getpass
import os

MOUNTS = "/proc/self/mounts"


def roots():
    """Folders where desktops mount USB sticks and memory cards for the current user."""
    try:
        user = getpass.getuser()
    except Exception:
        return ()
    return (f"/media/{user}/", f"/run/media/{user}/")


def removable_mounts(mounts=MOUNTS, under=None):
    """Mount points of removable drives currently attached."""
    under = roots() if under is None else under
    found = set()
    try:
        with open(mounts, encoding="utf-8", errors="surrogateescape") as file:
            for line in file:
                parts = line.split()
                if len(parts) < 2:
                    continue
                # The kernel writes spaces and other awkward characters as octal escapes.
                point = parts[1].encode("utf-8", "surrogateescape").decode("unicode_escape").encode("latin-1").decode("utf-8", "surrogateescape")
                if point.startswith(tuple(under)) and os.path.isdir(point):
                    found.add(point)
    except (OSError, ValueError):
        pass
    return found
