import json
import os
import tempfile
from core.paths import DATA

CONFIG = DATA / "config.json"
DEFAULTS = {
    "realtime": True, "notifications": True, "archives": True, "startup": False, "close_to_tray": True,
    "scheduled_scan": False, "weekly_home_scan": False,
    "scan_hour": -1, "quarantine_retention_days": 0, "theme": "system",
}
# Non-boolean settings accept only these values (-1 = any time, 0 = keep forever).
CHOICES = {
    "scan_hour": (-1, *range(24)),
    "quarantine_retention_days": (0, 30, 90),
    "theme": ("system", "dark", "light"),
}


def valid(key, value):
    if key not in DEFAULTS or type(value) is not type(DEFAULTS[key]):
        return False
    return key not in CHOICES or value in CHOICES[key]


def load_config():
    settings = DEFAULTS.copy()
    try:
        data = json.loads(CONFIG.read_text())
        if isinstance(data, dict):
            settings.update({k: v for k, v in data.items() if valid(k, v)})
    except (OSError, ValueError):
        pass
    return settings


def save_config(config):
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=CONFIG.parent, prefix=".config-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=4)
        os.replace(name, CONFIG)
    finally:
        if os.path.exists(name):
            os.unlink(name)
