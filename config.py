import json
import os
import tempfile
from core.paths import DATA

CONFIG = DATA / "config.json"
DEFAULTS = {"realtime": True, "notifications": True, "archives": True, "startup": False, "close_to_tray": True}


def load_config():
    settings = DEFAULTS.copy()
    try:
        data = json.loads(CONFIG.read_text())
        if isinstance(data, dict):
            settings.update({k: v for k, v in data.items() if k in settings and type(v) is bool})
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
