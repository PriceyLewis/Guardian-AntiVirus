import json
from pathlib import Path

CONFIG = Path("config.json")


def load_config():

    defaults = {
        "realtime": True,
        "notifications": True,
        "archives": True,
        "startup": False,
    }

    if not CONFIG.exists():
        save_config(defaults)
        return defaults

    try:
        with open(CONFIG) as f:
            data = json.load(f)

        defaults.update(data)
        return defaults

    except Exception:
        return defaults


def save_config(config):

    with open(CONFIG, "w") as f:
        json.dump(config, f, indent=4)