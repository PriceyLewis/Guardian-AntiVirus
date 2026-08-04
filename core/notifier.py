import json
import subprocess
from pathlib import Path


CONFIG = Path("config.json")


class GuardianNotifier:

    @staticmethod
    def notifications_enabled():

        if not CONFIG.exists():
            return True

        try:
            with open(CONFIG) as f:
                settings = json.load(f)

            return settings.get("notifications", True)

        except Exception:
            return True

    @staticmethod
    def notify(title, message):

        if not GuardianNotifier.notifications_enabled():
            return

        subprocess.run(
            [
                "notify-send",
                title,
                message,
            ],
            check=False,
        )