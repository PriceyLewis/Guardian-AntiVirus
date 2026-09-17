import subprocess
from config import load_config


class GuardianNotifier:
    @staticmethod
    def notifications_enabled():
        return load_config()["notifications"]

    @staticmethod
    def notify(title, message):
        if GuardianNotifier.notifications_enabled():
            try:
                subprocess.run(["notify-send", "--", title, message], check=False, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
