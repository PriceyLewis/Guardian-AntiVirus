import subprocess
from config import load_config


class GuardianNotifier:
    @staticmethod
    def notifications_enabled():
        return load_config()["notifications"]

    @staticmethod
    def notify(title, message):
        if not GuardianNotifier.notifications_enabled():
            return False
        try:
            result = subprocess.run(["notify-send", "--", title, message], check=False, timeout=5,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False
