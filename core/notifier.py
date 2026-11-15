import subprocess
from threading import Thread
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

    @staticmethod
    def notify_action(title, message, label, callback, timeout=120):
        """Notify with one button; callback runs on a background thread if it is pressed."""
        if not GuardianNotifier.notifications_enabled():
            return False

        def work():
            try:
                # With an action, notify-send waits and prints the name of the one chosen.
                result = subprocess.run(["notify-send", "--action=open=" + label, "--", title, message], check=False,
                                        timeout=timeout, capture_output=True, text=True)
            except (OSError, subprocess.TimeoutExpired):
                return
            if result.returncode != 0:
                # notify-send before 0.7.10 has no --action.
                GuardianNotifier.notify(title, message)
            elif result.stdout.strip() == "open":
                callback()

        Thread(target=work, name="guardian-notification", daemon=True).start()
        return True

