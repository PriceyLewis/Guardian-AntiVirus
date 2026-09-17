"""Apply persisted preferences with rollback of runtime and autostart changes."""
from config import load_config, save_config, DEFAULTS
from core.startup import set_startup, startup_path


def apply_preferences(settings, runtime_apply=None):
    if set(settings) != set(DEFAULTS) or any(type(v) is not bool for v in settings.values()):
        raise ValueError("Invalid settings")
    previous = load_config()
    entry = startup_path()
    startup_changed = settings["startup"] != previous["startup"]
    previous_entry = entry.read_bytes() if startup_changed and entry.exists() else None
    runtime_attempted = False
    try:
        if startup_changed:
            set_startup(settings["startup"])
        if runtime_apply and settings["realtime"] != previous["realtime"]:
            runtime_attempted = True
            runtime_apply(settings)
        save_config(settings)
    except Exception as exc:
        failures = []
        if startup_changed:
            try:
                if previous_entry is None:
                    entry.unlink(missing_ok=True)
                else:
                    entry.write_bytes(previous_entry)
            except OSError as rollback:
                failures.append(str(rollback))
        if runtime_attempted:
            try:
                runtime_apply(previous)
            except Exception as rollback:
                failures.append(str(rollback))
        suffix = " Rollback needs attention: " + "; ".join(failures) if failures else " Previous settings retained."
        raise RuntimeError(str(exc) + suffix) from exc
    return settings
