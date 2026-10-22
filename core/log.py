"""Rotating diagnostic log in the data directory (logs/guardian.log)."""
import logging
from logging.handlers import RotatingFileHandler
from core.paths import LOGS

log = logging.getLogger("guardian")
# Silent until setup_logging() runs, e.g. under tests.
log.addHandler(logging.NullHandler())
log.propagate = False


def setup_logging():
    if any(isinstance(handler, RotatingFileHandler) for handler in log.handlers):
        return
    LOGS.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(LOGS / "guardian.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(threadName)s] %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
