"""Logging: human-readable console + file logs, and a JSON-lines audit trail."""
import json
import logging
import sys
import threading
import time

from .config import LOG_DIR

_lock = threading.Lock()
_FMT = "%(asctime)s | %(levelname)-7s | %(name)-18s | %(message)s"


class _Colour(logging.Formatter):
    COLOURS = {"WARNING": "\033[33m", "ERROR": "\033[31m", "CRITICAL": "\033[31;1m", "INFO": "\033[36m"}

    def format(self, record):
        out = super().format(record)
        c = self.COLOURS.get(record.levelname)
        return f"{c}{out}\033[0m" if c and sys.stderr.isatty() else out


def get_logger(name: str = "phishguard", logfile: str = "phishguard.log", level=logging.INFO):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger(name)
    if getattr(log, "_pg_ready", False):
        return log
    log.setLevel(level)
    log.propagate = False
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(_Colour(_FMT, "%H:%M:%S"))
    fh = logging.FileHandler(LOG_DIR / logfile, encoding="utf-8")
    fh.setFormatter(logging.Formatter(_FMT))
    log.addHandler(ch)
    log.addHandler(fh)
    log._pg_ready = True
    return log


def audit(event: dict, path=None):
    """Append one JSON object per line to the audit log (tamper-evident ordering by time)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
    with _lock, open(path or LOG_DIR / "audit.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
