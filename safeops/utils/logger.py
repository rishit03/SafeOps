import os
from datetime import datetime


SAFEOPS_HOME = os.path.join(os.path.expanduser("~"), ".safeops")
LOG_PATH = os.path.join(SAFEOPS_HOME, "safeops.log")


def ensure_log_dir_exists():
    os.makedirs(SAFEOPS_HOME, exist_ok=True)


def log_message(level, message):
    ensure_log_dir_exists()

    timestamp = datetime.utcnow().isoformat()
    line = f"[{timestamp}] [{level.upper()}] {message}\n"

    with open(LOG_PATH, "a") as log_file:
        log_file.write(line)


def log_info(message):
    log_message("info", message)


def log_warning(message):
    log_message("warning", message)


def log_error(message):
    log_message("error", message)