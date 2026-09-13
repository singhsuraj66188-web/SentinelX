from datetime import datetime
from pathlib import Path


LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_FILE = LOG_DIR / "sentinelx.log"


def initialize_logger():
    LOG_DIR.mkdir(exist_ok=True)


def log_event(event_type, message, severity="INFO"):
    initialize_logger()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = (
        f"{timestamp} | "
        f"{severity} | "
        f"{event_type} | "
        f"{message}\n"
    )

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(log_entry)


def get_log_file():
    return LOG_FILE