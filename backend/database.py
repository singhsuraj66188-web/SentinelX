import sqlite3
from pathlib import Path
from datetime import datetime


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"

DATABASE_FILE = DATA_DIR / "sentinelx.db"


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():
    """
    Create the SentinelX database and security_events table
    if they do not already exist.
    """

    DATA_DIR.mkdir(exist_ok=True)

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            event_type TEXT NOT NULL,

            severity TEXT NOT NULL,

            process TEXT,

            message TEXT NOT NULL,

            risk_score INTEGER DEFAULT 0

        )
    """)

    connection.commit()

    connection.close()


# ============================================================
# SAVE EVENT
# ============================================================

def save_event(
    event_type,
    message,
    severity="INFO",
    process=None,
    risk_score=0
):
    """
    Save a security event into the SQLite database.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO security_events
        (
            timestamp,
            event_type,
            severity,
            process,
            message,
            risk_score
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        event_type,
        severity,
        process,
        message,
        risk_score
    ))

    connection.commit()

    connection.close()


# ============================================================
# RECENT EVENTS
# ============================================================

def get_recent_events(limit=10):
    """
    Return the most recent security events.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            event_type,
            severity,
            process,
            message,
            risk_score
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    events = cursor.fetchall()

    connection.close()

    return events


# ============================================================
# SECURITY ALERTS
# ============================================================

def get_security_alerts(limit=10):
    """
    Return the most recent security alerts.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            severity,
            process,
            message,
            risk_score
        FROM security_events
        WHERE event_type = 'SECURITY_ALERT'
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    alerts = cursor.fetchall()

    connection.close()

    return alerts


# ============================================================
# CURRENT RISK SCORE
# ============================================================

def get_current_risk_score():
    """
    Return the most recently calculated monitoring-cycle
    risk score.

    This represents the current system state rather than
    the highest risk ever recorded.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT risk_score
        FROM security_events
        WHERE event_type = 'RISK_ASSESSMENT'
        ORDER BY id DESC
        LIMIT 1
    """)

    result = cursor.fetchone()

    connection.close()

    if result is None:
        return 0

    return result[0]


# ============================================================
# HIGHEST HISTORICAL RISK
# ============================================================

def get_highest_risk_score():
    """
    Return the highest risk score ever recorded.

    This is useful for historical statistics and should not
    be used as the current live risk indicator.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT MAX(risk_score)
        FROM security_events
    """)

    result = cursor.fetchone()

    connection.close()

    return (
        result[0]
        if result[0] is not None
        else 0
    )


# ============================================================
# EVENT COUNT
# ============================================================

def get_event_count():
    """
    Return the total number of stored events.
    """

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
    """)

    result = cursor.fetchone()

    connection.close()

    return result[0]


# ============================================================
# EVENT HISTORY SUMMARY
# ============================================================

def display_event_summary():
    """
    Display SentinelX event history summary.
    """

    total_events = get_event_count()

    current_risk = get_current_risk_score()

    highest_risk = get_highest_risk_score()

    alerts = get_security_alerts(5)

    print("\n========== EVENT HISTORY ==========")

    print(
        f"Total Events     : {total_events}"
    )

    print(
        f"Current Risk     : {current_risk}/100"
    )

    print(
        f"Highest Risk     : {highest_risk}/100"
    )

    print("\nRecent Security Alerts:")

    if not alerts:

        print(
            "No security alerts recorded."
        )

    else:

        for alert in alerts:

            (
                event_id,
                timestamp,
                severity,
                process,
                message,
                risk_score
            ) = alert

            print(
                f"[{severity}] "
                f"{timestamp} | "
                f"{process} | "
                f"{message} | "
                f"Risk: {risk_score}"
            )

    print(
        "=================================="
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print(
        "SentinelX Event History"
    )

    display_event_summary()

