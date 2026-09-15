import sqlite3
import os
import json
from pathlib import Path
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"

DATABASE_FILE = DATA_DIR / "sentinelx.db"


# ============================================================
# SUPABASE CONFIGURATION
# ============================================================

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

USE_SUPABASE = bool(
    SUPABASE_URL and SUPABASE_SECRET_KEY
)


# ============================================================
# SUPABASE HELPER
# ============================================================

def supabase_request(
    method="GET",
    endpoint="",
    data=None,
    query=None,
    return_headers=False
):
    """
    Send a request to the Supabase REST API.

    This uses the server-side Supabase secret key.
    The key is read only from the environment and is
    never stored in the source code.

    return_headers=True can be used when an API response
    header such as Content-Range is required.
    """

    if not USE_SUPABASE:
        return None

    url = (
        SUPABASE_URL.rstrip("/")
        + "/rest/v1/"
        + endpoint
    )

    if query:
        url += "?" + urlencode(query)

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    if method == "POST":
        headers["Prefer"] = "return=minimal"

    request_data = None

    if data is not None:

        request_data = json.dumps(
            data
        ).encode("utf-8")

    request = Request(
        url,
        data=request_data,
        headers=headers,
        method=method
    )

    try:

        with urlopen(
            request,
            timeout=10
        ) as response:

            response_body = response.read()

            if return_headers:

                return (
                    response_body,
                    response.headers
                )

            if not response_body:

                return []

            return json.loads(
                response_body.decode("utf-8")
            )

    except HTTPError as error:

        print(
            f"Supabase HTTP error: "
            f"{error.code} {error.reason}"
        )

        return None

    except URLError as error:

        print(
            f"Supabase connection error: "
            f"{error.reason}"
        )

        return None

    except Exception as error:

        print(
            f"Supabase error: {error}"
        )

        return None


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():
    """
    Initialize SentinelX database.

    Local mode:
        Creates SQLite database.

    Cloud mode:
        Uses the existing Supabase security_events table.
    """

    if USE_SUPABASE:

        print(
            "Database mode: Supabase Cloud"
        )

        return

    DATA_DIR.mkdir(
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_FILE
    )

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
    risk_score=0,
    timestamp=None
):
    """
    Save a security event.

    Uses Supabase when cloud environment variables exist.
    Otherwise uses local SQLite.

    The timestamp can be supplied by a remote ingestion
    request. If no timestamp is supplied, the current
    local timestamp is generated automatically.

    IMPORTANT:
    The original risk score is preserved in storage.

    This is important for:
        RISK_ASSESSMENT
        current risk
        highest historical risk
        security alerts

    INFO events are normalized to risk 0 only when
    displayed in the event history.
    """

    if timestamp is None:

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    try:

        risk_score = int(
            risk_score
        )

    except (
        TypeError,
        ValueError
    ):

        risk_score = 0

    if risk_score < 0:

        risk_score = 0

    if risk_score > 100:

        risk_score = 100

    event_data = {

        "timestamp":
            str(timestamp),

        "event_type":
            str(event_type),

        "severity":
            str(severity),

        "process":
            process,

        "message":
            str(message),

        "risk_score":
            risk_score

    }

    # --------------------------------------------------------
    # CLOUD MODE
    # --------------------------------------------------------

    if USE_SUPABASE:

        result = supabase_request(
            method="POST",
            endpoint="security_events",
            data=event_data
        )

        if result is not None:

            return True

        return False

    # --------------------------------------------------------
    # LOCAL SQLITE MODE
    # --------------------------------------------------------

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

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

    return True


# ============================================================
# NORMALIZE DISPLAY RISK
# ============================================================

def normalize_event_risk(
    severity,
    risk_score
):
    """
    Determine the risk value that should be displayed
    for an event in Event History.

    INFO events are informational records and therefore
    display risk 0.

    Security alerts and non-INFO events preserve their
    actual stored risk score.

    This does NOT modify the database.
    """

    severity_text = str(
        severity or ""
    ).upper()

    try:

        risk = int(
            risk_score
        )

    except (
        TypeError,
        ValueError
    ):

        risk = 0

    if severity_text == "INFO":

        return 0

    return risk


# ============================================================
# RECENT EVENTS
# ============================================================

def get_recent_events(limit=10):
    """
    Return the most recent security events.

    INFO events are displayed with risk 0.

    The underlying stored risk value is not modified.
    This allows RISK_ASSESSMENT events to continue
    powering the current-risk calculation.
    """

    # --------------------------------------------------------
    # CLOUD MODE
    # --------------------------------------------------------

    if USE_SUPABASE:

        result = supabase_request(

            method="GET",

            endpoint="security_events",

            query={

                "select": (
                    "id,timestamp,event_type,severity,"
                    "process,message,risk_score"
                ),

                "order":
                    "id.desc",

                "limit":
                    limit

            }

        )

        if result is None:

            return []

        events = []

        for event in result:

            severity = event.get(
                "severity",
                "INFO"
            )

            stored_risk = event.get(
                "risk_score",
                0
            )

            display_risk = normalize_event_risk(
                severity,
                stored_risk
            )

            events.append((

                event["id"],

                event["timestamp"],

                event["event_type"],

                severity,

                event.get(
                    "process"
                ),

                event["message"],

                display_risk

            ))

        return events

    # --------------------------------------------------------
    # LOCAL SQLITE MODE
    # --------------------------------------------------------

    connection = sqlite3.connect(
        DATABASE_FILE
    )

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
    """, (
        limit,
    ))

    database_events = cursor.fetchall()

    connection.close()

    events = []

    for event in database_events:

        (
            event_id,
            timestamp,
            event_type,
            severity,
            process,
            message,
            stored_risk
        ) = event

        display_risk = normalize_event_risk(
            severity,
            stored_risk
        )

        events.append((

            event_id,
            timestamp,
            event_type,
            severity,
            process,
            message,
            display_risk

        ))

    return events


# ============================================================
# SECURITY ALERTS
# ============================================================

def get_security_alerts(limit=10):
    """
    Return the most recent security alerts.

    Security alerts retain their actual risk score.
    """

    # --------------------------------------------------------
    # CLOUD MODE
    # --------------------------------------------------------

    if USE_SUPABASE:

        result = supabase_request(

            method="GET",

            endpoint="security_events",

            query={

                "select": (
                    "id,timestamp,severity,"
                    "process,message,risk_score"
                ),

                "event_type":
                    "eq.SECURITY_ALERT",

                "order":
                    "id.desc",

                "limit":
                    limit

            }

        )

        if result is None:

            return []

        return [

            (

                alert["id"],

                alert["timestamp"],

                alert["severity"],

                alert.get(
                    "process"
                ),

                alert["message"],

                alert.get(
                    "risk_score",
                    0
                )

            )

            for alert in result

        ]

    # --------------------------------------------------------
    # LOCAL SQLITE MODE
    # --------------------------------------------------------

    connection = sqlite3.connect(
        DATABASE_FILE
    )

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
    """, (
        limit,
    ))

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

    RISK_ASSESSMENT events intentionally retain their
    actual risk value in storage.
    """

    # --------------------------------------------------------
    # CLOUD MODE
    # --------------------------------------------------------

    if USE_SUPABASE:

        result = supabase_request(

            method="GET",

            endpoint="security_events",

            query={

                "select":
                    "risk_score",

                "event_type":
                    "eq.RISK_ASSESSMENT",

                "order":
                    "id.desc",

                "limit":
                    1

            }

        )

        if not result:

            return 0

        try:

            return int(
                result[0].get(
                    "risk_score",
                    0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            return 0

    # --------------------------------------------------------
    # LOCAL SQLITE MODE
    # --------------------------------------------------------

    connection = sqlite3.connect(
        DATABASE_FILE
    )

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

    try:

        return int(
            result[0]
        )

    except (
        TypeError,
        ValueError
    ):

        return 0


# ============================================================
# HIGHEST HISTORICAL RISK
# ============================================================

def get_highest_risk_score():
    """
    Return the highest risk score ever recorded.
    """

    # --------------------------------------------------------
    # CLOUD MODE
    # --------------------------------------------------------

    if USE_SUPABASE:

        result = supabase_request(

            method="GET",

            endpoint="security_events",

            query={

                "select":
                    "risk_score",

                "order":
                    "risk_score.desc",

                "limit":
                    1

            }

        )

        if not result:

            return 0

        try:

            return int(
                result[0].get(
                    "risk_score",
                    0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            return 0

    # --------------------------------------------------------
    # LOCAL SQLITE MODE
    # --------------------------------------------------------

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT MAX(risk_score)
        FROM security_events
    """)

    result = cursor.fetchone()

    connection.close()

    if result is None:

        return 0

    try:

        return int(
            result[0]
        )

    except (
        TypeError,
        ValueError
    ):

        return 0


# ============================================================
# EVENT COUNT
# ============================================================

def get_event_count():
    """
    Return the total number of stored events.

    CLOUD MODE:
        Uses Supabase's exact Content-Range count so
        the result is not capped at 1,000 rows.

    LOCAL MODE:
        Uses SQLite COUNT(*).
    """

    # --------------------------------------------------------
    # CLOUD MODE
    # --------------------------------------------------------

    if USE_SUPABASE:

        try:

            url = (
                SUPABASE_URL.rstrip("/")
                + "/rest/v1/security_events"
            )

            url += "?" + urlencode({

                "select":
                    "id",

                "limit":
                    "1"

            })

            headers = {

                "apikey":
                    SUPABASE_SECRET_KEY,

                "Authorization":
                    f"Bearer {SUPABASE_SECRET_KEY}",

                "Prefer":
                    "count=exact"

            }

            request = Request(

                url,

                headers=headers,

                method="HEAD"

            )

            with urlopen(
                request,
                timeout=10
            ) as response:

                content_range = response.headers.get(
                    "Content-Range"
                )

            if content_range:

                # Expected format:
                #
                # 0-0/1087
                #
                # or:
                #
                # */1087

                if "/" in content_range:

                    total = (
                        content_range
                        .split("/")[-1]
                    )

                    if total != "*":

                        return int(
                            total
                        )

            # ------------------------------------------------
            # FALLBACK
            # ------------------------------------------------

            result = supabase_request(

                method="GET",

                endpoint="security_events",

                query={

                    "select":
                        "id",

                    "limit":
                        1

                }

            )

            if result is None:

                return 0

            # If exact count cannot be obtained,
            # return 1 rather than falsely reporting 1000.

            return len(
                result
            )

        except Exception as error:

            print(
                "Supabase event count error:",
                error
            )

            return 0

    # --------------------------------------------------------
    # LOCAL SQLITE MODE
    # --------------------------------------------------------

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
    """)

    result = cursor.fetchone()

    connection.close()

    if result is None:

        return 0

    return int(
        result[0]
    )


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

    print(
        "\n========== EVENT HISTORY =========="
    )

    print(
        f"Total Events     : {total_events}"
    )

    print(
        f"Current Risk     : {current_risk}/100"
    )

    print(
        f"Highest Risk     : {highest_risk}/100"
    )

    print(
        "\nRecent Security Alerts:"
    )

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

    if USE_SUPABASE:

        print(
            "Database: Supabase Cloud"
        )

    else:

        print(
            "Database: Local SQLite"
        )

    display_event_summary()