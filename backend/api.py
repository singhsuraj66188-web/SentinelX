from flask import Flask, jsonify, request, Response
from flask_cors import CORS

import os
import platform
import socket
import getpass
import psutil
import json
import urllib.request
import urllib.error

from datetime import datetime

from database import (
    initialize_database,
    save_event,
    get_recent_events,
    get_security_alerts,
    get_current_risk_score,
    get_highest_risk_score,
    get_event_count
)


# ============================================================
# SENTINELX API
# Cybersecurity Monitoring System
# ============================================================

app = Flask(__name__)

CORS(app)


# ============================================================
# DATABASE
# ============================================================

initialize_database()


# ============================================================
# SUPABASE CONFIGURATION
# ============================================================

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

SNAPSHOT_TABLE = "monitoring_snapshots"


# ============================================================
# SUPABASE REQUEST HELPER
# ============================================================

def supabase_request(
    method="GET",
    endpoint="",
    data=None,
    params=""
):

    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise Exception(
            "Supabase environment variables are not configured"
        )

    url = (
        SUPABASE_URL.rstrip("/")
        + "/rest/v1/"
        + endpoint
    )

    if params:
        url += "?" + params

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": "Bearer " + SUPABASE_SECRET_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    if method == "POST":

        headers["Prefer"] = "return=representation"

    request_data = None

    if data is not None:

        request_data = json.dumps(
            data
        ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=request_data,
        headers=headers,
        method=method
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=15
        ) as response:

            body = response.read().decode(
                "utf-8"
            )

            if not body:

                return []

            return json.loads(body)

    except urllib.error.HTTPError as error:

        error_body = error.read().decode(
            "utf-8",
            errors="replace"
        )

        raise Exception(
            f"Supabase HTTP {error.code}: "
            f"{error_body}"
        )

    except urllib.error.URLError as error:

        raise Exception(
            f"Supabase connection error: {error}"
        )


# ============================================================
# SAVE WINDOWS MONITORING SNAPSHOT
# ============================================================

def save_monitoring_snapshot(snapshot):

    system = snapshot.get(
        "system",
        {}
    )

    processes = snapshot.get(
        "processes",
        []
    )

    network = snapshot.get(
        "network",
        ""
    )

    risk_score = snapshot.get(
        "risk_score",
        0
    )

    timestamp = snapshot.get(
        "timestamp"
    )

    if not timestamp:

        timestamp = datetime.now().isoformat()

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


    snapshot_data = {

        "timestamp": str(
            timestamp
        ),

        "hostname": str(
            system.get(
                "hostname",
                "Unknown"
            )
        ),

        "operating_system": str(
            system.get(
                "operating_system",
                "Unknown"
            )
        ),

        "os_version": str(
            system.get(
                "os_version",
                "Unknown"
            )
        ),

        "username": str(
            system.get(
                "username",
                "Unknown"
            )
        ),

        "risk_score": risk_score,

        "processes": processes
            if isinstance(
                processes,
                list
            )
            else [],

        "network": network
            if isinstance(
                network,
                (str, list)
            )
            else []

    }


    result = supabase_request(
        method="POST",
        endpoint=SNAPSHOT_TABLE,
        data=snapshot_data
    )

    return result


# ============================================================
# GET LATEST WINDOWS SNAPSHOT
# ============================================================

def get_latest_snapshot():

    try:

        result = supabase_request(

            method="GET",

            endpoint=SNAPSHOT_TABLE,

            params=(
                "select=*"
                "&order=id.desc"
                "&limit=1"
            )
        )

        if not result:

            return None

        return result[0]

    except Exception as error:

        print(
            "Snapshot retrieval error:",
            error
        )

        return None


# ============================================================
# PARSE WINDOWS NETSTAT DATA
# ============================================================

def parse_network_data(network_data):

    connections = []


    # --------------------------------------------------------
    # Already parsed JSON/list
    # --------------------------------------------------------

    if isinstance(
        network_data,
        list
    ):

        for item in network_data:

            if not isinstance(
                item,
                dict
            ):

                continue

            connections.append({

                "protocol": item.get(
                    "protocol",
                    "UNKNOWN"
                ),

                "local_address": item.get(
                    "local_address",
                    "-"
                ),

                "foreign_address": item.get(
                    "foreign_address",
                    "-"
                ),

                "state": item.get(
                    "state",
                    "-"
                ),

                "pid": item.get(
                    "pid",
                    "-"
                )

            })

        return connections


    # --------------------------------------------------------
    # Raw Windows netstat string
    # --------------------------------------------------------

    if not isinstance(
        network_data,
        str
    ):

        return connections


    lines = network_data.splitlines()


    for line in lines:

        line = line.strip()

        if not line:

            continue


        # Skip netstat headings

        if line.lower().startswith(
            "active connections"
        ):

            continue

        if line.lower().startswith(
            "proto"
        ):

            continue


        parts = line.split()


        if len(parts) < 4:

            continue


        protocol = parts[0].upper()


        if protocol not in (
            "TCP",
            "UDP"
        ):

            continue


        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if protocol == "TCP":

            if len(parts) < 5:

                continue

            local_address = parts[1]

            foreign_address = parts[2]

            state = parts[3]

            pid = parts[4]


        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        else:

            local_address = parts[1]

            foreign_address = parts[2]

            state = "-"

            pid = parts[3]


        connections.append({

            "protocol": protocol,

            "local_address":
                local_address,

            "foreign_address":
                foreign_address,

            "state": state,

            "pid": pid

        })


    return connections


# ============================================================
# NORMALIZE PROCESS DATA
# ============================================================

def normalize_processes(processes):

    if not isinstance(
        processes,
        list
    ):

        return []


    normalized = []


    for process in processes:

        if not isinstance(
            process,
            dict
        ):

            continue


        normalized.append({

            "pid": process.get(
                "pid",
                "-"
            ),

            "name": process.get(
                "name",
                "-"
            ),

            "status": process.get(
                "status",
                "unknown"
            ),

            "username": process.get(
                "username",
                "-"
            ),

            "memory": process.get(
                "memory",
                process.get(
                    "memory_info",
                    0
                )
            )

        })


    return normalized


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({

        "name": "SentinelX",

        "description":
            "Cybersecurity Monitoring System",

        "status": "online"

    })


# ============================================================
# SYSTEM STATUS
# ============================================================

@app.route("/api/status")
def status():

    try:

        total_events = get_event_count()

    except Exception as error:

        print(
            "Status error:",
            error
        )

        total_events = 0


    return jsonify({

        "status": "online",

        "total_events":
            total_events

    })


# ============================================================
# SYSTEM INFORMATION
# ============================================================

@app.route("/api/system")
def system_info():

    snapshot = get_latest_snapshot()


    # --------------------------------------------------------
    # WINDOWS SNAPSHOT AVAILABLE
    # --------------------------------------------------------

    if snapshot:

        return jsonify({

            "hostname":
                snapshot.get(
                    "hostname",
                    "Unknown"
                ),

            "operating_system":
                snapshot.get(
                    "operating_system",
                    "Unknown"
                ),

            "os_version":
                snapshot.get(
                    "os_version",
                    "Unknown"
                ),

            "username":
                snapshot.get(
                    "username",
                    "Unknown"
                )

        })


    # --------------------------------------------------------
    # FALLBACK TO RENDER SERVER
    # --------------------------------------------------------

    try:

        return jsonify({

            "hostname":
                socket.gethostname(),

            "operating_system":
                platform.system(),

            "os_version":
                platform.version(),

            "username":
                getpass.getuser(),

            "source":
                "server_fallback"

        })

    except Exception as error:

        print(
            "System information error:",
            error
        )

        return jsonify({

            "hostname": "Unavailable",

            "operating_system":
                "Unavailable",

            "os_version":
                "Unavailable",

            "username":
                "Unavailable"

        }), 500


# ============================================================
# EVENT HISTORY
# ============================================================

@app.route("/api/events")
def events():

    try:

        data = get_recent_events()

        return jsonify(data)

    except Exception as error:

        print(
            "Events error:",
            error
        )

        return jsonify([])


# ============================================================
# SECURITY ALERTS
# ============================================================

@app.route("/api/alerts")
def alerts():

    try:

        data = get_security_alerts()

        return jsonify(data)

    except Exception as error:

        print(
            "Alerts error:",
            error
        )

        return jsonify([])


# ============================================================
# RISK SCORE
# ============================================================

@app.route("/api/risk")
def risk():

    try:

        current_risk = (
            get_current_risk_score()
        )

        highest_risk = (
            get_highest_risk_score()
        )


        return jsonify({

            "current_risk":
                current_risk,

            "highest_risk":
                highest_risk

        })

    except Exception as error:

        print(
            "Risk error:",
            error
        )

        return jsonify({

            "current_risk": 0,

            "highest_risk": 0

        })


# ============================================================
# RUNNING PROCESSES
# ============================================================

@app.route("/api/processes")
def processes():

    snapshot = get_latest_snapshot()


    # --------------------------------------------------------
    # WINDOWS PROCESS SNAPSHOT
    # --------------------------------------------------------

    if snapshot:

        process_list = normalize_processes(

            snapshot.get(
                "processes",
                []
            )

        )

        return jsonify(
            process_list
        )


    # --------------------------------------------------------
    # FALLBACK
    # --------------------------------------------------------

    process_list = []


    try:

        for process in psutil.process_iter(

            [
                "pid",
                "name",
                "status",
                "username",
                "memory_info"
            ]

        ):

            try:

                info = process.info

                memory = 0


                if info.get(
                    "memory_info"
                ):

                    memory = (
                        info[
                            "memory_info"
                        ].rss
                    )


                process_list.append({

                    "pid":
                        info.get(
                            "pid"
                        ),

                    "name":
                        info.get(
                            "name"
                        ) or "-",

                    "status":
                        info.get(
                            "status"
                        ) or "unknown",

                    "username":
                        info.get(
                            "username"
                        ) or "-",

                    "memory":
                        memory

                })


            except (

                psutil.NoSuchProcess,

                psutil.AccessDenied,

                psutil.ZombieProcess

            ):

                continue


        return jsonify(
            process_list
        )


    except Exception as error:

        print(
            "Process monitoring error:",
            error
        )

        return jsonify([])


# ============================================================
# NETWORK CONNECTIONS
# ============================================================

@app.route("/api/network")
def network():

    snapshot = get_latest_snapshot()


    # --------------------------------------------------------
    # WINDOWS NETWORK SNAPSHOT
    # --------------------------------------------------------

    if snapshot:

        network_data = snapshot.get(
            "network",
            []
        )


        connections = (
            parse_network_data(
                network_data
            )
        )


        return jsonify(
            connections
        )


    # --------------------------------------------------------
    # FALLBACK
    # --------------------------------------------------------

    connections = []


    try:

        network_connections = (
            psutil.net_connections(
                kind="inet"
            )
        )


        for connection in network_connections:

            try:

                # --------------------------------------------
                # PROTOCOL
                # --------------------------------------------

                if (
                    connection.type
                    == socket.SOCK_STREAM
                ):

                    protocol = "TCP"

                elif (
                    connection.type
                    == socket.SOCK_DGRAM
                ):

                    protocol = "UDP"

                else:

                    protocol = "UNKNOWN"


                # --------------------------------------------
                # LOCAL ADDRESS
                # --------------------------------------------

                if connection.laddr:

                    local_address = (

                        f"{connection.laddr.ip}:"

                        f"{connection.laddr.port}"

                    )

                else:

                    local_address = "-"


                # --------------------------------------------
                # FOREIGN ADDRESS
                # --------------------------------------------

                if connection.raddr:

                    foreign_address = (

                        f"{connection.raddr.ip}:"

                        f"{connection.raddr.port}"

                    )

                else:

                    foreign_address = "-"


                # --------------------------------------------
                # STATE
                # --------------------------------------------

                state = (
                    connection.status
                    or "-"
                )


                # --------------------------------------------
                # PID
                # --------------------------------------------

                pid = connection.pid

                if pid is None:

                    pid = "-"


                connections.append({

                    "protocol":
                        protocol,

                    "local_address":
                        local_address,

                    "foreign_address":
                        foreign_address,

                    "state":
                        state,

                    "pid":
                        pid

                })


            except Exception as error:

                print(
                    "Network record error:",
                    error
                )

                continue


        return jsonify(
            connections
        )


    except Exception as error:

        print(
            "Network monitoring error:",
            error
        )

        return jsonify([])


# ============================================================
# SECURE EVENT INGESTION
# ============================================================

@app.route(
    "/api/ingest",
    methods=["POST"]
)
def ingest_event():

    ingest_key = os.environ.get(
        "INGEST_API_KEY"
    )


    if not ingest_key:

        return jsonify({

            "status": "error",

            "message":
                "Ingestion authentication "
                "is not configured"

        }), 503


    supplied_key = request.headers.get(
        "X-SentinelX-Key"
    )


    if (
        not supplied_key
        or supplied_key != ingest_key
    ):

        return jsonify({

            "status": "error",

            "message":
                "Unauthorized"

        }), 401


    data = request.get_json(
        silent=True
    )


    if not data:

        return jsonify({

            "status": "error",

            "message":
                "JSON body is required"

        }), 400


    required_fields = [

        "timestamp",

        "event_type",

        "severity",

        "message",

        "risk_score"

    ]


    missing_fields = [

        field

        for field in required_fields

        if field not in data

    ]


    if missing_fields:

        return jsonify({

            "status": "error",

            "message":
                "Missing required fields",

            "fields":
                missing_fields

        }), 400


    try:

        risk_score = int(
            data["risk_score"]
        )

    except (
        TypeError,
        ValueError
    ):

        return jsonify({

            "status": "error",

            "message":
                "risk_score must be an integer"

        }), 400


    if (
        risk_score < 0
        or risk_score > 100
    ):

        return jsonify({

            "status": "error",

            "message":
                "risk_score must be between 0 and 100"

        }), 400


    save_event(

        timestamp=str(
            data["timestamp"]
        ),

        event_type=str(
            data["event_type"]
        ),

        severity=str(
            data["severity"]
        ),

        process=str(
            data.get(
                "process",
                ""
            )
        ),

        message=str(
            data["message"]
        ),

        risk_score=risk_score

    )


    return jsonify({

        "status": "success",

        "message":
            "Event stored successfully"

    }), 201


# ============================================================
# WINDOWS MONITORING SNAPSHOT INGESTION
# ============================================================

@app.route(
    "/api/snapshot",
    methods=["POST"]
)
def ingest_snapshot():

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    ingest_key = os.environ.get(
        "INGEST_API_KEY"
    )


    if not ingest_key:

        return jsonify({

            "status": "error",

            "message":
                "Snapshot authentication "
                "is not configured"

        }), 503


    supplied_key = request.headers.get(
        "X-SentinelX-Key"
    )


    if (
        not supplied_key
        or supplied_key != ingest_key
    ):

        return jsonify({

            "status": "error",

            "message":
                "Unauthorized"

        }), 401


    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )


    if not data:

        return jsonify({

            "status": "error",

            "message":
                "JSON body is required"

        }), 400


    # --------------------------------------------------------
    # BASIC VALIDATION
    # --------------------------------------------------------

    if "system" not in data:

        return jsonify({

            "status": "error",

            "message":
                "system field is required"

        }), 400


    if not isinstance(
        data["system"],
        dict
    ):

        return jsonify({

            "status": "error",

            "message":
                "system must be an object"

        }), 400


    try:

        result = save_monitoring_snapshot(
            data
        )


        return jsonify({

            "status": "success",

            "message":
                "Windows monitoring snapshot stored",

            "snapshot_count":
                len(result)

        }), 201


    except Exception as error:

        print(
            "Snapshot storage error:",
            error
        )


        return jsonify({

            "status": "error",

            "message":
                "Unable to store monitoring snapshot",

            "details":
                str(error)

        }), 500


# ============================================================
# LATEST SNAPSHOT
# ============================================================

@app.route("/api/snapshot")
def latest_snapshot():

    snapshot = get_latest_snapshot()


    if not snapshot:

        return jsonify({

            "status": "empty",

            "message":
                "No Windows monitoring snapshot available"

        }), 404


    return jsonify(
        snapshot
    )


# ============================================================
# API HEALTH
# ============================================================

@app.route("/api/health")
def health():

    return jsonify({

        "service":
            "SentinelX API",

        "status":
            "healthy",

        "timestamp":
            datetime.now().isoformat()

    })


# ============================================================
# SECURITY REPORT
# ============================================================

@app.route("/api/report")
def security_report():

    try:

        # ----------------------------------------------------
        # REPORT TIME
        # ----------------------------------------------------

        report_time = datetime.now().strftime(

            "%d %B %Y, %I:%M:%S %p"

        )


        # ----------------------------------------------------
        # LATEST WINDOWS SNAPSHOT
        # ----------------------------------------------------

        snapshot = get_latest_snapshot()


        if snapshot:

            hostname = snapshot.get(
                "hostname",
                "Unknown"
            )

            operating_system = snapshot.get(
                "operating_system",
                "Unknown"
            )

            os_version = snapshot.get(
                "os_version",
                "Unknown"
            )

            username = snapshot.get(
                "username",
                "Unknown"
            )

            snapshot_processes = (
                normalize_processes(
                    snapshot.get(
                        "processes",
                        []
                    )
                )
            )

            snapshot_network = (
                parse_network_data(
                    snapshot.get(
                        "network",
                        []
                    )
                )
            )

            process_count = len(
                snapshot_processes
            )

            network_count = len(
                snapshot_network
            )


        else:

            hostname = socket.gethostname()

            operating_system = (
                platform.system()
            )

            os_version = (
                platform.version()
            )

            username = getpass.getuser()


            try:

                process_count = len(
                    list(
                        psutil.process_iter()
                    )
                )

            except Exception:

                process_count = 0


            try:

                network_count = len(

                    psutil.net_connections(
                        kind="inet"
                    )

                )

            except Exception:

                network_count = 0


        # ----------------------------------------------------
        # RISK
        # ----------------------------------------------------

        current_risk = (
            get_current_risk_score()
        )

        highest_risk = (
            get_highest_risk_score()
        )

        total_events = (
            get_event_count()
        )


        # ----------------------------------------------------
        # RISK LEVEL
        # ----------------------------------------------------

        if current_risk >= 100:

            risk_level = "CRITICAL"

        elif current_risk >= 75:

            risk_level = "HIGH"

        elif current_risk >= 50:

            risk_level = "MEDIUM"

        elif current_risk >= 20:

            risk_level = "LOW"

        else:

            risk_level = "NORMAL"


        # ----------------------------------------------------
        # SECURITY ALERTS
        # ----------------------------------------------------

        security_alerts = (
            get_security_alerts()
        )


        # ----------------------------------------------------
        # RECENT EVENTS
        # ----------------------------------------------------

        recent_events = (
            get_recent_events()
        )


        # ----------------------------------------------------
        # SECURITY STATUS
        # ----------------------------------------------------

        if current_risk >= 75:

            security_status = "HIGH RISK"

        elif current_risk >= 50:

            security_status = "MODERATE RISK"

        elif current_risk >= 20:

            security_status = "LOW RISK"

        else:

            security_status = "SECURE"


        # ----------------------------------------------------
        # ALERT TABLE
        # ----------------------------------------------------

        alert_rows = ""


        for alert in security_alerts[:20]:

            try:

                event_id = alert[0]

                timestamp = alert[1]

                severity = alert[2]

                process = alert[3]

                message = alert[4]

                risk_score = alert[5]


            except Exception:

                continue


            alert_rows += f"""

            <tr>

                <td>{event_id}</td>

                <td>{timestamp}</td>

                <td>{severity}</td>

                <td>{process}</td>

                <td>{message}</td>

                <td>{risk_score}</td>

            </tr>

            """


        if not alert_rows:

            alert_rows = """

            <tr>

                <td colspan="6">

                    No security alerts recorded.

                </td>

            </tr>

            """


        # ----------------------------------------------------
        # EVENT TABLE
        # ----------------------------------------------------

        event_rows = ""


        for event in recent_events[:30]:

            try:

                event_id = event[0]

                timestamp = event[1]

                event_type = event[2]

                severity = event[3]

                process = event[4] or "-"

                message = event[5]

                risk_score = event[6]


            except Exception:

                continue


            event_rows += f"""

            <tr>

                <td>{event_id}</td>

                <td>{timestamp}</td>

                <td>{event_type}</td>

                <td>{severity}</td>

                <td>{process}</td>

                <td>{message}</td>

                <td>{risk_score}</td>

            </tr>

            """


        if not event_rows:

            event_rows = """

            <tr>

                <td colspan="7">

                    No recent events recorded.

                </td>

            </tr>

            """


        # ----------------------------------------------------
        # HTML REPORT
        # ----------------------------------------------------

        html_report = f"""

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>SentinelX Security Report</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #f4f7f9;
    color: #17202a;
}}

.container {{
    width: 94%;
    max-width: 1400px;
    margin: 30px auto;
}}

.header {{
    background: #111827;
    color: white;
    padding: 35px;
    border-radius: 12px;
    margin-bottom: 25px;
}}

.header h1 {{
    margin: 0 0 8px 0;
    font-size: 32px;
}}

.header p {{
    margin: 5px 0;
    color: #cbd5e1;
}}

.status {{
    display: inline-block;
    margin-top: 15px;
    padding: 8px 16px;
    border-radius: 20px;
    background: #00a878;
    color: white;
    font-weight: bold;
}}

.section {{
    background: white;
    padding: 25px;
    margin-bottom: 25px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}}

.section h2 {{
    margin-top: 0;
    border-bottom: 2px solid #e5e7eb;
    padding-bottom: 10px;
}}

.summary {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
}}

.card {{
    padding: 20px;
    background: #f8fafc;
    border-radius: 10px;
    border: 1px solid #e2e8f0;
}}

.card-title {{
    color: #64748b;
    font-size: 13px;
    margin-bottom: 8px;
}}

.card-value {{
    font-size: 25px;
    font-weight: bold;
}}

.low {{
    color: #d97706;
}}

.medium {{
    color: #ea580c;
}}

.high {{
    color: #dc2626;
}}

.critical {{
    color: #991b1b;
}}

.normal {{
    color: #059669;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}

th {{
    background: #111827;
    color: white;
    padding: 10px;
    text-align: left;
    font-size: 13px;
}}

td {{
    padding: 9px;
    border-bottom: 1px solid #e5e7eb;
    font-size: 12px;
}}

tr:nth-child(even) {{
    background: #f8fafc;
}}

.info-grid {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(250px, 1fr));
    gap: 10px;
}}

.info-item {{
    padding: 12px;
    background: #f8fafc;
    border-radius: 8px;
}}

.footer {{
    text-align: center;
    color: #64748b;
    padding: 25px;
    font-size: 13px;
}}

@media print {{

    body {{
        background: white;
    }}

    .container {{
        width: 100%;
        margin: 0;
    }}

    .section {{
        box-shadow: none;
        border: 1px solid #ddd;
        break-inside: avoid;
    }}

}}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>SentinelX Security Report</h1>

<p>Cybersecurity Monitoring System</p>

<p>Generated: {report_time}</p>

<div class="status">
{security_status}
</div>

</div>


<div class="section">

<h2>Executive Summary</h2>

<div class="summary">

<div class="card">

<div class="card-title">
Current Risk
</div>

<div class="card-value {risk_level.lower()}">
{current_risk}/100
</div>

</div>


<div class="card">

<div class="card-title">
Risk Level
</div>

<div class="card-value {risk_level.lower()}">
{risk_level}
</div>

</div>


<div class="card">

<div class="card-title">
Highest Recorded Risk
</div>

<div class="card-value">
{highest_risk}/100
</div>

</div>


<div class="card">

<div class="card-title">
Total Events
</div>

<div class="card-value">
{total_events}
</div>

</div>


<div class="card">

<div class="card-title">
Security Alerts
</div>

<div class="card-value">
{len(security_alerts)}
</div>

</div>


<div class="card">

<div class="card-title">
Running Processes
</div>

<div class="card-value">
{process_count}
</div>

</div>


<div class="card">

<div class="card-title">
Network Connections
</div>

<div class="card-value">
{network_count}
</div>

</div>

</div>

</div>


<div class="section">

<h2>System Information</h2>

<div class="info-grid">

<div class="info-item">
<strong>Hostname:</strong>
{hostname}
</div>

<div class="info-item">
<strong>Operating System:</strong>
{operating_system}
</div>

<div class="info-item">
<strong>OS Version:</strong>
{os_version}
</div>

<div class="info-item">
<strong>Username:</strong>
{username}
</div>

</div>

</div>


<div class="section">

<h2>Security Alerts</h2>

<table>

<thead>

<tr>

<th>ID</th>
<th>Timestamp</th>
<th>Severity</th>
<th>Process</th>
<th>Message</th>
<th>Risk</th>

</tr>

</thead>

<tbody>

{alert_rows}

</tbody>

</table>

</div>


<div class="section">

<h2>Recent Security Events</h2>

<table>

<thead>

<tr>

<th>ID</th>
<th>Timestamp</th>
<th>Type</th>
<th>Severity</th>
<th>Process</th>
<th>Message</th>
<th>Risk</th>

</tr>

</thead>

<tbody>

{event_rows}

</tbody>

</table>

</div>


<div class="section">

<h2>Monitoring Summary</h2>

<p>
SentinelX continuously monitors the system for suspicious
process activity, security events, risk indicators and
network activity.
</p>

<p>
The current security assessment is:
<strong>{security_status}</strong>.
</p>

<p>
Current risk score:
<strong>{current_risk}/100</strong>.
</p>

<p>
Highest recorded risk score:
<strong>{highest_risk}/100</strong>.
</p>

</div>


<div class="footer">

SentinelX Cybersecurity Monitoring System<br>

Automated Security Assessment Report<br>

Generated on {report_time}

</div>

</div>

</body>

</html>

"""


        return Response(

            html_report,

            mimetype="text/html",

            headers={

                "Content-Disposition":
                    "attachment; "
                    "filename="
                    "SentinelX_Security_Report.html"

            }

        )


    except Exception as error:

        print(
            "Report generation error:",
            error
        )


        return jsonify({

            "error":
                "Unable to generate security report",

            "details":
                str(error)

        }), 500


# ============================================================
# 404 ERROR
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({

        "error":
            "Endpoint not found"

    }), 404


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()

    print("================================")

    print("       SENTINELX API")

    print("================================")

    host = "0.0.0.0"

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    print(
        "API server starting..."
    )

    print(
        f"Host: {host}"
    )

    print(
        f"Port: {port}"
    )

    print()

    app.run(

        host=host,

        port=port,

        debug=False

    )