from flask import Flask, jsonify, Response
from flask_cors import CORS

import os
import platform
import socket
import getpass
import psutil
from datetime import datetime

from database import (
    initialize_database,
    get_recent_events,
    get_security_alerts,
    get_current_risk_score,
    get_highest_risk_score,
    get_event_count
)


# ============================================
# SENTINELX API
# ============================================

app = Flask(__name__)

CORS(app)


# ============================================
# DATABASE
# ============================================

initialize_database()


# ============================================
# HOME
# ============================================

@app.route("/")
def home():

    return jsonify({
        "name": "SentinelX",
        "description": "Cybersecurity Monitoring System",
        "status": "online"
    })


# ============================================
# SYSTEM STATUS
# ============================================

@app.route("/api/status")
def status():

    try:

        total_events = get_event_count()

    except Exception as error:

        print("Status error:", error)

        total_events = 0

    return jsonify({
        "status": "online",
        "total_events": total_events
    })


# ============================================
# SYSTEM INFORMATION
# ============================================

@app.route("/api/system")
def system_info():

    try:

        return jsonify({
            "hostname": socket.gethostname(),
            "operating_system": platform.system(),
            "os_version": platform.version(),
            "username": getpass.getuser()
        })

    except Exception as error:

        print("System information error:", error)

        return jsonify({
            "hostname": "Unavailable",
            "operating_system": "Unavailable",
            "os_version": "Unavailable",
            "username": "Unavailable"
        }), 500


# ============================================
# EVENT HISTORY
# ============================================

@app.route("/api/events")
def events():

    try:

        data = get_recent_events()

        return jsonify(data)

    except Exception as error:

        print("Events error:", error)

        return jsonify([])


# ============================================
# SECURITY ALERTS
# ============================================

@app.route("/api/alerts")
def alerts():

    try:

        data = get_security_alerts()

        return jsonify(data)

    except Exception as error:

        print("Alerts error:", error)

        return jsonify([])


# ============================================
# RISK SCORE
# ============================================

@app.route("/api/risk")
def risk():

    try:

        current_risk = get_current_risk_score()

        highest_risk = get_highest_risk_score()

        return jsonify({
            "current_risk": current_risk,
            "highest_risk": highest_risk
        })

    except Exception as error:

        print("Risk error:", error)

        return jsonify({
            "current_risk": 0,
            "highest_risk": 0
        })


# ============================================
# RUNNING PROCESSES
# ============================================

@app.route("/api/processes")
def processes():

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

                if info.get("memory_info"):

                    memory = info["memory_info"].rss

                process_list.append({

                    "pid": info.get("pid"),

                    "name": info.get("name") or "-",

                    "status": info.get("status") or "unknown",

                    "username": info.get("username") or "-",

                    "memory": memory

                })

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):

                continue

        return jsonify(process_list)

    except Exception as error:

        print(
            "Process monitoring error:",
            error
        )

        return jsonify([])


# ============================================
# NETWORK CONNECTIONS
# ============================================

@app.route("/api/network")
def network():

    connections = []

    try:

        network_connections = psutil.net_connections(
            kind="inet"
        )

        for connection in network_connections:

            try:

                # -----------------------------
                # PROTOCOL
                # -----------------------------

                if connection.type == socket.SOCK_STREAM:

                    protocol = "TCP"

                elif connection.type == socket.SOCK_DGRAM:

                    protocol = "UDP"

                else:

                    protocol = "UNKNOWN"


                # -----------------------------
                # LOCAL ADDRESS
                # -----------------------------

                if connection.laddr:

                    local_address = (
                        f"{connection.laddr.ip}:"
                        f"{connection.laddr.port}"
                    )

                else:

                    local_address = "-"


                # -----------------------------
                # FOREIGN ADDRESS
                # -----------------------------

                if connection.raddr:

                    foreign_address = (
                        f"{connection.raddr.ip}:"
                        f"{connection.raddr.port}"
                    )

                else:

                    foreign_address = "-"


                # -----------------------------
                # CONNECTION STATE
                # -----------------------------

                state = connection.status or "-"


                # -----------------------------
                # PROCESS ID
                # -----------------------------

                pid = connection.pid

                if pid is None:

                    pid = "-"


                # -----------------------------
                # SAVE CONNECTION
                # -----------------------------

                connections.append({

                    "protocol": protocol,

                    "local_address": local_address,

                    "foreign_address": foreign_address,

                    "state": state,

                    "pid": pid

                })

            except Exception as error:

                print(
                    "Network record error:",
                    error
                )

                continue

        return jsonify(connections)

    except Exception as error:

        print(
            "Network monitoring error:",
            error
        )

        return jsonify([])


# ============================================
# API HEALTH
# ============================================

@app.route("/api/health")
def health():

    return jsonify({

        "service": "SentinelX API",

        "status": "healthy",

        "timestamp": datetime.now().isoformat()

    })


# ============================================
# SECURITY REPORT
# ============================================

@app.route("/api/report")
def security_report():

    try:

        # ----------------------------------------
        # REPORT TIME
        # ----------------------------------------

        report_time = datetime.now().strftime(
            "%d %B %Y, %I:%M:%S %p"
        )


        # ----------------------------------------
        # SYSTEM INFORMATION
        # ----------------------------------------

        hostname = socket.gethostname()

        operating_system = platform.system()

        os_version = platform.version()

        username = getpass.getuser()


        # ----------------------------------------
        # RISK INFORMATION
        # ----------------------------------------

        current_risk = get_current_risk_score()

        highest_risk = get_highest_risk_score()

        total_events = get_event_count()


        # ----------------------------------------
        # RISK LEVEL
        # ----------------------------------------

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


        # ----------------------------------------
        # SECURITY ALERTS
        # ----------------------------------------

        security_alerts = get_security_alerts()


        # ----------------------------------------
        # RECENT EVENTS
        # ----------------------------------------

        recent_events = get_recent_events()


        # ----------------------------------------
        # PROCESS INFORMATION
        # ----------------------------------------

        process_count = 0

        try:

            process_count = len(
                list(psutil.process_iter())
            )

        except Exception:

            process_count = 0


        # ----------------------------------------
        # NETWORK INFORMATION
        # ----------------------------------------

        network_count = 0

        try:

            network_count = len(
                psutil.net_connections(
                    kind="inet"
                )
            )

        except Exception:

            network_count = 0


        # ----------------------------------------
        # SECURITY STATUS
        # ----------------------------------------

        if current_risk >= 75:

            security_status = "HIGH RISK"

        elif current_risk >= 50:

            security_status = "MODERATE RISK"

        elif current_risk >= 20:

            security_status = "LOW RISK"

        else:

            security_status = "SECURE"


        # ----------------------------------------
        # ALERT TABLE
        # ----------------------------------------

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


        # ----------------------------------------
        # EVENT TABLE
        # ----------------------------------------

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


        # ----------------------------------------
        # HTML REPORT
        # ----------------------------------------

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


<!-- HEADER -->

<div class="header">

<h1>SentinelX Security Report</h1>

<p>Cybersecurity Monitoring System</p>

<p>Generated: {report_time}</p>

<div class="status">
    {security_status}
</div>

</div>


<!-- EXECUTIVE SUMMARY -->

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


<!-- SYSTEM INFORMATION -->

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


<!-- SECURITY ALERTS -->

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


<!-- RECENT EVENTS -->

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


<!-- MONITORING SUMMARY -->

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


<!-- FOOTER -->

<div class="footer">

SentinelX Cybersecurity Monitoring System<br>

Automated Security Assessment Report<br>

Generated on {report_time}

</div>


</div>

</body>

</html>
"""


        # ----------------------------------------
        # RETURN REPORT
        # ----------------------------------------

        return Response(
            html_report,
            mimetype="text/html",
            headers={
                "Content-Disposition":
                    "attachment; filename=SentinelX_Security_Report.html"
            }
        )


    except Exception as error:

        print(
            "Report generation error:",
            error
        )

        return jsonify({
            "error": "Unable to generate security report",
            "details": str(error)
        }), 500


# ============================================
# 404 ERROR
# ============================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "error": "Endpoint not found"
    }), 404


# ============================================
# START SERVER
# ============================================

if __name__ == "__main__":

    print()

    print("================================")

    print("       SENTINELX API")

    print("================================")

    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 5000))

    print("API server starting...")
    print(f"Host: {host}")
    print(f"Port: {port}")

    print()

    app.run(
        host=host,
        port=port,
        debug=False
    )