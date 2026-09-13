# SentinelX — Cybersecurity Monitoring System

SentinelX is a Windows-based cybersecurity monitoring and threat detection system designed to continuously monitor system activity, detect suspicious processes, assess security risk, and present security information through a web-based dashboard.

## Features

* Real-time system monitoring
* Running process monitoring
* Suspicious process detection
* Risk scoring and severity classification
* Network connection monitoring
* Security event logging
* SQLite database storage
* REST API using Flask
* Interactive web dashboard
* Security alerts and event history
* Security report generation
* Current-risk and historical-risk tracking

## System Architecture

```text
┌───────────────────────────────┐
│      Windows Monitoring       │
│           Engine              │
│                               │
│  System Monitor               │
│  Process Monitor              │
│  Network Monitor              │
│  Threat Detector              │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Risk Assessment         │
│                               │
│ INFO     → 0                  │
│ LOW      → 20                 │
│ MEDIUM   → 50                 │
│ HIGH     → 75                 │
│ CRITICAL → 100                │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       SQLite Database         │
│       Security Events         │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│        Flask REST API         │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│       Web Dashboard           │
│                               │
│ Risk • Alerts • Events        │
│ Processes • Network • Stats   │
└───────────────────────────────┘
```

## Technology Stack

### Backend

* Python
* Flask
* Flask-CORS
* psutil
* SQLite

### Frontend

* HTML5
* CSS3
* JavaScript
* Chart.js

### Development Tools

* Visual Studio Code
* Git
* GitHub

## Project Structure

```text
SentinelX/
│
├── backend/
│   ├── api.py
│   ├── database.py
│   ├── detector.py
│   ├── logger.py
│   ├── main.py
│   ├── monitor.py
│   ├── network_monitor.py
│   ├── process_metadata.py
│   ├── process_monitor.py
│   └── risk_engine.py
│
├── dashboard/
│   ├── app.js
│   ├── index.html
│   └── style.css
│
├── data/
│   └── sentinelx.db
│
├── logs/
│   └── sentinelx.log
│
├── requirements.txt
├── .gitignore
└── README.md
```

> Local database files, logs, and generated reports are excluded from Git using `.gitignore`.

## Detection Engine

SentinelX currently uses rule-based detection for selected Windows processes associated with potentially suspicious execution behavior.

| Process        | Severity | Risk Score |
| -------------- | -------: | ---------: |
| `wscript.exe`  |     HIGH |         75 |
| `cscript.exe`  |     HIGH |         75 |
| `mshta.exe`    |     HIGH |         75 |
| `regsvr32.exe` |     HIGH |         75 |
| `rundll32.exe` |      LOW |         20 |

The detection engine analyzes running processes and generates security events when configured suspicious indicators are observed.

## Risk Assessment

SentinelX converts event severity into a numerical risk score:

| Severity | Score |
| -------- | ----: |
| INFO     |     0 |
| LOW      |    20 |
| MEDIUM   |    50 |
| HIGH     |    75 |
| CRITICAL |   100 |

The dashboard distinguishes between:

* **Current Risk** — risk associated with the latest/current security state.
* **Highest Risk** — highest risk recorded during the monitoring history.

This allows historical security events to remain visible even after the current system state returns to a lower risk level.

## REST API

The Flask backend provides endpoints including:

```text
/api/status
/api/system
/api/events
/api/alerts
/api/risk
/api/processes
/api/network
/api/health
/api/report
```

The API acts as the communication layer between the monitoring engine, database, and dashboard.

## Dashboard

The SentinelX dashboard provides:

* System overview
* Current security status
* Risk assessment
* Risk history visualization
* Security alerts
* Event history
* Process monitoring
* Network monitoring
* Security statistics
* Security report generation

## Running SentinelX Locally

### 1. Install dependencies

Open a terminal in the project directory:

```powershell
pip install -r requirements.txt
```

### 2. Start the monitoring engine

```powershell
cd backend
python main.py
```

### 3. Start the API

Open another terminal:

```powershell
cd backend
python api.py
```

The API runs at:

```text
http://127.0.0.1:5000
```

### 4. Start the dashboard

Open another terminal:

```powershell
cd dashboard
python -m http.server 5500
```

Open:

```text
http://127.0.0.1:5500
```

## Security and Privacy

SentinelX is designed as a local cybersecurity monitoring project.

The repository intentionally excludes:

* Local SQLite databases
* Runtime logs
* Generated security reports
* Environment files
* Secrets and credentials
* Machine-specific runtime data

These exclusions are configured through `.gitignore`.

## Limitations

* Primarily designed for Windows environments.
* Detection currently uses rule-based indicators rather than a full machine-learning threat detection model.
* Network monitoring provides connection-level visibility rather than deep packet inspection.
* The current system is intended as an academic cybersecurity monitoring project rather than an enterprise SIEM.

## Future Scope

Potential future improvements include:

* Machine-learning-based anomaly detection
* Authentication and role-based access control
* Centralized cloud monitoring
* Multi-device monitoring
* Email/SMS security notifications
* Advanced network analysis
* Threat intelligence integration
* Improved behavioral analysis
* Docker-based deployment
* Enterprise-scale log management

## Project Status

**Status:** Functional prototype / major project

SentinelX currently includes the core monitoring engine, threat detection, risk assessment, database logging, REST API, web dashboard, and security report generation.

## Disclaimer

SentinelX is developed for educational, research, and authorized cybersecurity monitoring purposes. It should only be used on systems and networks where the user has appropriate authorization.
