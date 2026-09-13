# SentinelX - Intelligent Process Detector

"""
SentinelX security detection engine.

The detector uses multiple layers:

1. Suspicious process detection
2. Process metadata analysis
3. Suspicious command-line indicators
4. Context-aware severity

Important:
Legitimate Windows utilities such as PowerShell and
Rundll32 are not automatically considered malicious.
"""

# ============================================================
# SUSPICIOUS / MONITORED PROCESSES
# ============================================================

SUSPICIOUS_PROCESSES = {

    "wscript.exe": {
        "reason": "Windows Script Host detected",
        "severity": "HIGH"
    },

    "cscript.exe": {
        "reason": "Windows Script Host detected",
        "severity": "HIGH"
    },

    "mshta.exe": {
        "reason": "MSHTA process detected",
        "severity": "HIGH"
    },

    "regsvr32.exe": {
        "reason": "Regsvr32 execution detected",
        "severity": "HIGH"
    },

    "rundll32.exe": {
        "reason": "Rundll32 execution detected",
        "severity": "LOW"
    }
}


# ============================================================
# POWERSHELL SUSPICIOUS ARGUMENTS
# ============================================================

SUSPICIOUS_POWERSHELL_ARGUMENTS = [

    "-enc",

    "-encodedcommand",

    "invoke-expression",

    "iex ",

    "downloadstring",

    "downloadfile",

    "invoke-webrequest",

    "iwr ",

    "start-bitstransfer"

]


# ============================================================
# RUNDLL32 SUSPICIOUS INDICATORS
# ============================================================

SUSPICIOUS_RUNDLL32_INDICATORS = [

    "http://",

    "https://",

    "javascript:",

    "vbscript:",

    "\\temp\\",

    "\\appdata\\",

    "\\downloads\\",

    ".url,",

    ".hta,",

    "javascript",

    "shell32.dll"

]


# ============================================================
# REGSVR32 SUSPICIOUS INDICATORS
# ============================================================

SUSPICIOUS_REGSVR32_INDICATORS = [

    "http://",

    "https://",

    "\\temp\\",

    "\\appdata\\",

    "\\downloads\\",

    ".sct",

    "/i:"

]


# ============================================================
# BASIC PROCESS ANALYSIS
# ============================================================

def analyze_processes(process_output):
    """
    Analyze raw Windows process output.

    Normal monitored processes are reported only once
    per monitoring cycle.
    """

    alerts = []

    detected = set()

    if not process_output:
        return alerts

    for line in process_output.splitlines():

        line_lower = line.lower()

        for process_name, details in SUSPICIOUS_PROCESSES.items():

            if process_name in line_lower:

                if process_name not in detected:

                    alerts.append({

                        "process": process_name,

                        "reason": details["reason"],

                        "severity": details["severity"]

                    })

                    detected.add(process_name)

    return alerts


# ============================================================
# PROCESS METADATA ANALYSIS
# ============================================================

def analyze_process_metadata(metadata):
    """
    Analyze command-line and process metadata.

    PowerShell, Rundll32 and Regsvr32 are legitimate
    Windows utilities and are only escalated when
    suspicious behavior is detected.
    """

    alerts = []

    if not metadata:

        return alerts

    metadata_lower = metadata.lower()

    # --------------------------------------------------------
    # POWERSHELL
    # --------------------------------------------------------

    if "powershell.exe" in metadata_lower:

        for argument in SUSPICIOUS_POWERSHELL_ARGUMENTS:

            if argument in metadata_lower:

                alerts.append({

                    "process": "powershell.exe",

                    "reason": (
                        "Suspicious PowerShell argument "
                        f"detected: {argument}"
                    ),

                    "severity": "HIGH"

                })

                break

    # --------------------------------------------------------
    # RUNDLL32
    # --------------------------------------------------------

    if "rundll32.exe" in metadata_lower:

        for indicator in SUSPICIOUS_RUNDLL32_INDICATORS:

            if indicator in metadata_lower:

                alerts.append({

                    "process": "rundll32.exe",

                    "reason": (
                        "Suspicious Rundll32 indicator "
                        f"detected: {indicator}"
                    ),

                    "severity": "HIGH"

                })

                break

    # --------------------------------------------------------
    # REGSVR32
    # --------------------------------------------------------

    if "regsvr32.exe" in metadata_lower:

        for indicator in SUSPICIOUS_REGSVR32_INDICATORS:

            if indicator in metadata_lower:

                alerts.append({

                    "process": "regsvr32.exe",

                    "reason": (
                        "Suspicious Regsvr32 indicator "
                        f"detected: {indicator}"
                    ),

                    "severity": "HIGH"

                })

                break

    return alerts


# ============================================================
# ALERT DISPLAY
# ============================================================

def display_alerts(alerts):

    print("\n========== SECURITY ANALYSIS ==========")

    if not alerts:

        print(
            "Status: No suspicious indicators detected."
        )

    else:

        print(
            f"Indicators detected: {len(alerts)}"
        )

        for alert in alerts:

            print(

                f"[{alert['severity']}] "

                f"{alert['process']} - "

                f"{alert['reason']}"

            )

    print(
        "=======================================\n"
    )

