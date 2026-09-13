import time

from monitor import display_system_status
from process_monitor import get_running_processes, get_process_list
from process_metadata import get_process_details
from network_monitor import get_network_connections
from detector import (
    analyze_processes,
    analyze_process_metadata,
    display_alerts
)
from risk_engine import calculate_risk_score, display_risk_score
from logger import log_event
from database import initialize_database, save_event


def show_banner():
    print("================================")
    print("          SENTINELX")
    print(" Cybersecurity Monitoring System")
    print("================================")


def monitoring_cycle():

    print("\n========== MONITORING CYCLE ==========")

    # --------------------------------------------
    # START MONITORING CYCLE
    # --------------------------------------------

    log_event(
        "SYSTEM",
        "Monitoring cycle started",
        "INFO"
    )

    # --------------------------------------------
    # SYSTEM STATUS
    # --------------------------------------------

    display_system_status()

    # --------------------------------------------
    # PROCESS MONITORING
    # --------------------------------------------

    print("Collecting running processes...")

    raw_processes = get_running_processes()
    process_list = get_process_list()

    print("Analyzing processes...")

    # --------------------------------------------
    # BASIC PROCESS DETECTION
    # --------------------------------------------

    alerts = analyze_processes(raw_processes)

    # --------------------------------------------
    # PROCESS METADATA ANALYSIS
    # --------------------------------------------

    # Processes that may require additional
    # command-line / parent-process investigation.

    metadata_processes = {
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe"
    }

    for process in process_list:

        process_name = process["name"].lower()

        if process_name in metadata_processes:

            try:

                metadata = get_process_details(
                    process["pid"]
                )

                metadata_alerts = analyze_process_metadata(
                    metadata
                )

                alerts.extend(metadata_alerts)

            except Exception as error:

                print(
                    f"Metadata analysis failed for "
                    f"{process_name} "
                    f"(PID {process['pid']}): {error}"
                )

                log_event(
                    "SYSTEM",
                    (
                        f"Metadata analysis failed for "
                        f"{process_name} "
                        f"(PID {process['pid']})"
                    ),
                    "INFO"
                )

    # --------------------------------------------
    # SECURITY ANALYSIS DISPLAY
    # --------------------------------------------

    display_alerts(alerts)

    # --------------------------------------------
    # SAVE SECURITY ALERTS
    # --------------------------------------------

    for alert in alerts:

        message = (
            f"{alert['process']} - "
            f"{alert['reason']}"
        )

        # Log alert

        log_event(
            "SECURITY_ALERT",
            message,
            alert["severity"]
        )

        # Calculate risk contribution
        # for this individual alert.

        alert_risk_score = calculate_risk_score(
            [alert]
        )

        # Save alert to database.

        save_event(
            event_type="SECURITY_ALERT",
            message=message,
            severity=alert["severity"],
            process=alert["process"],
            risk_score=alert_risk_score
        )

    # --------------------------------------------
    # OVERALL RISK ASSESSMENT
    # --------------------------------------------

    risk_score = calculate_risk_score(alerts)

    display_risk_score(risk_score)

    # Log risk assessment

    log_event(
        "RISK_ASSESSMENT",
        f"Risk score: {risk_score}/100",
        "INFO"
    )

    # Save risk assessment

    save_event(
        event_type="RISK_ASSESSMENT",
        message=f"Risk score: {risk_score}/100",
        severity="INFO",
        risk_score=risk_score
    )

    # --------------------------------------------
    # NETWORK MONITORING
    # --------------------------------------------

    print("Collecting network connections...")

    connections = get_network_connections()

    connection_count = len(
        [
            line
            for line in connections.splitlines()
            if line.strip()
        ]
    )

    print(
        f"Network records collected: "
        f"{connection_count}"
    )

    # Log network information

    log_event(
        "NETWORK",
        f"{connection_count} network records collected",
        "INFO"
    )

    # Save network information

    save_event(
        event_type="NETWORK",
        message=(
            f"{connection_count} "
            f"network records collected"
        ),
        severity="INFO",
        risk_score=risk_score
    )

    # --------------------------------------------
    # CYCLE COMPLETE
    # --------------------------------------------

    log_event(
        "SYSTEM",
        "Monitoring cycle completed",
        "INFO"
    )

    print("=======================================")


def main():

    print("Starting SentinelX...\n")

    show_banner()

    # --------------------------------------------
    # DATABASE INITIALIZATION
    # --------------------------------------------

    initialize_database()

    # --------------------------------------------
    # START LOGGING
    # --------------------------------------------

    log_event(
        "SYSTEM",
        "SentinelX continuous monitoring started",
        "INFO"
    )

    # --------------------------------------------
    # CONTINUOUS MONITORING
    # --------------------------------------------

    try:

        while True:

            monitoring_cycle()

            print(
                "\nNext monitoring cycle in "
                "30 seconds..."
            )

            print(
                "Press Ctrl+C to stop SentinelX."
            )

            time.sleep(30)

    except KeyboardInterrupt:

        print(
            "\nSentinelX stopped by user."
        )

        # Log shutdown

        log_event(
            "SYSTEM",
            "SentinelX stopped by user",
            "INFO"
        )

        # Save shutdown event

        save_event(
            event_type="SYSTEM",
            message="SentinelX stopped by user",
            severity="INFO",
            risk_score=0
        )


if __name__ == "__main__":
    main()
