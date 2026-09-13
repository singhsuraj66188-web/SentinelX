import subprocess
import sys


def get_process_details(pid):
    command = [
        "wmic",
        "process",
        "where",
        f"ProcessId={pid}",
        "get",
        "Name,ExecutablePath,CommandLine,ParentProcessId",
        "/format:list"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.stdout


def display_process_details(pid):
    print("\n========== PROCESS DETAILS ==========")
    print(f"PID: {pid}")
    print()

    details = get_process_details(pid)

    if details.strip():
        print(details)
    else:
        print("No process information found.")

    print("=====================================\n")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: py backend\\process_metadata.py <PID>")
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
    except ValueError:
        print("PID must be a number.")
        sys.exit(1)

    display_process_details(pid)