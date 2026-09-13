import os
import platform
import socket


def get_system_status():
    status = {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "os_version": platform.version(),
        "username": os.environ.get("USERNAME", "Unknown"),
    }

    return status


def display_system_status():
    print("\n========== SYSTEM STATUS ==========")

    status = get_system_status()

    for key, value in status.items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    print("===================================\n")


if __name__ == "__main__":
    display_system_status()