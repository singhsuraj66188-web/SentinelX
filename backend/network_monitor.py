import subprocess


def get_network_connections():
    result = subprocess.run(
        ["netstat", "-ano"],
        capture_output=True,
        text=True
    )

    return result.stdout


def display_network_connections(connections):
    print("\n========== NETWORK CONNECTIONS ==========")

    print(connections)

    print("=========================================\n")


if __name__ == "__main__":
    connections = get_network_connections()
    display_network_connections(connections)