import subprocess
import csv
import io


def get_running_processes():
    result = subprocess.run(
        ["tasklist"],
        capture_output=True,
        text=True
    )
    return result.stdout


def get_process_list():
    result = subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True
    )

    processes = []

    reader = csv.reader(io.StringIO(result.stdout))

    for row in reader:
        if len(row) >= 2:
            try:
                processes.append({
                    "name": row[0],
                    "pid": int(row[1])
                })
            except ValueError:
                pass

    return processes


def display_processes(processes):
    print("\n========== RUNNING PROCESSES ==========")
    print(processes)
    print("=======================================\n")


if __name__ == "__main__":
    process_list = get_process_list()

    for process in process_list[:10]:
        print(process)   