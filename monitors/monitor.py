import subprocess
import time
from datetime import datetime

def get_active_connections():
    result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
    return result.stdout

def get_running_processes():
    result = subprocess.run(['tasklist'], capture_output=True, text=True)
    return result.stdout

def log_activity(data, filename):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(f"logs/{filename}", "a", encoding="utf-8") as f:
        f.write(f"\n[{timestamp}]\n{data}\n")

def monitor():
    print("========================================")
    print("  HODOR - Hold, Observe, Detect,")
    print("          Organize, Respond")
    print("  HODOR holds the door so threats")
    print("  can't get through.")
    print("========================================")
    print("Cikis icin CTRL+C\n")
    while True:
        connections = get_active_connections()
        log_activity(connections, "connections.log")
        processes = get_running_processes()
        log_activity(processes, "processes.log")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Tarama tamamlandi...")
        time.sleep(60)

if __name__ == "__main__":
    monitor()
