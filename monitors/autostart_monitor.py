import subprocess
import os
import csv
import io
from datetime import datetime

WHITELIST_AUTOSTART = [
    "onedrive", "dropbox", "googledrive",
    "steam", "discord", "spotify",
    "nvidia", "realtek", "intel",
    "windows security", "windefend", "securityhealth",
    "synaptics", "logitech",
    "claude", "cowork-svc",
    "cloudflare", "warp",
    "desktop.ini",
    "ollama",
    "microsoftedgeautolaunch",
    "edge",
"softlanding",
]

def is_whitelisted(name):
    name_lower = name.lower()
    for w in WHITELIST_AUTOSTART:
        if w in name_lower:
            return True
    return False

def run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout
        )
        stdout = result.stdout.decode('utf-8', errors='ignore')
        return stdout
    except Exception:
        return ""

def get_registry_autostart():
    entries = []
    locations = [
        ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
        ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
        ('HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
        ('HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
    ]

    for hive, path in locations:
        output = run_cmd(['reg', 'query', f'{hive}\\{path}'])
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('HKEY') and 'REG_' in line:
                parts = line.split('REG_', 1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    value = parts[1].split(None, 1)
                    value_str = value[1] if len(value) > 1 else ""
                    entries.append({
                        "location": f"{hive}\\{path}",
                        "name": name,
                        "value": value_str.strip()
                    })

    return entries

def get_startup_folder_items():
    entries = []
    startup_paths = [
        os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
        os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
    ]

    for path in startup_paths:
        if os.path.exists(path):
            try:
                for item in os.listdir(path):
                    if item.lower() == "desktop.ini":
                        continue
                    entries.append({
                        "location": "Startup Folder",
                        "name": item,
                        "value": os.path.join(path, item)
                    })
            except Exception:
                continue

    return entries

def get_scheduled_tasks():
    """schtasks CSV ciktisini gercek bir CSV parser ile okur (manuel split yerine)"""
    entries = []
    output = run_cmd(['schtasks', '/query', '/fo', 'CSV', '/v'], timeout=20)

    if not output.strip():
        return entries

    try:
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
    except Exception:
        return entries

    if len(rows) < 2:
        return entries

    header = rows[0]

    def find_col(possible_names):
        for i, col in enumerate(header):
            for pname in possible_names:
                if pname.lower() in col.lower():
                    return i
        return -1

    name_idx = find_col(["TaskName", "Gorev Adi", "Görev Adı"])
    status_idx = find_col(["Status", "Durum"])

    if name_idx == -1:
        return entries

    seen_tasks = set()

    for row in rows[1:]:
        if len(row) <= max(name_idx, status_idx if status_idx != -1 else 0):
            continue

        task_name = row[name_idx].strip()
        status = row[status_idx].strip() if status_idx != -1 else ""

        if not task_name or task_name == "TaskName":
            continue

        if task_name.startswith('\\Microsoft\\'):
            continue

        if task_name in seen_tasks:
            continue
        seen_tasks.add(task_name)

        if status.lower() in ("ready", "running", "hazir", "calisiyor"):
            entries.append({
                "location": "Scheduled Task",
                "name": task_name,
                "value": status
            })

    return entries

def check_autostart():
    alerts = []
    all_entries = []

    registry_entries = get_registry_autostart()
    startup_entries = get_startup_folder_items()
    task_entries = get_scheduled_tasks()

    all_entries.extend(registry_entries)
    all_entries.extend(startup_entries)
    all_entries.extend(task_entries)

    suspicious_entries = []
    for entry in all_entries:
        if not is_whitelisted(entry['name']):
            suspicious_entries.append(entry)

    if suspicious_entries:
        for entry in suspicious_entries:
            alerts.append({
                "severity": "MEDIUM",
                "message": f"Bilinmeyen baslangic ogesi: {entry['name']} ({entry['location']})",
                "detail": entry['value'][:200]
            })

    return alerts, all_entries

if __name__ == "__main__":
    print("HODOR Autostart taramasi baslatiliyor...\n")
    alerts, all_entries = check_autostart()

    print(f"Toplam {len(all_entries)} baslangic ogesi bulundu.\n")

    if alerts:
        print(f"{len(alerts)} bilinmeyen oge tespit edildi:\n")
        for a in alerts:
            print(f"[{a['severity']}] {a['message']}")
            print(f"  -> {a['detail']}")
    else:
        print("Tum baslangic ogeleri tanidik/guvenilir.")