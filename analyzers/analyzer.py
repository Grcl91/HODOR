import subprocess
from datetime import datetime
from core.threats import (
    WHITELIST_IPS, WHITELIST_PORTS, WHITELIST_PROCESSES,
    SUSPICIOUS_PORTS, MALWARE_PROCESSES, TOR_PORTS,
    SUSPICIOUS_BEHAVIORS, THREAT_LEVELS
)

def get_process_name(pid):
    try:
        result = subprocess.run(
            ['tasklist', '/FI', f'PID eq {pid}', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True
        )
        name = result.stdout.split(',')[0].strip('"')
        return name if name else "Bilinmiyor"
    except:
        return "Bilinmiyor"

def is_whitelisted_ip(ip):
    for safe_ip in WHITELIST_IPS:
        if ip.startswith(safe_ip):
            return True
    return False

def is_whitelisted_port(port):
    return int(port) in WHITELIST_PORTS

def is_whitelisted_process(process):
    return process.lower() in [p.lower() for p in WHITELIST_PROCESSES]

def analyze(connections, processes):
    alerts = []
    warnings = []
    info = []
    port_activity = {}

    lines = connections.split('\n')

    for line in lines:
        if 'TCP' not in line and 'UDP' not in line:
            continue

        parts = line.strip().split()
        if len(parts) < 4:
            continue

        pid = parts[-1] if parts else "?"
        proc = get_process_name(pid)

        # Whitelist process kontrolu
        if is_whitelisted_process(proc):
            continue

        # Yerel adres ve port
        local = parts[1] if len(parts) > 1 else ""
        remote = parts[2] if len(parts) > 2 else ""
        state = parts[3] if len(parts) > 3 else ""

        local_port = local.split(':')[-1] if ':' in local else ""
        remote_ip = remote.rsplit(':', 1)[0] if ':' in remote else ""
        remote_port = remote.split(':')[-1] if ':' in remote else ""

        # Whitelist IP kontrolu
        if is_whitelisted_ip(remote_ip):
            continue

        # Zararlı yazılım process kontrolu
        if proc.lower() in [m.lower() for m in MALWARE_PROCESSES]:
            alerts.append({
                "severity": "CRITICAL",
                "message": f"ZARARLI YAZILIM tespit edildi: {proc} (PID:{pid})",
                "detail": line.strip()
            })

        # Supheli port kontrolu
        try:
            if int(remote_port) in SUSPICIOUS_PORTS:
                alerts.append({
                    "severity": "HIGH",
                    "message": f"Supheli port {remote_port} - {proc} (PID:{pid})",
                    "detail": line.strip()
                })

            # Tor port kontrolu
            if int(remote_port) in TOR_PORTS or int(local_port) in TOR_PORTS:
                if not is_whitelisted_process(proc):
                    warnings.append({
                        "severity": "MEDIUM",
                        "message": f"Tor trafigi tarayici disinda: {proc} (PID:{pid})",
                        "detail": line.strip()
                    })

            # RDP kontrolu
            if int(remote_port) == 3389 or int(local_port) == 3389:
                alerts.append({
                    "severity": "CRITICAL",
                    "message": f"RDP baglantisi tespit edildi! {proc} (PID:{pid})",
                    "detail": line.strip()
                })

        except ValueError:
            pass

        # Port tarama tespiti
        if remote_ip and remote_ip not in ['0.0.0.0', '*']:
            if remote_ip not in port_activity:
                port_activity[remote_ip] = []
            port_activity[remote_ip].append(remote_port)

        # SYN_SENT kontrolu
        if 'SYN_SENT' in line and not is_whitelisted_process(proc):
            info.append({
                "severity": "LOW",
                "message": f"SYN_SENT - {proc} (PID:{pid}) -> {remote_ip}:{remote_port}",
                "detail": line.strip()
            })

    # Port tarama kontrolu
    for ip, ports in port_activity.items():
        if len(ports) >= SUSPICIOUS_BEHAVIORS["port_scan"]["threshold"]:
            alerts.append({
                "severity": "HIGH",
                "message": f"PORT TARAMA tespit edildi! {ip} -> {len(ports)} port",
                "detail": f"Portlar: {', '.join(set(ports))}"
            })

    return alerts, warnings, info

def print_report(alerts, warnings, info):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*45}")
    print(f"HODOR TEHDIT RAPORU - {timestamp}")
    print(f"{'='*45}")

    if alerts:
        print("\n!! KRITIK/YUKSEK UYARILAR !!")
        for a in alerts:
            print(f"[{a['severity']}] {a['message']}")
            print(f"  -> {a['detail']}")
    else:
        print("\nKritik tehdit yok.")

    if warnings:
        print("\n! UYARILAR !")
        for w in warnings:
            print(f"[{w['severity']}] {w['message']}")
    
    if info:
        print("\n-- Bilgi --")
        for i in info:
            print(f"[{i['severity']}] {i['message']}")

    if not alerts and not warnings and not info:
        print("\nSistem tamamen temiz. HODOR gorevde! 🚪")

    print(f"{'='*45}\n")
