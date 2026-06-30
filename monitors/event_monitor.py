import subprocess
from datetime import datetime
from core.threats import WHITELIST_SERVICES

EVENT_IDS = {
    4625: {"desc": "Basarisiz giris denemesi", "severity": "HIGH"},
    4624: {"desc": "Basarili giris", "severity": "LOW"},
    4720: {"desc": "Yeni kullanici olusturuldu", "severity": "CRITICAL"},
    4726: {"desc": "Kullanici silindi", "severity": "HIGH"},
    4728: {"desc": "Kullanici admin grubuna eklendi", "severity": "CRITICAL"},
    4732: {"desc": "Kullanici yerel gruba eklendi", "severity": "HIGH"},
    4756: {"desc": "Kullanici evrensel gruba eklendi", "severity": "HIGH"},
    4698: {"desc": "Yeni zamanlanmis gorev olusturuldu", "severity": "HIGH"},
    4702: {"desc": "Zamanlanmis gorev guncellendi", "severity": "MEDIUM"},
    7045: {"desc": "Yeni servis yuklendi", "severity": "HIGH"},
    1102: {"desc": "Audit log temizlendi", "severity": "CRITICAL"},
    4719: {"desc": "Sistem audit politikasi degistirildi", "severity": "CRITICAL"},
    4946: {"desc": "Firewall kurali eklendi", "severity": "HIGH"},
}

SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz", "psexec", "wce.exe", "fgdump",
    "pwdump", "procdump", "nc.exe", "ncat.exe",
    "xmrig", "minerd"
]

def get_events(event_id, log="Security"):
    try:
        cmd = ['wevtutil', 'qe', log,
               f'/q:*[System[EventID={event_id}]]',
               '/f:text', '/rd:true', '/c:10']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout
    except:
        return ""

def is_whitelisted_service(service_name):
    service_lower = service_name.lower()
    for ws in WHITELIST_SERVICES:
        if ws.lower() in service_lower:
            return True
    return False

def check_failed_logins():
    alerts = []
    content = get_events(4625)
    if content and "Event[" in content:
        count = content.count("Event[")
        if count >= 5:
            alerts.append({
                "severity": "CRITICAL",
                "message": f"BRUTE FORCE! {count} basarisiz giris denemesi!",
                "detail": content[:300]
            })
        elif count > 0:
            alerts.append({
                "severity": "HIGH",
                "message": f"{count} basarisiz giris denemesi tespit edildi",
                "detail": content[:300]
            })
    return alerts

def check_new_users():
    alerts = []
    content = get_events(4720)
    if content and "Event[" in content:
        alerts.append({
            "severity": "CRITICAL",
            "message": "Yeni kullanici hesabi olusturuldu!",
            "detail": content[:300]
        })
    return alerts

def check_admin_changes():
    alerts = []
    for event_id in [4728, 4732, 4756]:
        content = get_events(event_id)
        if content and "Event[" in content:
            alerts.append({
                "severity": "CRITICAL",
                "message": f"{EVENT_IDS[event_id]['desc']} tespit edildi!",
                "detail": content[:300]
            })
    return alerts

def check_new_services():
    alerts = []
    content = get_events(7045, log="System")
    if content and "Event[" in content:
        lines = content.split('\n')
        service_name = ""
        for line in lines:
            if "Hizmet Adi" in line or "Service Name" in line:
                service_name = line.split(":")[-1].strip()
                break
        if service_name and not is_whitelisted_service(service_name):
            alerts.append({
                "severity": "HIGH",
                "message": f"Bilinmeyen servis yuklendi: {service_name}",
                "detail": content[:300]
            })
    return alerts

def check_audit_cleared():
    alerts = []
    content = get_events(1102)
    if content and "Event[" in content:
        alerts.append({
            "severity": "CRITICAL",
            "message": "KRITIK: Audit loglar temizlendi! Saldiri izleri silinmis olabilir!",
            "detail": content[:300]
        })
    return alerts

def check_scheduled_tasks():
    alerts = []
    content = get_events(4698)
    if content and "Event[" in content:
        alerts.append({
            "severity": "HIGH",
            "message": "Yeni zamanlanmis gorev olusturuldu! Zararlı yazılım kalici olabilir.",
            "detail": content[:300]
        })
    return alerts

def check_suspicious_processes():
    alerts = []
    try:
        result = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                                capture_output=True, text=True)
        processes = result.stdout.lower()
        for proc in SUSPICIOUS_PROCESS_NAMES:
            if proc.lower() in processes:
                alerts.append({
                    "severity": "CRITICAL",
                    "message": f"ZARARLI YAZILIM tespit edildi: {proc}",
                    "detail": f"Process listesinde {proc} bulundu!"
                })
    except:
        pass
    return alerts

def run_event_log_check():
    all_alerts = []
    print("  [EVENT LOG] Kontrol ediliyor...")
    all_alerts.extend(check_failed_logins())
    all_alerts.extend(check_new_users())
    all_alerts.extend(check_admin_changes())
    all_alerts.extend(check_new_services())
    all_alerts.extend(check_audit_cleared())
    all_alerts.extend(check_scheduled_tasks())
    all_alerts.extend(check_suspicious_processes())
    return all_alerts

if __name__ == "__main__":
    print("Windows Event Log analizi baslatiliyor...\n")
    alerts = run_event_log_check()
    if alerts:
        print(f"{len(alerts)} olay tespit edildi:\n")
        for a in alerts:
            print(f"[{a['severity']}] {a['message']}")
    else:
        print("Temiz - Supheli event log aktivitesi yok.")
