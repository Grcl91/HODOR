import subprocess
import requests
import time
from datetime import datetime
from core.threats import THREAT_LEVELS
from core.notifier import alert_critical, alert_warning, alert_info
from core.ip_intel import identify_ip, is_private_ip
from core.connection_forensics import investigate_unverified_connections, format_findings
from analyzers.analyzer import analyze, print_report
from monitors.event_monitor import run_event_log_check
from monitors.autostart_monitor import check_autostart

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "llama3.1:8b"
SCAN_INTERVAL = 60
AUTOSTART_CHECK_EVERY = 10

def banner():
    print("========================================")
    print("  HODOR - Hold, Observe, Detect,")
    print("          Organize, Respond")
    print("  HODOR holds the door so threats")
    print("  can't get through.")
    print("========================================\n")

def get_connections():
    result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
    return result.stdout

def get_processes():
    result = subprocess.run(['tasklist'], capture_output=True, text=True)
    return result.stdout

def log_activity(data, filename):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(f"logs/{filename}", "a", encoding="utf-8") as f:
        f.write(f"\n[{timestamp}]\n{data}\n")

def extract_remote_ips(connections_text):
    ips = set()
    for line in connections_text.split('\n'):
        if 'ESTABLISHED' not in line and 'SYN_SENT' not in line and 'TIME_WAIT' not in line:
            continue
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        remote = parts[2]
        if ':' in remote:
            ip = remote.rsplit(':', 1)[0].strip('[]')
            if not is_private_ip(ip) and ip not in ['0.0.0.0', '*']:
                ips.add(ip)
    return ips

def build_ip_intel_summary(ips):
    if not ips:
        return "Dis baglanti yok."

    summary = []
    for ip in list(ips)[:15]:
        org = identify_ip(ip)
        summary.append(f"{ip} = {org}")
    return "\n".join(summary)

def ai_analysis(connections, event_alerts, ip_intel, autostart_alerts, forensics_summary):
    print("  [AI] Dusunuyor...", end="", flush=True)

    event_summary = "\n".join([f"- {a['message']}" for a in event_alerts]) if event_alerts else "Supheli event log aktivitesi yok."
    autostart_summary = "\n".join([f"- {a['message']}" for a in autostart_alerts]) if autostart_alerts else "Tum baslangic ogeleri tanidik."

    prompt = f"""You are HODOR, a careful and precise cybersecurity AI agent protecting a home user.

CRITICAL RULES:
1. You have been given VERIFIED IP ownership data below (from real WHOIS lookups). TRUST this data completely - do not guess or contradict it.
2. If an IP is identified as Microsoft, Google, Cloudflare, Akamai, Amazon, or Apple - it is a LEGITIMATE company, NOT malware C2, even if you don't recognize the specific service.
3. NEVER claim an IP is a "known malware C2 server" unless you have explicit evidence. If unsure, say "requires further investigation" instead of making definitive claims.
4. Only flag IPs marked as "Bilinmiyor" or "Sorgu basarisiz" (unverified) as potentially worth investigating, and even then use cautious language like "unverified, worth monitoring" rather than alarming claims.
5. Standard Windows ports (135, 445, 139) being open locally is NORMAL Windows behavior, not a threat by itself.
6. CONNECTION FORENSICS DATA below shows the actual process name and file path for any connections to unverified IPs - use this real data instead of speculating about what process might be responsible.

VERIFIED IP OWNERSHIP DATA:
{ip_intel}

CONNECTION FORENSICS (process behind unverified IPs):
{forensics_summary}

Network connections (raw):
{connections[:1200]}

System Events:
{event_summary}

Autostart/Startup Items:
{autostart_summary}

Respond in this format:
THREAT LEVEL: (LOW/MEDIUM/HIGH/CRITICAL)
SUSPICIOUS: (only list items with unverified/unknown IPs, or genuine anomalies - say NONE if everything checks out)
RECOMMENDATION: (brief, proportionate action - don't recommend disconnecting from the internet unless truly critical)"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=300
        )
        print(" Tamamlandi!")
        return response.json().get("response", "Cevap alinamadi.")
    except Exception as e:
        print(" Hata!")
        return f"AI baglanti hatasi: {e}"

def save_report(alerts, warnings, info, event_alerts, autostart_alerts, ip_intel, forensics_summary, ai_result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"\n{'='*45}\nHODOR RAPORU - {timestamp}\n{'='*45}\n"

    report += "\n[AG ANALIZI]\n"
    if alerts:
        for a in alerts:
            report += f"[{a['severity']}] {a['message']}\n  -> {a['detail']}\n"
    else:
        report += "Kritik ag tehdidi yok.\n"

    report += "\n[EVENT LOG ANALIZI]\n"
    if event_alerts:
        for a in event_alerts:
            report += f"[{a['severity']}] {a['message']}\n"
    else:
        report += "Supheli event log aktivitesi yok.\n"

    report += "\n[AUTOSTART ANALIZI]\n"
    if autostart_alerts:
        for a in autostart_alerts:
            report += f"[{a['severity']}] {a['message']}\n  -> {a['detail']}\n"
    else:
        report += "Tum baslangic ogeleri tanidik/guvenilir.\n"

    report += f"\n[IP DOGRULAMA]\n{ip_intel}\n"

    report += f"\n[BAGLANTI ADLI ANALIZI]\n{forensics_summary}\n"

    if ai_result:
        report += f"\n[AI ANALIZ]\n{ai_result}\n"

    report += f"{'='*45}\n"

    with open("alerts/report.txt", "a", encoding="utf-8") as f:
        f.write(report)

    return report

def hodor():
    banner()
    alert_info("HODOR aktif ve gorevde!")
    scan_count = 0
    last_autostart_alerts = []

    while True:
        scan_count += 1
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] Tarama #{scan_count} basliyor...")

        connections = get_connections()
        processes = get_processes()

        log_activity(connections, "connections.log")
        log_activity(processes, "processes.log")

        alerts, warnings, info = analyze(connections, processes)
        event_alerts = run_event_log_check()

        if scan_count % AUTOSTART_CHECK_EVERY == 0 or scan_count == 1:
            print("  [AUTOSTART] Baslangic ogeleri kontrol ediliyor...")
            autostart_alerts, _ = check_autostart()
            last_autostart_alerts = autostart_alerts
        else:
            autostart_alerts = last_autostart_alerts

        print("  [IP INTEL] Dis IP'ler dogrulaniyor...")
        remote_ips = extract_remote_ips(connections)
        ip_intel = build_ip_intel_summary(remote_ips)

        print("  [FORENSICS] Dogrulanamamis baglantilar arastiriliyor...")
        forensics_findings = investigate_unverified_connections(connections)
        forensics_summary = format_findings(forensics_findings)

        if alerts:
            for a in alerts:
                alert_critical(a['message'][:100])
        elif forensics_findings:
            alert_warning(f"{len(forensics_findings)} dogrulanamamis baglanti incelendi, detaylar raporda")
        elif autostart_alerts:
            alert_warning(f"{len(autostart_alerts)} bilinmeyen baslangic ogesi tespit edildi")
        elif event_alerts:
            critical_events = [e for e in event_alerts if e['severity'] == 'CRITICAL']
            high_events = [e for e in event_alerts if e['severity'] == 'HIGH']
            if critical_events:
                alert_critical(critical_events[0]['message'][:100])
            elif high_events:
                alert_warning(high_events[0]['message'][:100])
        elif warnings:
            for w in warnings:
                alert_warning(w['message'][:100])

        ai_result = ""
        if scan_count % 5 == 0 or scan_count == 1:
            print("  [AI] Analiz baslatiliyor...")
            ai_result = ai_analysis(connections, event_alerts, ip_intel, autostart_alerts, forensics_summary)
            if "THREAT LEVEL: CRITICAL" in ai_result:
                alert_critical("AI KRITIK TEHDIT tespit etti!")
            elif "THREAT LEVEL: HIGH" in ai_result:
                alert_warning("AI YUKSEK tehdit tespit etti!")

        print_report(alerts, warnings, info)

        if event_alerts:
            print("\n[EVENT LOG UYARILARI]")
            for e in event_alerts:
                print(f"[{e['severity']}] {e['message']}")

        if autostart_alerts:
            print("\n[AUTOSTART UYARILARI]")
            for a in autostart_alerts:
                print(f"[{a['severity']}] {a['message']}")

        print(f"\n[IP INTEL]\n{ip_intel}")

        if forensics_findings:
            print(f"\n[BAGLANTI ADLI ANALIZI]\n{forensics_summary}")

        save_report(alerts, warnings, info, event_alerts, autostart_alerts, ip_intel, forensics_summary, ai_result)

        print(f"\nSonraki tarama {SCAN_INTERVAL} saniye sonra...\n")
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    hodor()
