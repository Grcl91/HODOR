import subprocess
from core.ip_intel import identify_ip, is_private_ip

def get_process_for_pid(pid):
    """Bir PID'nin hangi process'e ait oldugunu bulur"""
    try:
        result = subprocess.run(
            ['tasklist', '/FI', f'PID eq {pid}', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            name = result.stdout.split(',')[0].strip('"')
            return name if name else "Bilinmiyor"
        return "Process sonlanmis"
    except Exception:
        return "Sorgu basarisiz"

def get_process_path(pid):
    """Process'in tam dosya yolunu bulur (WMIC ile, daha detayli bilgi icin)"""
    try:
        result = subprocess.run(
            ['wmic', 'process', 'where', f'ProcessId={pid}', 'get', 'ExecutablePath'],
            capture_output=True, text=True, timeout=5
        )
        lines = [l.strip() for l in result.stdout.split('\n') if l.strip() and 'ExecutablePath' not in l]
        return lines[0] if lines else "Yol bulunamadi"
    except Exception:
        return "Sorgu basarisiz"

def investigate_unverified_connections(connections_text, max_investigate=5):
    """
    Dogrulanamamis (Bilinmiyor/Sorgu basarisiz) IP'lere baglanan
    process'leri otomatik tespit eder ve detayli rapor olusturur.
    Sadece az sayida supheli baglanti oldugu icin sistem yuku dusuktur.
    """
    findings = []
    investigated_ips = set()

    lines = connections_text.split('\n')
    for line in lines:
        if 'TCP' not in line and 'UDP' not in line:
            continue
        if 'ESTABLISHED' not in line and 'SYN_SENT' not in line:
            continue  # sadece aktif baglantilari incele, LISTENING/TIME_WAIT atla

        parts = line.strip().split()
        if len(parts) < 4:
            continue

        remote = parts[2]
        pid = parts[-1]

        if ':' not in remote:
            continue

        remote_ip = remote.rsplit(':', 1)[0].strip('[]')

        if is_private_ip(remote_ip) or remote_ip in ['0.0.0.0', '*']:
            continue

        if remote_ip in investigated_ips:
            continue

        org = identify_ip(remote_ip)

        # Sadece dogrulanamayan veya bilinmeyen IP'leri derinlemesine incele
        if org in ("Bilinmiyor", "Sorgu basarisiz") and len(findings) < max_investigate:
            investigated_ips.add(remote_ip)
            process_name = get_process_for_pid(pid)
            process_path = get_process_path(pid)

            findings.append({
                "ip": remote_ip,
                "org": org,
                "pid": pid,
                "process": process_name,
                "path": process_path,
                "raw_line": line.strip()
            })

    return findings

def format_findings(findings):
    """Bulgulari okunabilir rapor metnine cevirir"""
    if not findings:
        return "Dogrulanamamis IP'ye baglanan supheli process tespit edilmedi."

    report = []
    for f in findings:
        report.append(
            f"IP: {f['ip']} ({f['org']})\n"
            f"  Process: {f['process']} (PID: {f['pid']})\n"
            f"  Yol: {f['path']}"
        )
    return "\n\n".join(report)

if __name__ == "__main__":
    result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
    connections = result.stdout

    print("Dogrulanamamis IP baglantilari arastiriliyor...\n")
    findings = investigate_unverified_connections(connections)
    print(format_findings(findings))
