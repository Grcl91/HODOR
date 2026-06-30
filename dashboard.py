from flask import Flask, jsonify, render_template_string
import json
import os
from datetime import datetime

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>HODOR - Security Dashboard</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #00ff41; font-family: 'Courier New', monospace; }
        .header { background: #111; padding: 20px; border-bottom: 2px solid #00ff41; text-align: center; }
        .header h1 { font-size: 2em; letter-spacing: 5px; }
        .header p { color: #666; margin-top: 5px; }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }
        .card { background: #111; border: 1px solid #00ff41; border-radius: 8px; padding: 20px; }
        .card h3 { color: #00ff41; margin-bottom: 10px; font-size: 0.8em; letter-spacing: 2px; }
        .card .value { font-size: 2.2em; font-weight: bold; }
        .clean { color: #00ff41; }
        .warning { color: #ffaa00; }
        .critical { color: #ff0000; }
        .panel { background: #111; border: 1px solid #333; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .panel h2 { color: #00ff41; margin-bottom: 15px; letter-spacing: 3px; border-bottom: 1px solid #333; padding-bottom: 10px; font-size: 1.1em; }
        .panel h2 .icon { margin-right: 8px; }
        .status-bar { background: #111; border: 1px solid #00ff41; border-radius: 8px; padding: 15px 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
        .pulse { display: inline-block; width: 10px; height: 10px; background: #00ff41; border-radius: 50%; margin-right: 8px; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        pre { white-space: pre-wrap; word-wrap: break-word; font-size: 0.8em; color: #aaa; max-height: 400px; overflow-y: auto; }
        .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 800px) { .two-col { grid-template-columns: 1fr; } .grid { grid-template-columns: repeat(2, 1fr); } }
        .module-status { display: flex; align-items: center; gap: 8px; padding: 8px 0; border-bottom: 1px solid #1a1a1a; font-size: 0.85em; }
        .module-status:last-child { border-bottom: none; }
        .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
        .dot-clean { background: #00ff41; }
        .dot-warning { background: #ffaa00; }
        .dot-critical { background: #ff0000; }
        .ip-list { font-size: 0.8em; }
        .ip-row { display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #1a1a1a; }
        .ip-addr { color: #888; }
        .ip-org { color: #00ff41; }
        .ip-org.unverified { color: #ffaa00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚪 HODOR</h1>
        <p>Hold, Observe, Detect, Organize, Respond</p>
        <p style="color:#444; font-size:0.8em; margin-top:5px;">HODOR holds the door so threats can't get through</p>
    </div>

    <div class="container">
        <div class="status-bar">
            <div><span class="pulse"></span> HODOR AKTIF - Sistem Izleniyor</div>
            <div style="color:#666;">Son guncelleme: {{ timestamp }}</div>
            <div style="color:#666;">Otomatik yenileme: 30 saniye</div>
        </div>

        <div class="grid">
            <div class="card">
                <h3>TEHDIT DURUMU</h3>
                <div class="value {{ threat_class }}">{{ threat_level }}</div>
            </div>
            <div class="card">
                <h3>TOPLAM TARAMA</h3>
                <div class="value clean">{{ scan_count }}</div>
            </div>
            <div class="card">
                <h3>UYARI SAYISI</h3>
                <div class="value {{ 'critical' if alert_count > 0 else 'clean' }}">{{ alert_count }}</div>
            </div>
            <div class="card">
                <h3>DOGRULANMIS IP</h3>
                <div class="value clean">{{ verified_ip_count }}</div>
            </div>
        </div>

        <div class="panel">
            <h2><span class="icon">🛡️</span>MODUL DURUMU</h2>
            <div class="module-status">
                <span class="dot {{ network_dot }}"></span>
                <strong>Ag Izleme:</strong>&nbsp;{{ network_status }}
            </div>
            <div class="module-status">
                <span class="dot {{ event_dot }}"></span>
                <strong>Event Log:</strong>&nbsp;{{ event_status }}
            </div>
            <div class="module-status">
                <span class="dot {{ autostart_dot }}"></span>
                <strong>Autostart:</strong>&nbsp;{{ autostart_status }}
            </div>
            <div class="module-status">
                <span class="dot dot-clean"></span>
                <strong>IP Dogrulama:</strong>&nbsp;Aktif ({{ verified_ip_count }} IP kontrol edildi)
            </div>
        </div>

        <div class="two-col">
            <div class="panel">
                <h2><span class="icon">🔌</span>BASLANGIC OGELERI (AUTOSTART)</h2>
                <pre>{{ autostart_report }}</pre>
            </div>
            <div class="panel">
                <h2><span class="icon">🌐</span>IP DOGRULAMA</h2>
                <div class="ip-list">{{ ip_intel_html|safe }}</div>
            </div>
        </div>

        <div class="panel">
            <h2><span class="icon">📋</span>SON TEHDIT RAPORU</h2>
            <pre>{{ last_report }}</pre>
        </div>

        <div class="panel">
            <h2><span class="icon">🧠</span>AI ANALIZ</h2>
            <pre>{{ ai_report }}</pre>
        </div>
    </div>
</body>
</html>
"""

def get_dashboard_data():
    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threat_level": "TEMIZ",
        "threat_class": "clean",
        "scan_count": 0,
        "alert_count": 0,
        "verified_ip_count": 0,
        "last_report": "Henuz rapor yok.",
        "ai_report": "Henuz AI analizi yok.",
        "autostart_report": "Henuz autostart taramasi yapilmadi.",
        "ip_intel_html": "<p style='color:#666'>Henuz IP verisi yok.</p>",
        "network_status": "Bekleniyor...",
        "network_dot": "dot-clean",
        "event_status": "Bekleniyor...",
        "event_dot": "dot-clean",
        "autostart_status": "Bekleniyor...",
        "autostart_dot": "dot-clean",
    }

    if os.path.exists("alerts/report.txt"):
        with open("alerts/report.txt", "r", encoding="utf-8") as f:
            content = f.read()
            reports = content.split("="*45)
            reports = [r.strip() for r in reports if r.strip()]

            if reports:
                data["last_report"] = reports[-1][:2500]
                last_section = reports[-1]
            else:
                last_section = ""

            data["scan_count"] = content.count("HODOR RAPORU")
            data["alert_count"] = content.count("[CRITICAL]") + content.count("[HIGH]")

            if "[CRITICAL]" in last_section:
                data["threat_level"] = "KRITIK"
                data["threat_class"] = "critical"
            elif "[HIGH]" in last_section:
                data["threat_level"] = "YUKSEK"
                data["threat_class"] = "critical"
            elif "[MEDIUM]" in last_section:
                data["threat_level"] = "ORTA"
                data["threat_class"] = "warning"

            # AG ANALIZI durumu
            if "[AG ANALIZI]" in last_section:
                ag_part = last_section.split("[AG ANALIZI]")[1].split("[EVENT LOG")[0] if "[EVENT LOG" in last_section else last_section.split("[AG ANALIZI]")[1][:200]
                if "Kritik ag tehdidi yok" in ag_part:
                    data["network_status"] = "Temiz - Kritik tehdit yok"
                    data["network_dot"] = "dot-clean"
                else:
                    data["network_status"] = "Uyarilar mevcut"
                    data["network_dot"] = "dot-critical"

            # EVENT LOG durumu
            if "[EVENT LOG ANALIZI]" in last_section:
                event_part = last_section.split("[EVENT LOG ANALIZI]")[1].split("[AUTOSTART")[0] if "[AUTOSTART" in last_section else last_section.split("[EVENT LOG ANALIZI]")[1][:200]
                if "Supheli event log aktivitesi yok" in event_part:
                    data["event_status"] = "Temiz - Supheli aktivite yok"
                    data["event_dot"] = "dot-clean"
                else:
                    data["event_status"] = "Uyarilar mevcut"
                    data["event_dot"] = "dot-warning"

            # AUTOSTART durumu
            if "[AUTOSTART ANALIZI]" in last_section:
                autostart_part = last_section.split("[AUTOSTART ANALIZI]")[1].split("[IP DOGRULAMA]")[0] if "[IP DOGRULAMA]" in last_section else last_section.split("[AUTOSTART ANALIZI]")[1][:500]
                data["autostart_report"] = autostart_part.strip()[:1000]
                if "tanidik/guvenilir" in autostart_part:
                    data["autostart_status"] = "Temiz - Tum ogeler tanidik"
                    data["autostart_dot"] = "dot-clean"
                else:
                    data["autostart_status"] = "Bilinmeyen ogeler tespit edildi"
                    data["autostart_dot"] = "dot-warning"
            else:
                data["autostart_report"] = "Bu taramada autostart kontrolu yapilmadi (her 10 dongude bir calisir)."

            # IP DOGRULAMA
            if "[IP DOGRULAMA]" in last_section:
                ip_part = last_section.split("[IP DOGRULAMA]")[1].split("[AI ANALIZ]")[0] if "[AI ANALIZ]" in last_section else last_section.split("[IP DOGRULAMA]")[1]
                ip_lines = [l.strip() for l in ip_part.strip().split('\n') if '=' in l]
                data["verified_ip_count"] = len(ip_lines)

                rows = ""
                for line in ip_lines[:20]:
                    if '=' in line:
                        ip, org = line.split('=', 1)
                        ip = ip.strip()
                        org = org.strip()
                        org_class = "unverified" if org in ("Bilinmiyor", "Sorgu basarisiz", "Bilinmiyor", "") else ""
                        rows += f'<div class="ip-row"><span class="ip-addr">{ip}</span><span class="ip-org {org_class}">{org}</span></div>'
                data["ip_intel_html"] = rows if rows else "<p style='color:#666'>Dis baglanti yok.</p>"

            # AI raporu
            if "[AI ANALIZ]" in last_section:
                ai_part = last_section.split("[AI ANALIZ]")[1].strip()
                data["ai_report"] = ai_part[:1500]

    return data

@app.route("/")
def dashboard():
    data = get_dashboard_data()
    return render_template_string(HTML, **data)

@app.route("/api/status")
def api_status():
    return jsonify(get_dashboard_data())

if __name__ == "__main__":
    print("HODOR Dashboard baslatiliyor...")
    print("Tarayicida ac: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
