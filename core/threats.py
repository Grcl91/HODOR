# =====================================
# HODOR - Tehdit Tanimlama Modulu
# Hedef: Ev kullanicisi + Tor kullanan
# =====================================

WHITELIST_IPS = [
    # Microsoft
    "13.64.", "13.65.", "13.66.", "13.67.",
    "20.42.", "20.43.", "20.44.", "20.45.",
    "40.76.", "40.77.", "40.78.", "40.79.",
    # Cloudflare
    "1.1.1.1", "1.0.0.1",
    "162.159.", "104.16.", "104.17.",
    # Google
    "8.8.8.8", "8.8.4.4",
    "142.250.", "172.217.",
    # Windows Update
    "131.107.",
]

WHITELIST_PORTS = [
    7680,
    5353,
    1900,
]

WHITELIST_PROCESSES = [
    "svchost.exe",
    "System",
    "lsass.exe",
    "explorer.exe",
    "SearchHost.exe",
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
]

WHITELIST_SERVICES = [
    "claude",           # Claude Desktop
    "amustorage",       # USB surucusu
    "amusbstoru",       # USB surucusu
    "wuauserv",         # Windows Update
    "bits",             # Background Transfer
    "wscsvc",           # Windows Security
    "windefend",        # Windows Defender
]

SUSPICIOUS_PORTS = [
    4444, 1337, 31337, 8888, 9999,
    1234, 6666, 6667, 6668, 6669,
    1080, 3389, 5900, 23, 21,
]

TOR_PORTS = [9050, 9051, 9150, 9151]
TOR_EXIT_NODES = []

MALWARE_PROCESSES = [
    "cryptominer.exe",
    "xmrig.exe",
    "minerd.exe",
    "nmap.exe",
    "masscan.exe",
    "mimikatz.exe",
    "psexec.exe",
    "nc.exe",
    "ncat.exe",
]

SUSPICIOUS_BEHAVIORS = {
    "port_scan": {
        "description": "Port tarama tespit edildi",
        "threshold": 10,
        "severity": "HIGH"
    },
    "dns_leak": {
        "description": "DNS sizintisi",
        "severity": "HIGH"
    },
    "unexpected_rdp": {
        "description": "Beklenmedik RDP baglantisi",
        "severity": "CRITICAL"
    },
    "crypto_mining": {
        "description": "Kripto madenciligi aktivitesi",
        "severity": "HIGH"
    },
    "tor_outside_browser": {
        "description": "Tor trafigi tarayici disinda",
        "severity": "MEDIUM"
    }
}

THREAT_LEVELS = {
    "CRITICAL": "Hemen mudahale et! Sistemi izole et.",
    "HIGH": "Acil inceleme gerekli.",
    "MEDIUM": "Dikkatli izle, log tut.",
    "LOW": "Normal izlemeye devam et.",
    "CLEAN": "Sistem temiz. HODOR gorevde."
}
