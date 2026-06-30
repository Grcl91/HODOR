# 🚪 HODOR
### Hold, Observe, Detect, Organize, Respond

> *"HODOR holds the door so threats can't get through."*

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

---

## What is HODOR?

HODOR is a **local, AI-powered cybersecurity agent** for home users. It runs entirely on your machine — no data ever leaves your computer. It monitors your system in real time, detects threats, and alerts you before damage is done.

Inspired by the Game of Thrones character who held the door against overwhelming odds, HODOR quietly stands guard at the critical points of your system — unnoticed, but always there.

---

## Why HODOR?

| | Commercial Tools | HODOR |
|---|---|---|
| Cost | Paid subscription | Free & open source |
| Data privacy | Cloud-based | 100% local |
| AI analysis | Rule-based only | Local LLM (Ollama) |
| Tor user protection | None | Built-in |
| Setup difficulty | Complex | Simple |

---

## Features

- **Real-time network monitoring** — tracks all active connections
- **Windows Event Log analysis** — detects failed logins, new users, privilege escalation
- **Autostart monitoring** — catches malware persistence attempts
- **AI-powered threat analysis** — local LLM via Ollama, no internet required
- **Real WHOIS-based IP verification** — no false alarms from known providers
- **Connection forensics** — identifies which process connects to unknown IPs
- **Desktop notifications** — instant alerts when threats are detected
- **Web dashboard** — beautiful real-time monitoring interface at `localhost:5000`
- **Tor-aware** — special detection rules for Tor browser users

---

## Requirements

- Windows 10/11
- Python 3.x
- [Ollama](https://ollama.com) with `llama3.1:8b` model
- Git

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Grcl91/HODOR.git
cd HODOR

# 2. Install dependencies
pip install flask requests plyer

# 3. Install and start Ollama
# Download from https://ollama.com
ollama pull llama3.1:8b

# 4. Create required folders
mkdir logs
mkdir alerts
```

---

## Usage

Open **3 terminals** and run:

**Terminal 1 — Ollama AI Engine:**
```powershell
$env:OLLAMA_MODELS = "C:\ollama-models"
ollama serve
```

**Terminal 2 — HODOR Main Agent:**
```powershell
cd C:\HODOR
python -m hodor
```

**Terminal 3 — Web Dashboard:**
```powershell
cd C:\HODOR
python dashboard.py
```

Then open your browser at: **http://localhost:5000**

---

## Project Structure

```
HODOR/
├── hodor.py                  # Main agent loop
├── dashboard.py              # Web dashboard (Flask)
├── core/
│   ├── threats.py            # Threat definitions & whitelists
│   ├── ip_intel.py           # Real-time WHOIS IP verification
│   ├── connection_forensics.py # Process-to-IP mapping
│   └── notifier.py           # Desktop notification system
├── monitors/
│   ├── monitor.py            # Network connection monitor
│   ├── event_monitor.py      # Windows Event Log monitor
│   └── autostart_monitor.py  # Startup/autostart monitor
└── analyzers/
    └── analyzer.py           # Rule-based threat analyzer
```

---

## Dashboard

HODOR includes a real-time web dashboard with:

- Threat level indicator
- Module status (Network, Event Log, Autostart, Forensics, IP Intel)
- Live IP verification table
- Connection forensics panel
- AI analysis results
- Full threat reports

---

## Threat Detection

HODOR detects:

- Brute force login attempts (Event ID 4625)
- New user account creation (Event ID 4720)
- Privilege escalation (Event ID 4728/4732)
- New services installed (Event ID 7045)
- Audit log cleared (Event ID 1102)
- Suspicious ports (4444, 1337, 31337, 3389, etc.)
- Known malware processes
- Port scanning activity
- Unverified IP connections with process identification
- Unknown autostart entries
- Tor traffic outside browser

---

## Roadmap

- [ ] Linux/macOS support
- [ ] Automatic threat response (block IP, kill process)
- [ ] Email/SMS alerts
- [ ] Historical threat timeline
- [ ] Multi-machine network monitoring
- [ ] Larger AI model support

---

## Contributing

Contributions are welcome! HODOR is just getting started.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

MIT License — free to use, modify and distribute.

---

## Acknowledgments

> *"HODOR" — Game of Thrones character who held the door against all odds.*
> 
> Just like him, this agent stands quietly at the door of your system,
> holding it shut so threats can't get through.

**Hold the door. 🚪**
