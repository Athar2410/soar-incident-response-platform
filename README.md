# 🛡️ SOAR Incident Response Platform

> An automated **Security Orchestration, Automation & Response (SOAR)** mini-platform that connects a Machine Learning-based Network Intrusion Detection System with real-time threat intelligence APIs and automated firewall response.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-F7931E?style=flat&logo=scikit-learn&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat&logo=sqlite&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=flat)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API-red?style=flat)

---

## 📌 Overview

This project implements a full **Detect → Enrich → Respond** security pipeline:

1. **Detect** — A trained Random Forest multiclass classifier (NSL-KDD dataset, 41 features) classifies network traffic into 5 categories: Normal, DoS, Probe, R2L, U2R
2. **Enrich** — Suspicious source IPs are automatically queried against VirusTotal and AbuseIPDB for reputation scoring, geolocation, and ASN data
3. **Respond** — High-confidence malicious IPs are auto-blocked via Windows Firewall (`netsh`) or Linux `iptables`, incidents are logged to SQLite, and Slack alerts are sent

---

## 🏗️ Architecture

```
soar_platform/
├── detection/
│   ├── detector.py          # ML model loader + classify_traffic()
│   ├── nids_model.pkl       # Trained Random Forest (rf_multiclass)
│   └── test_detector.py
├── enrichment/
│   ├── enricher.py          # VirusTotal + AbuseIPDB API queries
│   └── test_enricher.py
├── response/
│   ├── responder.py         # Firewall block + SQLite logging + Slack
│   └── test_responder.py
├── dashboard/
│   └── app.py               # Streamlit SOC dashboard (4 pages)
├── logs/
│   └── incidents.db         # SQLite incident database
├── main.py                  # Pipeline orchestrator
├── config.py                # API keys + thresholds
├── check_db.py              # Quick DB inspection utility
├── requirements.txt
└── .env                     # Secret keys (never commit)
```

---

## ⚙️ Pipeline Flow

```
[Network Traffic / Scapy Capture]
            │
            ▼
   ┌─────────────────┐
   │   1. DETECT     │  Random Forest Classifier
   │  41 NSL-KDD     │  5-class: Normal/DoS/Probe/R2L/U2R
   │    features     │  Confidence threshold: 50%
   └────────┬────────┘
            │ is_attack = True
            ▼
   ┌─────────────────┐
   │   2. ENRICH     │  VirusTotal API  → malicious engine count
   │  Threat Intel   │  AbuseIPDB API   → confidence score (0-100)
   │                 │  GeoIP + ASN     → country, ISP, owner
   └────────┬────────┘
            │ abuse_score >= 80
            ▼
   ┌─────────────────┐
   │   3. RESPOND    │  Windows: netsh advfirewall (host)
   │  Auto-Response  │  Linux:   iptables -I INPUT -j DROP (Kali VM)
   │                 │  SQLite:  incident logged to logs/incidents.db
   │                 │  Slack:   webhook alert to #soc-alerts
   └─────────────────┘
```

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.10+
- Windows (host) + Kali Linux on VMware (for live iptables blocking)
- Free API keys: [VirusTotal](https://www.virustotal.com) + [AbuseIPDB](https://www.abuseipdb.com/register)

### 1. Clone the Repository
```bash
git clone https://github.com/Athar2410/soar-incident-response-platform.git
cd soar-incident-response-platform
```

### 2. Create Virtual Environment
```bash
python -m venv soar_venv
# Windows:
soar_venv\Scripts\activate
# Linux/Kali:
source soar_venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API Keys
Create a `.env` file in the project root:
```
VT_API_KEY=your_virustotal_api_key_here
ABUSE_API_KEY=your_abuseipdb_api_key_here
SLACK_WEBHOOK=your_slack_webhook_url_here   # optional
```

### 5. Add Your NIDS Model
Place your trained model at:
```
detection/nids_model.pkl
```

### 6. Run the Pipeline
```bash
# Run as Administrator (Windows) for firewall rules
python main.py
```

### 7. Launch Dashboard
```bash
streamlit run dashboard/app.py
# Opens at http://localhost:8501
```

---

## 📊 Dashboard Pages

| Page | Description |
|------|-------------|
| 📊 Dashboard | KPI cards, attack type pie chart, severity bar chart, top IPs table |
| 🚨 Incidents | Filterable incident log with CSV export |
| 🔍 Enrichment | Abuse score vs VT detections scatter plot, per-IP threat summary |
| ⚙️ Pipeline | Architecture diagram, pipeline stats, current configuration |

---

## 🔧 Configuration

Edit `config.py` to tune thresholds:

| Setting | Default | Description |
|---------|---------|-------------|
| `VT_MALICIOUS_THRESHOLD` | 10 | Flag IP if ≥ 10 VT engines detect it |
| `ABUSE_SCORE_THRESHOLD` | 50 | Flag IP if AbuseIPDB score ≥ 50 |
| `AUTO_BLOCK_THRESHOLD` | 80 | Auto-block IP if AbuseIPDB score ≥ 80 |
| `PLATFORM` | `"windows"` | Set to `"linux"` on Kali for iptables |

---

## 🐧 Kali Linux — Live iptables Blocking

To use real `iptables` enforcement on your Kali VM:

1. Copy the project to Kali via VMware Shared Folders
2. Change `PLATFORM = "linux"` in `main.py`
3. Run with sudo:
```bash
sudo python main.py
```

The response module will execute:
```bash
sudo iptables -I INPUT -s <malicious_ip> -j DROP
```

To view all SOAR-created rules:
```bash
sudo iptables -L INPUT -n --line-numbers | grep SOAR
```

To remove all SOAR rules:
```bash
sudo iptables -D INPUT -s <ip> -j DROP
```

---

## 💬 Slack Alerts

To enable Slack notifications:

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → Create App → Incoming Webhooks
2. Enable webhooks → Add to a channel (e.g. `#soc-alerts`)
3. Copy the webhook URL into your `.env`:
```
SLACK_WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

Each auto-blocked IP triggers an alert like:
```
🚨 SOAR Alert — INC-0001
> Attack: DOS (conf: 97.0%)
> IP: 185.220.101.47 — DE / Stiftung Erneuerbare Freiheit
> VT: 15/91 engines  |  AbuseIPDB: 100/100
> Action: 🛡️ IP BLOCKED
```

---

## 📦 Tech Stack

| Component | Technology |
|-----------|------------|
| ML Model | scikit-learn RandomForestClassifier |
| Dataset | NSL-KDD (41 features, 5 classes) |
| Threat Intel | VirusTotal API v3, AbuseIPDB API v2 |
| Firewall | Windows netsh / Linux iptables |
| Database | SQLite (via Python sqlite3) |
| Dashboard | Streamlit + Plotly |
| Alerting | Slack Incoming Webhooks |
| HTTP | Python requests library |
| Scheduling | APScheduler (live mode) |

---

## 📈 Sample Results

| Metric | Value |
|--------|-------|
| Detection latency | < 0.5 seconds |
| Enrichment time | ~18 seconds (VT rate limit) |
| Total pipeline time | < 20 seconds per event |
| VT API usage | ~3 req/min (well within free 4/min limit) |
| Auto-block accuracy | Depends on AbuseIPDB threshold (default: score ≥ 80) |

---

## 🔮 Future Extensions

- [ ] **Live Scapy capture** — replace simulated events with real packet sniffing
- [ ] **MITRE ATT&CK mapping** — tag each alert with ATT&CK technique IDs
- [ ] **Email alerts** — SMTP notifications alongside Slack
- [ ] **Docker containerization** — package the platform for easy deployment
- [ ] **Suricata integration** — compare ML detections vs rule-based IDS
- [ ] **REST API** — expose pipeline as a Flask API for external integrations

---

## ⚠️ Disclaimer

This tool is built for **educational and research purposes only**. Only test on networks and systems you own or have explicit written permission to test. The author is not responsible for any misuse.

---

## 👤 Author

**Atharva Amle**
- GitHub: [@Athar2410](https://github.com/Athar2410)
- Project: SOAR Incident Response Platform

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.
