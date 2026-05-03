# response/responder.py
import subprocess
import requests
import sqlite3
import json
from datetime import datetime
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SLACK_WEBHOOK_URL, AUTO_BLOCK_THRESHOLD, DB_PATH

# ── Database setup ──
def init_db():
    """Create incidents table if it doesn't exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            ip          TEXT,
            prediction  TEXT,
            severity    TEXT,
            confidence  REAL,
            vt_ratio    TEXT,
            abuse_score INTEGER,
            country     TEXT,
            asn         TEXT,
            is_blocked  INTEGER DEFAULT 0,
            slack_sent  INTEGER DEFAULT 0,
            notes       TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] Incidents table ready.")


def log_incident(detection: dict, enrichment: dict, blocked: bool, slack_sent: bool) -> int:
    """Save incident to SQLite. Returns the new incident ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        INSERT INTO incidents
        (timestamp, ip, prediction, severity, confidence,
         vt_ratio, abuse_score, country, asn, is_blocked, slack_sent)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        detection.get("timestamp"),
        enrichment.get("ip", "unknown"),
        detection.get("prediction"),
        detection.get("severity"),
        detection.get("confidence"),
        enrichment.get("vt_ratio", "N/A"),
        enrichment.get("abuse_score", 0),
        enrichment.get("country", "Unknown"),
        enrichment.get("as_owner", "Unknown"),
        int(blocked),
        int(slack_sent),
    ))
    conn.commit()
    incident_id = cursor.lastrowid
    conn.close()
    print(f"[DB] Incident saved → ID: INC-{incident_id:04d}")
    return incident_id


def block_ip_windows(ip: str) -> bool:
    """
    Block IP using Windows Firewall (netsh) — runs on your Windows host.
    Falls back gracefully if permissions are missing.
    """
    rule_name = f"SOAR_BLOCK_{ip}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "enable=yes"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"[RESPONDER] ✅ Windows Firewall rule added → BLOCK {ip}")
            return True
        else:
            print(f"[RESPONDER] ⚠️  Firewall rule failed: {result.stderr.strip()}")
            print(f"[RESPONDER] 💡 Try running terminal as Administrator")
            return False
    except Exception as e:
        print(f"[RESPONDER] ❌ block_ip error: {e}")
        return False


def block_ip_linux(ip: str) -> bool:
    """
    Block IP using iptables — run this on your Kali Linux VM.
    """
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"[RESPONDER] ✅ iptables rule added → BLOCK {ip}")
            return True
        else:
            print(f"[RESPONDER] ⚠️  iptables failed: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"[RESPONDER] ❌ iptables error: {e}")
        return False


def send_slack_alert(incident_id: int, detection: dict, enrichment: dict) -> bool:
    """Send Slack webhook notification. Skips silently if no webhook configured."""
    if not SLACK_WEBHOOK_URL:
        print("[RESPONDER] Slack webhook not configured — skipping.")
        return False

    emoji = {"critical": "🚨", "high": "🔴", "medium": "🟡"}.get(detection.get("severity",""), "⚠️")
    msg = {
        "text": (
            f"{emoji} *SOAR Alert — INC-{incident_id:04d}*\n"
            f">*Attack:* {detection.get('prediction')} "
            f"(conf: {detection.get('confidence')*100:.1f}%)\n"
            f">*IP:* `{enrichment.get('ip')}` — {enrichment.get('country')} / {enrichment.get('as_owner')}\n"
            f">*VT:* {enrichment.get('vt_ratio','N/A')} engines  |  "
            f"*AbuseIPDB:* {enrichment.get('abuse_score',0)}/100\n"
            f">*Action:* {'🛡️ IP BLOCKED' if enrichment.get('abuse_score',0) >= AUTO_BLOCK_THRESHOLD else '👁️ Flagged for review'}"
        )
    }
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=msg, timeout=5)
        if resp.status_code == 200:
            print(f"[RESPONDER] ✅ Slack alert sent → INC-{incident_id:04d}")
            return True
        else:
            print(f"[RESPONDER] ⚠️  Slack error: {resp.status_code}")
            return False
    except Exception as e:
        print(f"[RESPONDER] ❌ Slack error: {e}")
        return False


def respond(detection: dict, enrichment: dict, platform: str = "windows") -> dict:
    """
    Full response orchestrator.
    Decides whether to block based on abuse score + VT flags.
    """
    ip = enrichment.get("ip", "unknown")
    abuse_score = enrichment.get("abuse_score", 0)
    is_malicious = enrichment.get("is_malicious", False)

    blocked = False
    # Auto-block only if above threshold AND confirmed malicious
    if is_malicious and abuse_score >= AUTO_BLOCK_THRESHOLD:
        print(f"[RESPONDER] Auto-block triggered for {ip} (score={abuse_score})")
        if platform == "linux":
            blocked = block_ip_linux(ip)
        else:
            blocked = block_ip_windows(ip)
    else:
        print(f"[RESPONDER] Score {abuse_score} below threshold — flagging only.")

    # Log to DB
    incident_id = log_incident(detection, enrichment, blocked, slack_sent=False)

    # Send Slack alert
    slack_sent = send_slack_alert(incident_id, detection, enrichment)

    return {
        "incident_id": f"INC-{incident_id:04d}",
        "ip":          ip,
        "blocked":     blocked,
        "slack_sent":  slack_sent,
    }