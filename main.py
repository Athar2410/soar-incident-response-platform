# main.py
import time
import random
from datetime import datetime
from detection.detector import classify_traffic, model
from enrichment.enricher import enrich_ip
from response.responder import init_db, respond

# ── Config ──
PLATFORM = "linux"   # change to "linux" when running on Kali
POLL_INTERVAL = 5      # seconds between checks in simulation mode

# ── Sample NSL-KDD feature vectors for simulation ──
# In Phase 5 (live traffic), Scapy will generate these from real packets
SAMPLE_EVENTS = [
    # Normal — typical HTTP request pattern
    ("normal", "8.8.8.8",
     [0,6,215,45296,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,0,0,0,0,0,0,0]),

    # DoS — high connection count, same host flooding
    ("dos", "185.220.101.47",
     [0,6,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,511,511,0,0,1,1,1,0,0,255,1,1,0,1,0,0,0,0,0]),

    # Probe — port scan pattern
    ("probe", "103.41.167.8",
     [0,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,229,0.28,0.28,0,0,0,0,0,0.28,0]),

    # Normal — DNS query
    ("normal", "1.1.1.1",
     [0,17,105,420,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,0,0,0,0,0,0,0]),

    # DoS — SYN flood
    ("dos", "45.142.212.100",
     [0,6,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,511,511,0,0,1,1,1,0,0,255,1,1,0,1,0,0,0,0,0]),
]


def process_event(ip: str, features: list) -> None:
    """Run one event through the full pipeline."""
    print(f"\n{'─'*55}")
    print(f"[PIPELINE] {datetime.now().strftime('%H:%M:%S')} — Processing {ip}")
    print(f"{'─'*55}")

    # ── Stage 1: Detect ──
    detection = classify_traffic(features)
    print(f"[DETECT]   {detection['prediction']} | "
          f"conf={detection['confidence']*100:.1f}% | "
          f"severity={detection['severity']}")

    if not detection["is_attack"]:
        print(f"[DETECT]   ✅ Normal traffic — no action needed.")
        return

    # ── Stage 2: Enrich ──
    print(f"[ENRICH]   Querying threat intel for {ip}...")
    enrichment = enrich_ip(ip)
    enrichment["ip"] = ip
    print(f"[ENRICH]   VT={enrichment.get('vt_ratio','N/A')} | "
          f"AbuseScore={enrichment.get('abuse_score',0)} | "
          f"Malicious={enrichment.get('is_malicious')}")

    # ── Stage 3: Respond ──
    print(f"[RESPOND]  Executing response actions...")
    result = respond(detection, enrichment, platform=PLATFORM)
    print(f"[RESPOND]  {result['incident_id']} | "
          f"blocked={result['blocked']} | "
          f"slack={result['slack_sent']}")


def run_simulation():
    """Simulate pipeline with sample events."""
    print("\n" + "═"*55)
    print("  SOAR PLATFORM — Simulation Mode")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  Press Ctrl+C to stop")
    print("═"*55)

    init_db()

    try:
        for label, ip, features in SAMPLE_EVENTS:
            process_event(ip, features)
            print(f"\n[PIPELINE] Waiting {POLL_INTERVAL}s before next event...")
            time.sleep(POLL_INTERVAL)

        print("\n[PIPELINE] ✅ All sample events processed.")
        print("[PIPELINE] Check logs/incidents.db for saved incidents.")

    except KeyboardInterrupt:
        print("\n[PIPELINE] Stopped by user.")


if __name__ == "__main__":
    run_simulation()