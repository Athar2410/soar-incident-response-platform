# response/test_responder.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from response.responder import init_db, respond

# Init DB first
init_db()

# Simulate a detection + enrichment result
mock_detection = {
    "timestamp":  "2026-05-03 01:00:00",
    "label_id":   1,
    "prediction": "DOS",
    "confidence": 0.97,
    "is_attack":  True,
    "severity":   "critical",
}
mock_enrichment = {
    "ip":          "185.220.101.47",
    "vt_malicious": 15,
    "vt_total":     91,
    "vt_ratio":    "15/91",
    "vt_flagged":   True,
    "country":     "DE",
    "asn":          60729,
    "as_owner":    "Stiftung Erneuerbare Freiheit",
    "abuse_score":  100,
    "abuse_flagged": True,
    "isp":         "Network for Tor-Exit traffic.",
    "is_malicious": True,
}

result = respond(mock_detection, mock_enrichment, platform="windows")

print("\n── Response Result ──")
for k, v in result.items():
    print(f"  {k}: {v}")