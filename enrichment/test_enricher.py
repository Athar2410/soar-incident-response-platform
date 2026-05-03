# enrichment/test_enricher.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from enrichment.enricher import enrich_ip

# Known malicious Tor exit node — safe to test with
test_ip = "185.220.101.47"
print(f"Testing enrichment for: {test_ip}\n")

result = enrich_ip(test_ip)

print("\n── Enrichment Result ──")
for k, v in result.items():
    print(f"  {k}: {v}")