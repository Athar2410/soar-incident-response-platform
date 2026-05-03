# enrichment/enricher.py
import requests
import time
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY,
                    VT_MALICIOUS_THRESHOLD, ABUSE_SCORE_THRESHOLD)

def query_virustotal(ip: str) -> dict:
    """Query VirusTotal for IP reputation."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values())
            country   = data.get("country", "Unknown")
            asn       = data.get("asn", "Unknown")
            as_owner  = data.get("as_owner", "Unknown")
            return {
                "vt_malicious":  malicious,
                "vt_total":      total,
                "vt_ratio":      f"{malicious}/{total}",
                "vt_flagged":    malicious >= VT_MALICIOUS_THRESHOLD,
                "country":       country,
                "asn":           asn,
                "as_owner":      as_owner,
                "vt_error":      None,
            }
        else:
            return {"vt_error": f"HTTP {resp.status_code}", "vt_flagged": False}
    except Exception as e:
        return {"vt_error": str(e), "vt_flagged": False}


def query_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for abuse confidence score."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            return {
                "abuse_score":   score,
                "abuse_flagged": score >= ABUSE_SCORE_THRESHOLD,
                "isp":           data.get("isp", "Unknown"),
                "domain":        data.get("domain", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "abuse_error":   None,
            }
        else:
            return {"abuse_error": f"HTTP {resp.status_code}", "abuse_flagged": False}
    except Exception as e:
        return {"abuse_error": str(e), "abuse_flagged": False}


def enrich_ip(ip: str) -> dict:
    """
    Full enrichment: query both APIs and return combined result.
    Respects VT rate limit (4 req/min) with a 16s delay.
    """
    print(f"[ENRICHER] Querying VirusTotal for {ip}...")
    vt_result = query_virustotal(ip)

    print(f"[ENRICHER] Waiting 16s for VT rate limit...")
    time.sleep(16)

    print(f"[ENRICHER] Querying AbuseIPDB for {ip}...")
    abuse_result = query_abuseipdb(ip)

    combined = {"ip": ip, **vt_result, **abuse_result}

    # Overall verdict
    combined["is_malicious"] = (
        combined.get("vt_flagged", False) or
        combined.get("abuse_flagged", False)
    )

    print(f"[ENRICHER] Done → malicious={combined['is_malicious']}")
    return combined