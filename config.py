# config.py
import os
from dotenv import load_dotenv
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY  = os.getenv("ABUSE_API_KEY")
SLACK_WEBHOOK_URL  = os.getenv("SLACK_WEBHOOK", "")   # optional for now

# Thresholds
VT_MALICIOUS_THRESHOLD   = 10   # flag if >10 engines detect it
ABUSE_SCORE_THRESHOLD    = 50   # flag if score >50
AUTO_BLOCK_THRESHOLD     = 80   # auto-block if abuse score >80

# Paths
DB_PATH              = "logs/incidents.db"
MODEL_PATH           = "detection/rf_multiclass.pkl"