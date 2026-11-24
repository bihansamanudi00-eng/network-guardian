# Network Guardian configuration
# The app discovers available Npcap interfaces at runtime.
CAPTURE_FILTER = ""          # Empty means capture all packets visible to the selected adapter
WINDOW_SECONDS = 10
PORT_SCAN_THRESHOLD = 15     # Unique destination ports from one source in one window
REPEATED_DNS_THRESHOLD = 10  # Same queried domain in one window
MAX_DOMAIN_LENGTH = 100
MAX_LABEL_LENGTH = 50
MAX_SUBDOMAINS = 5
SUSPICIOUS_KEYWORDS = (
    "malware", "phishing", "botnet", "ransomware", "stealer", "command-control"
)
MIN_TRAINING_ROWS = 100
MODEL_PATH = "models/isolation_forest.joblib"
DATABASE_PATH = "data/network_guardian.db"
