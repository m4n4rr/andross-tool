import re

# ================================
# PATTERN REGEXES
# ================================
patterns = {
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "OpenAI Key": re.compile(r"^sk-(live|test)?-[0-9a-zA-Z]{0,60}$"),
    "GitHub PAT (ghp_)": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "Stripe Secret Key": re.compile(r"^sk_(live|test)_[0-9A-Za-z]{24,48}$"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{8,}"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"),
    "BasicAuth (Base64) header": re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}\b"),
    "OAuth client_secret (param)": re.compile(r"(?i)client_secret[\"'\s:=]{0,6}[A-Za-z0-9\-_\./+=]{8,100}"),
    "JDBC MySQL": re.compile(r"jdbc:mysql:\/\/[^\s'\";]+"),
    "MongoDB URI": re.compile(r"mongodb(?:\+srv)?:\/\/[^\s'\";]+"),
    "Postgres URI": re.compile(r"postgres(?:ql)?:\/\/[^\s'\";]+"),
    "Redis URL": re.compile(r"redis:\/\/[^\s'\";]+"),
    "RDS Endpoint (heuristic)": re.compile(r"[a-z0-9\-]+\.rds\.amazonaws\.com"),
    "Internal Hostname (heuristic)": re.compile(r"\b(?:internal|staging|dev|qa|backend|admin|internal-api)[\.\-][A-Za-z0-9\.\-]*", flags=re.IGNORECASE),
    "Private IP:Port (RFC1918)": re.compile(r"\b(?:(?:10|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3})(?::\d{2,5})?\b"),
    "Email (heuristic)": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "S3 URL (heuristic)": re.compile(r"https?://s3[.-][a-z0-9-]+\.amazonaws\.com/[^\s'\"<>]+"),
    "API key in query (heuristic)": re.compile(r"[?&](api_key|key|token|auth)[=][A-Za-z0-9\-_\.%]{8,200}"),
}

# ================================
# DETECT PATTERNS
# ================================
def detect_patterns(strings):
    print("\n=== Pattern Detection ===\n")
    for s in strings:
        for name, regex in patterns.items():
            if regex.fullmatch(s["string"]):
                source = s.get('dex') or s.get('source') or 'unknown'
                print(f"[{name}] {s['string']} ({source})")
                break
