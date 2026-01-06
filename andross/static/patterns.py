import re

# ================================
# PATTERN REGEXES
# ================================
patterns = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "openai_key": re.compile(r"^sk-(live|test)?-[0-9a-zA-Z]{0,60}$"),
    "github_pat": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "stripe_secretkey": re.compile(r"^sk_(live|test)_[0-9A-Za-z]{24,48}$"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{8,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"),
    "basicauth_header": re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}\b"),
    "oauth_client_secret": re.compile(r"(?i)client_secret[\"'\s:=]{0,6}[A-Za-z0-9\-_\./+=]{8,100}"),
    "jdbc_mysql": re.compile(r"jdbc:mysql:\/\/[^\s'\";]+"),
    "mongodb_uri": re.compile(r"mongodb(?:\+srv)?:\/\/[^\s'\";]+"),
    "postgres_uri": re.compile(r"postgres(?:ql)?:\/\/[^\s'\";]+"),
    "redis_url": re.compile(r"redis:\/\/[^\s'\";]+"),
    "rds_endpoint": re.compile(r"[a-z0-9\-]+\.rds\.amazonaws\.com"),
    "internal_hostname": re.compile(r"\b(?:internal|staging|dev|qa|backend|admin|internal-api)[\.\-][A-Za-z0-9\.\-]*", flags=re.IGNORECASE),
    "private_ip": re.compile(r"\b(?:(?:10|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3})(?::\d{2,5})?\b"),
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "s3_url": re.compile(r"https?://s3[.-][a-z0-9-]+\.amazonaws\.com/[^\s'\"<>]+"),
    "api_key_in_query": re.compile(r"[?&](api_key|key|token|auth)[=][A-Za-z0-9\-_\.%]{8,200}"),
}

# ================================
# PATTERN UTILITIES
# ================================
def normalize_string(s):
    """Normalize string by stripping common quotes and whitespace
    
    Handles strings like: 'value', "value", `value`, value
    """
    s = s.strip()
    # Remove surrounding quotes if present
    if (s.startswith("'") and s.endswith("'")) or \
       (s.startswith('"') and s.endswith('"')) or \
       (s.startswith('`') and s.endswith('`')):
        s = s[1:-1]
    return s


def get_available_patterns():
    """Return list of available pattern names"""
    return list(patterns.keys())


def filter_by_pattern(strings, pattern_names):
    """Filter strings list by one or more pattern names
    
    Args:
        strings: List of string objects with format {"string": s, "dex": ..., "class": ..., "method": ...}
        pattern_names: Single pattern name (str), list of pattern names, or "all" to filter by all patterns
    
    Returns:
        Tuple of (filtered_list, applied_patterns) or (None, None) if pattern not found
    """
    # Convert single pattern to list
    if isinstance(pattern_names, str):
        pattern_names = [pattern_names]
    
    # Handle "all" special case - use all available patterns
    if "all" in pattern_names:
        applied_patterns = list(patterns.keys())
    else:
        applied_patterns = pattern_names
        # Validate all patterns exist
        invalid_patterns = [p for p in applied_patterns if p not in patterns]
        if invalid_patterns:
            return None, None
    
    filtered = []
    for s in strings:
        # Normalize the string value for pattern matching
        normalized_value = normalize_string(s["string"])
        
        # Check against each pattern
        for pattern_name in applied_patterns:
            regex = patterns[pattern_name]
            if regex.fullmatch(normalized_value):
                # Create a copy of the string object and add the pattern field
                matched_string = s.copy()
                matched_string["pattern"] = pattern_name
                filtered.append(matched_string)
                break  # Only add once even if matches multiple patterns
    
    return filtered, applied_patterns
