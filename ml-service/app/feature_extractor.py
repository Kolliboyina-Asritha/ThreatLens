"""
ThreatLens AI - Python URL Feature Extractor
Extracts the exact 18-dimension feature vector matching the Node.js URL Analyzer.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "bank",
    "password", "credential", "confirm", "wallet", "payment",
    "billing", "authenticate", "authentication", "webscr",
    "ebayisapi", "banking", "recover", "unlock", "validation"
]

KNOWN_TWO_PART_SUFFIXES = {
    "co.uk", "com.br", "gov.uk", "co.nz", "com.au", "org.uk", "net.au"
}


def is_ip_address(hostname: str) -> bool:
    """Checks if hostname is a valid IPv4 or IPv6 address."""
    if not hostname:
        return False
    clean = hostname.strip("[]").strip()
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def extract_domain_components(hostname: str, is_ip: bool) -> Dict[str, Any]:
    """Extracts domain, subdomains, and subdomain count from hostname."""
    if is_ip or not hostname:
        return {"tld": "", "domain": hostname, "subdomains": [], "subdomain_count": 0}
    
    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 1:
        return {"tld": "", "domain": hostname, "subdomains": [], "subdomain_count": 0}
    
    tld = parts[-1]
    second_last = parts[-2] if len(parts) > 2 else ""
    full_suffix = f"{second_last}.{tld}" if second_last else tld
    
    if full_suffix in KNOWN_TWO_PART_SUFFIXES and len(parts) > 2:
        domain = ".".join(parts[-3:])
        subdomains = parts[:-3]
    else:
        domain = ".".join(parts[-2:])
        subdomains = parts[:-2]
        
    return {
        "tld": tld,
        "domain": domain,
        "subdomains": subdomains,
        "subdomain_count": len(subdomains)
    }


def find_suspicious_keywords(text: str) -> List[str]:
    """Detects security-sensitive keywords in URL string."""
    if not text:
        return []
    lower = text.lower()
    detected = []
    for kw in SUSPICIOUS_KEYWORDS:
        pattern = rf"(^|[^a-z0-9]){re.escape(kw)}([^a-z0-9]|$)"
        if re.search(pattern, lower) or kw in lower:
            if kw not in detected:
                detected.append(kw)
    return detected


def extract_features_from_url(raw_url: str) -> Dict[str, Any]:
    """
    Extracts the deterministic 18 features from a URL string.
    Returns a dict with keys matching FEATURE_NAMES.
    """
    url_str = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_str):
        if url_str.startswith("//"):
            url_str = "http:" + url_str
        else:
            url_str = "http://" + url_str
            
    parsed = urlparse(url_str)
    protocol = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    pathname = parsed.path or "/"
    query = parsed.query or ""
    
    is_ip = is_ip_address(hostname)
    domain_info = extract_domain_components(hostname, is_ip)
    
    total_len = len(url_str)
    host_len = len(hostname)
    path_len = len(pathname)
    query_len = len(query)
    
    dot_count = url_str.count(".")
    path_segments = [p for p in pathname.split("/") if p]
    path_segment_count = len(path_segments)
    
    query_params_count = len(parsed.query.split("&")) if parsed.query else 0
    
    hyphen_count = url_str.count("-")
    hostname_hyphen_count = hostname.count("-")
    underscore_count = url_str.count("_")
    at_symbol_count = url_str.count("@")
    percent_count = url_str.count("%")
    digits_count = len(re.findall(r"\d", url_str))
    
    special_matches = re.findall(r"[^a-zA-Z0-9:/._\-?=&%#]", url_str)
    special_char_count = len(special_matches) + percent_count + at_symbol_count
    
    path_and_query = f"{pathname}?{query}"
    detected_keywords = find_suspicious_keywords(path_and_query)
    if not is_ip:
        detected_keywords.extend(find_suspicious_keywords(hostname))
    unique_keywords = list(set(detected_keywords))
    
    hostname_labels = hostname.split(".")
    has_long_label = any(len(lbl) > 30 for lbl in hostname_labels)
    suspicious_hostname_pattern = 1 if (
        hostname_hyphen_count >= 2 or has_long_label or (is_ip and path_len > 1)
    ) else 0
    
    return {
        "url_length": total_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "dot_count": dot_count,
        "subdomain_count": domain_info["subdomain_count"],
        "path_segment_count": path_segment_count,
        "query_params_count": query_params_count,
        "special_char_count": special_char_count,
        "digits_count": digits_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "at_symbol_count": at_symbol_count,
        "percent_count": percent_count,
        "uses_https": 1 if protocol == "https" else 0,
        "is_ip_address": 1 if is_ip else 0,
        "suspicious_keyword_count": len(unique_keywords),
        "suspicious_hostname_pattern": suspicious_hostname_pattern,
    }
