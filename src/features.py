"""Feature extraction for phishing indicators.

All features are computed offline from the indicator string alone. Non-URL
indicators (domain, hostname, IPv4) are normalised to ``http://<value>/`` so a
single extractor applies uniformly. See ``parameters.md`` for definitions and
references.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

import tldextract

# Curated list of phishing-prone TLDs (Spamhaus / Interisle / APWG reports).
SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work", "party",
    "gq", "tk", "ml", "cf", "ga", "top", "click", "loan", "racing", "win",
    "download", "stream", "xyz", "men", "bid", "trade", "date", "rest",
    "support", "info", "biz", "pw", "icu", "buzz", "monster", "rest", "fit",
    "live", "best", "shop", "store", "online", "site", "cyou", "quest",
}

BRAND_TOKENS = [
    "paypal", "ebay", "amazon", "apple", "microsoft", "outlook", "office365",
    "google", "gmail", "facebook", "instagram", "whatsapp", "netflix",
    "bank", "chase", "wellsfargo", "hsbc", "barclays", "santander", "natwest",
    "dhl", "fedex", "ups", "usps", "irs", "hmrc",
]

SUSPICIOUS_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "secure", "account", "update",
    "verify", "verification", "confirm", "banking", "password", "webscr",
    "wallet", "auth", "session", "token", "recovery", "unlock",
]

_TOKEN_SPLIT = re.compile(r"[\/._\-\?=&]+")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalise(indicator: str, indicator_type: str) -> str:
    """Convert any indicator to a URL string for uniform parsing."""
    val = indicator.strip()
    if indicator_type == "URL":
        if "://" not in val:
            val = "http://" + val
        return val
    # domain / hostname / IPv4
    return "http://" + val.strip("/") + "/"


@dataclass
class Features:
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    num_dots: int
    num_hyphens: int
    num_at: int
    num_question: int
    num_equals: int
    num_underscore: int
    num_ampersand: int
    num_tilde: int
    num_percent: int
    num_slash: int
    num_digits: int
    digit_letter_ratio: float
    num_subdomains: int
    longest_token_length: int
    avg_token_length: float
    hostname_entropy: float
    has_https: int
    has_port: int
    has_ip_in_hostname: int
    has_punycode: int
    has_at_symbol: int
    has_double_slash_in_path: int
    tld: str
    tld_length: int
    is_suspicious_tld: int
    num_suspicious_keywords: int
    brand_in_subdomain: int
    brand_in_path: int


def extract(indicator: str, indicator_type: str) -> dict:
    url = normalise(indicator, indicator_type)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    ext = tldextract.extract(hostname)
    subdomain = ext.subdomain or ""
    tld = ext.suffix or ""
    num_subdomains = len([p for p in subdomain.split(".") if p]) if subdomain else 0

    num_letters = sum(c.isalpha() for c in url)
    num_digits = sum(c.isdigit() for c in url)

    tokens = [t for t in _TOKEN_SPLIT.split(url) if t]
    longest = max((len(t) for t in tokens), default=0)
    avg_len = (sum(len(t) for t in tokens) / len(tokens)) if tokens else 0.0

    url_lower = url.lower()
    susp_kw = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    brand_sub = int(any(b in subdomain for b in BRAND_TOKENS))
    brand_path = int(any(b in path.lower() for b in BRAND_TOKENS))

    # double slash in path: ignore the scheme separator
    path_double_slash = int("//" in path)

    feats = Features(
        url_length=len(url),
        hostname_length=len(hostname),
        path_length=len(path),
        query_length=len(query),
        num_dots=url.count("."),
        num_hyphens=url.count("-"),
        num_at=url.count("@"),
        num_question=url.count("?"),
        num_equals=url.count("="),
        num_underscore=url.count("_"),
        num_ampersand=url.count("&"),
        num_tilde=url.count("~"),
        num_percent=url.count("%"),
        num_slash=url.count("/"),
        num_digits=num_digits,
        digit_letter_ratio=num_digits / max(num_letters, 1),
        num_subdomains=num_subdomains,
        longest_token_length=longest,
        avg_token_length=round(avg_len, 4),
        hostname_entropy=round(_shannon(hostname), 4),
        has_https=int(parsed.scheme == "https"),
        has_port=int(parsed.port is not None),
        has_ip_in_hostname=int(_is_ip(hostname)),
        has_punycode=int(any(lbl.startswith("xn--") for lbl in hostname.split("."))),
        has_at_symbol=int("@" in url),
        has_double_slash_in_path=path_double_slash,
        tld=tld,
        tld_length=len(tld),
        is_suspicious_tld=int(tld in SUSPICIOUS_TLDS),
        num_suspicious_keywords=susp_kw,
        brand_in_subdomain=brand_sub,
        brand_in_path=brand_path,
    )
    return asdict(feats)
