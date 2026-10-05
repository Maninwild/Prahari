"""
feature_extraction.py
----------------------
Converts a raw URL string into a fixed-length numerical feature vector
that can be fed into a machine-learning classifier.

This module is imported by:
  - src/train_model.py   (during training)
  - app.py                (during live prediction in the Streamlit app)

Keeping the feature logic in ONE place guarantees that training and
inference always use identical feature definitions.
"""

import re
from urllib.parse import urlparse

# Keywords commonly seen in phishing URLs (credential harvesting, urgency, etc.)
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "bank",
    "password",
    "update",
    "confirm",
    "signin",
    "webscr",
    "ebayisapi",
    "billing",
    "suspend",
    "limited",
    "urgent",
    "click",
    "reset",
    "unlock",
]

# A short, illustrative list of known URL-shortening services.
SHORTENING_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "shorte.st",
    "rebrand.ly",
    "cutt.ly",
]

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Ordered list of feature names - this order MUST match the vector
# produced by `extract_features`. The app and training script both
# rely on this list for column naming / display.
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "num_subdomains",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_at",
    "num_ampersands",
    "has_https",
    "has_ip_address",
    "has_suspicious_keyword",
    "has_login",
    "has_verify",
    "has_account",
    "has_secure",
    "has_bank",
    "has_password",
    "has_shortener",
]


def _get_domain(url: str) -> str:
    """Best-effort extraction of the domain/netloc part of a URL."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    netloc = parsed.netloc or parsed.path.split("/")[0]
    # Strip credentials (user:pass@) and port if present
    netloc = netloc.split("@")[-1].split(":")[0]
    return netloc


def extract_features(url: str) -> dict:
    """
    Extract a dictionary of numerical features from a single URL string.
    Returns a dict keyed by FEATURE_NAMES so it can be turned into a
    DataFrame row directly.
    """
    url = str(url).strip()
    url_lower = url.lower()
    domain = _get_domain(url)

    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(not c.isalnum() and c not in ".-/" for c in url),
        "num_subdomains": max(domain.count(".") - 1, 0),
        "num_slashes": url.count("/"),
        "num_question_marks": url.count("?"),
        "num_equals": url.count("="),
        "num_at": url.count("@"),
        "num_ampersands": url.count("&"),
        "has_https": int(url_lower.startswith("https://")),
        "has_ip_address": int(bool(IP_PATTERN.match(domain))),
        "has_suspicious_keyword": int(any(k in url_lower for k in SUSPICIOUS_KEYWORDS)),
        "has_login": int("login" in url_lower or "signin" in url_lower),
        "has_verify": int("verify" in url_lower or "confirm" in url_lower),
        "has_account": int("account" in url_lower),
        "has_secure": int("secure" in url_lower),
        "has_bank": int("bank" in url_lower),
        "has_password": int("password" in url_lower or "pwd" in url_lower),
        "has_shortener": int(any(s in url_lower for s in SHORTENING_SERVICES)),
    }
    return features


def extract_features_vector(url: str) -> list:
    """Same as extract_features but returns an ordered list (for model input)."""
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]


if __name__ == "__main__":
    # Quick manual test
    test_urls = [
        "https://www.google.com",
        "http://secure-login-example.com/verify/account?user=1&id=2",
        "http://192.168.1.5/paypal/login.php",
        "https://bit.ly/3xYzAbc",
    ]
    for u in test_urls:
        print(u)
        print(extract_features(u))
        print()
