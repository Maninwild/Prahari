"""Explainable URL shape indicators; no reputation lookup or site fetching."""

import ipaddress
import re
from urllib.parse import urlsplit
from ..schemas import Finding


def inspect_url(url):
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    indicators = []
    if parsed.scheme.lower() == "http":
        indicators.append(("URL-001", "URL uses unencrypted HTTP", 35, "url.scheme"))
    try:
        ipaddress.ip_address(host)
        indicators.append(
            (
                "URL-002",
                "Destination is an IP address rather than a domain",
                45,
                "url.host",
            )
        )
    except ValueError:
        pass
    if any(part.startswith("xn--") for part in host.lower().split(".")):
        indicators.append(
            (
                "URL-003",
                "Internationalized hostname requires visual verification",
                35,
                "url.host",
            )
        )
    if len(host.rstrip(".").split(".")) > 4:
        indicators.append(
            ("URL-004", "Unusually deep hostname hierarchy", 40, "url.host")
        )
    if re.search(
        r"(?:verify|secure|account|login|password|wallet)", host + parsed.path, re.I
    ):
        indicators.append(
            (
                "URL-005",
                "Credential or account-related URL wording; verify destination",
                30,
                "url",
            )
        )
    return [
        Finding(
            detector="phishing_rules",
            category="phishing",
            evidence_kind="rule",
            rule_id=rule_id,
            summary=summary,
            score=score,
            component=component,
            view="url_structure",
        )
        for rule_id, summary, score, component in indicators
    ]
