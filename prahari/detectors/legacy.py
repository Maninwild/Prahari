"""Archived SentinelAI baseline definitions; original authors: user and collaborator."""

import unicodedata, html

from urllib.parse import unquote

RULES = [
    ("SQL Injection", "UNION SELECT clause", r"\bunion(?:\s|/\*.*?\*/)+(?:all\s+)?select\b"),
    ("SQL Injection", "Always-true SQL comparison", r"""\b(?:or|and)\s+(?:(['"])(\w+)\1\s*=\s*\1\2\1|(\d+)\s*=\s*\3\b)"""),
    ("SQL Injection", "Quote followed by SQL comment", r"""['"]\s*(?:--|#)"""),
    ("SQL Injection", "Destructive SQL statement", r";\s*(?:drop|alter|truncate)\s+(?:table|database)\b"),
    ("SQL Injection", "SQL timing function", r"\b(?:sleep|benchmark)\s*\(\s*\d"),
    ("Cross-Site Scripting", "Script element", r"<\s*script\b"),
    ("Cross-Site Scripting", "HTML event handler", r"<[^>\n]{0,240}\bon(?:error|load|focus|click|toggle|mouseover)\s*="),
    ("Cross-Site Scripting", "JavaScript URL scheme", r"\bjavascript\s*:"),
    ("Command Injection", "Shell separator followed by command", r"(?:[;&|]|\n)\s*(?:whoami|id|uname|cat|dir|pwd|type)\b"),
    ("Command Injection", "Shell command substitution", r"(?:\$\(|\x60)\s*(?:whoami|id|uname|cat|dir|pwd|type)\b"),
    ("Path Traversal", "Parent-directory traversal", r"\.{2,}[/\\]+"),
    ("Path Traversal", "Sensitive absolute file parameter", r"""(?:file|path|doc|name)\s*=\s*['"]?(?:/etc/(?:passwd|shadow|hosts)|[a-z]:\\windows\\win\.ini)"""),
]

def normalize_request(text):
    """Bounded heuristic text decoding, not a full HTTP/application parser."""
    current = unicodedata.normalize("NFKC", text.strip())
    steps = []
    if current != text.strip():
        steps.append("Unicode normalization")
    # Replace original form-style plus separators before percent decoding.
    # A literal plus encoded as %2B is therefore retained.
    if "+" in current:
        current = current.replace("+", " ")
        steps.append("Form-style plus separators")
    for number in (1, 2):
        decoded = unquote(current)
        if decoded != current:
            steps.append("URL decoding pass " + str(number))
        unescaped = html.unescape(decoded)
        if unescaped != decoded:
            steps.append("HTML entity decoding pass " + str(number))
        if unescaped == current:
            break
        current = unescaped
    return current, steps