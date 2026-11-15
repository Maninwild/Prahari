import re
from .legacy import RULES
from ..schemas import Finding
from ..parsing import views

LABELS = {'SQL Injection':'sqli', 'Cross-Site Scripting':'xss', 'Command Injection':'command_injection', 'Path Traversal':'path_traversal'}
RULESET_VERSION = 'sentinel-refactor-0.1'
PATTERNS = [(f'PRH-{index:03}', LABELS[label], name, re.compile(pattern, re.I)) for index, (label, name, pattern) in enumerate(RULES, 1)]


def inspect(components):
    findings, seen = [], set()
    for component in components:
        for view, text, transformations in views(component):
            for rule_id, category, name, pattern in PATTERNS:
                match = pattern.search(text)
                if match and (rule_id, component.name) not in seen:
                    seen.add((rule_id, component.name))
                    findings.append(Finding(detector='rules', category=category, evidence_kind='rule', summary=name, excerpt=match.group(0)[:120], score=90, component=component.name, rule_id=rule_id, view=view, start=match.start(), end=match.end(), transformations=transformations))
    return findings
