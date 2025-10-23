"""Detectors for common PII patterns.
The implementation favors streaming and avoids loading whole files into memory.
"""
import re
from typing import List, Tuple, Dict, Any

# Simple, conservative regexes. Not perfect; suitable as a base for improvement.
PATTERN_MAP = {
    'email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
    'phone': r'(?:(?:\+?\d{1,3})?[-.\s]?)?(?:\(\d{2,4}\)|\d{2,4})[-.\s]?\d{3,4}[-.\s]?\d{3,4}',
    'cc': r'\b(?:\d[ -]*?){13,16}\b',
    'ipv4': r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
}

class Detector:
    def __init__(self, types=None):
        self.types = types or list(PATTERN_MAP.keys())
        self.compiled = {t: re.compile(PATTERN_MAP[t]) for t in self.types if t in PATTERN_MAP}

    def find_all(self, text: str):
        results = []
        for t, pat in self.compiled.items():
            for m in pat.finditer(text):
                results.append({'type': t, 'match': m.group(0), 'span': m.span()})
        return results

    def redact_line(self, line: str, line_no:int, placeholder:str='[REDACTED]'):
        findings = []
        redacted = line
        # To avoid overlapping replacements issues, collect matches first and replace from right to left.
        matches = []
        for t, pat in self.compiled.items():
            for m in pat.finditer(line):
                matches.append((m.start(), m.end(), t, m.group(0)))
        # sort by start descending
        matches.sort(key=lambda x: x[0], reverse=True)
        for start, end, t, matched in matches:
            findings.append({'line': line_no, 'type': t, 'match': matched})
            redacted = redacted[:start] + placeholder + redacted[end:]
        return redacted, findings
