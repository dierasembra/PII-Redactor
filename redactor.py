#!/usr/bin/env python3
"""PII Redactor - Scan text files and redact emails, phones, credit cards, IPv4 addresses."""
import argparse
import re
import sys
from pii.detectors import Detector, PATTERN_MAP

def parse_args():
    p = argparse.ArgumentParser(description='Redact PII from a text file.')
    p.add_argument('--input','-i', required=True, help='Input text file path')
    p.add_argument('--output','-o', required=True, help='Output file path (redacted)')
    p.add_argument('--types','-t', nargs='+', choices=list(PATTERN_MAP.keys()), default=list(PATTERN_MAP.keys()),
                   help='Types of PII to redact (default: all)')
    p.add_argument('--placeholder','-p', default='[REDACTED]', help='Replacement placeholder')
    p.add_argument('--json','-j', action='store_true', help='Also write JSON report of findings (saved next to output)')
    return p.parse_args()

def process_file(input_path, output_path, types, placeholder, json_out=False):
    detector = Detector(types=types)
    findings = []
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as src,                  open(output_path, 'w', encoding='utf-8') as dst:
        for line_no, line in enumerate(src, start=1):
            redacted, line_findings = detector.redact_line(line, line_no, placeholder)
            if line_findings:
                findings.extend(line_findings)
            dst.write(redacted)
    if json_out:
        import json, os
        report_path = os.path.splitext(output_path)[0] + '_report.json'
        with open(report_path, 'w', encoding='utf-8') as r:
            json.dump(findings, r, indent=2)
        print(f'Wrote JSON report: {report_path}')
    return findings

def main():
    args = parse_args()
    findings = process_file(args.input, args.output, args.types, args.placeholder, args.json)
    print(f'Redaction complete. Found {len(findings)} items.')
    if findings:
        print('Sample findings:')
        for f in findings[:10]:
            print(f)

if __name__ == '__main__':
    main()
