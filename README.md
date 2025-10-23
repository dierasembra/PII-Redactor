# PII Redactor

**PII Redactor** is a simple, open-source command-line tool for scanning text files and redacting commonly-occurring personally identifiable information (PII) such as:
- Email addresses
- Phone numbers
- Credit card numbers
- IPv4 addresses

The project is suitable as a GitHub Sponsors repo: small, useful, and easy to extend.

## Features
- Fast file streaming (works with large files)
- Configurable redaction rules
- CLI usage and optional JSON output
- MIT license

## Quick start

Requirements: Python 3.8+

Install (optional virtualenv):
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Scan and redact a file:
```bash
python redactor.py --input samples/sample.txt --output samples/sample_redacted.txt --types email phone cc ipv4
```

For help:
```bash
python redactor.py --help
```

## Structure
- `redactor.py` — main CLI tool
- `pii/` — detection utilities
- `samples/` — sample files
- `tests/` — simple unit tests
- `README.md`, `LICENSE`, `requirements.txt`

## Contributing
Contributions welcome. Please open issues or PRs. If you like this project, consider sponsoring development on GitHub Sponsors.

## License
MIT
