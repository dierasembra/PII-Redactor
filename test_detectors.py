import io
from pii.detectors import Detector

def test_find_email():
    d = Detector(['email'])
    findings = d.find_all('Contact: bob.smith@example.co.uk')
    assert any(f['type']=='email' for f in findings)

def test_redact_line():
    d = Detector(['email','ipv4'])
    redacted, findings = d.redact_line('reach me at admin@site.com or 10.0.0.1', 1)
    assert '[REDACTED]' in redacted
    assert len(findings) >= 2
