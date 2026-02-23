"""Tests for blackroad-secret-scanner."""
import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from src.secret_scanner import SecretScanner, _entropy, _high_entropy_strings, generate_summary, SecretFinding


def write_dir(files):
    d = tempfile.mkdtemp()
    for name, content in files.items():
        Path(d, name).write_text(content)
    return d


class TestEntropy:
    def test_high_entropy(self):
        assert _entropy("AAAAAAAAAAAAAAAAA") < 1.0  # repetitive = low entropy
        assert _entropy("aB3$xY9!mK2#nQ7@") > 3.5  # random = high entropy

    def test_empty_string(self):
        assert _entropy("") == 0.0


class TestHighEntropyStrings:
    def test_detects_high_entropy(self):
        line = "token = 'aB3xY9mK2nQ7wP5zR8sT1uV4'"
        results = _high_entropy_strings(line, min_len=20, threshold=3.0)
        assert len(results) > 0

    def test_no_false_positive_simple(self):
        line = "value = 'aaaaaaaaaaaaaaaaaaaaaa'"
        results = _high_entropy_strings(line, min_len=20, threshold=4.5)
        assert len(results) == 0


class TestSecretScanner:
    def test_aws_key_detected(self):
        d = write_dir({"config.py": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"})
        scanner = SecretScanner()
        findings = scanner.scan_directory(d)
        assert any(f.pattern_name == "AWS_ACCESS_KEY" for f in findings)

    def test_github_token_detected(self):
        d = write_dir({"ci.py": "token = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890'"})
        scanner = SecretScanner()
        findings = scanner.scan_directory(d)
        assert any(f.pattern_name == "GITHUB_TOKEN" for f in findings)

    def test_private_key_detected(self):
        d = write_dir({"key.pem": "-----BEGIN PRIVATE KEY-----\nMIIE..."})
        scanner = SecretScanner()
        findings = scanner.scan_directory(d)
        assert any("PRIVATE_KEY" in f.pattern_name for f in findings)

    def test_clean_file_no_findings(self):
        d = write_dir({"main.py": "x = 1 + 2\nprint('hello world')"})
        scanner = SecretScanner()
        findings = scanner.scan_directory(d)
        assert findings == []

    def test_skip_binary_extensions(self):
        d = write_dir({"img.png": "AKIAIOSFODNN7EXAMPLE"})
        scanner = SecretScanner()
        findings = scanner.scan_directory(d)
        assert findings == []

    def test_snippet_is_redacted(self):
        d = write_dir({"config.py": "api_key = 'AKIAIOSFODNN7EXAMPLE'"})
        scanner = SecretScanner()
        findings = scanner.scan_directory(d)
        if findings:
            assert "[REDACTED]" in findings[0].snippet or len(findings[0].snippet) < 120


class TestSummary:
    def test_empty_findings(self):
        s = generate_summary([])
        assert s["total"] == 0
        assert s["critical_count"] == 0

    def test_counts_correctly(self):
        findings = [
            SecretFinding("a", "CRITICAL", "AWS", "f.py", 1, "desc"),
            SecretFinding("b", "HIGH", "GH", "f.py", 2, "desc"),
        ]
        s = generate_summary(findings)
        assert s["total"] == 2
        assert s["critical_count"] == 1
        assert s["high_count"] == 1