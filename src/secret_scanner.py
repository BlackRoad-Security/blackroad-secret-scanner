"""
BlackRoad Secret Scanner – detect hardcoded secrets, tokens and credentials.
Scans files using regex entropy analysis and pattern matching.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────
# Secret patterns
# ─────────────────────────────────────────────

@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern
    severity: str
    description: str
    remediation: str


SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}"),
                  "CRITICAL", "AWS Access Key ID", "Rotate immediately; use IAM roles."),
    SecretPattern("AWS_SECRET_KEY",
                  re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
                  "CRITICAL", "AWS Secret Access Key", "Rotate immediately."),
    SecretPattern("GITHUB_TOKEN",
                  re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
                  "CRITICAL", "GitHub Personal Access Token", "Revoke and rotate token."),
    SecretPattern("ANTHROPIC_KEY",
                  re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),
                  "CRITICAL", "Anthropic API Key", "Revoke and rotate key."),
    SecretPattern("OPENAI_KEY",
                  re.compile(r"sk-[A-Za-z0-9]{20,}"),
                  "CRITICAL", "OpenAI API Key", "Revoke and rotate key."),
    SecretPattern("STRIPE_KEY",
                  re.compile(r"(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,}"),
                  "CRITICAL", "Stripe API Key", "Revoke and regenerate."),
    SecretPattern("SLACK_TOKEN",
                  re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
                  "HIGH", "Slack API Token", "Revoke token in Slack console."),
    SecretPattern("PRIVATE_KEY_PEM",
                  re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
                  "CRITICAL", "Private key material in file",
                  "Remove from source; use key vault."),
    SecretPattern("JWT_TOKEN",
                  re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
                  "HIGH", "JWT Token embedded in source", "Never embed tokens in code."),
    SecretPattern("BASIC_AUTH",
                  re.compile(r"https?://[^:@/\s]+:[^:@/\s]+@"),
                  "HIGH", "Basic auth credentials in URL", "Use env vars for credentials."),
    SecretPattern("GENERIC_API_KEY",
                  re.compile(r"(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"),
                  "HIGH", "Generic API key", "Move to environment variables."),
    SecretPattern("GENERIC_SECRET",
                  re.compile(r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
                  "HIGH", "Generic secret/password in code", "Use a secrets manager."),
    SecretPattern("PRIVATE_IP",
                  re.compile(r"(?:^|\s)(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)"),
                  "LOW", "Private IP address hardcoded", "Use configuration/DNS names."),
    SecretPattern("CLOUDFLARE_TOKEN",
                  re.compile(r"(?i)cloudflare[_\-]?(api[_\-]?)?token\s*[:=]\s*['\"]([A-Za-z0-9_\-]{30,})['\"]"),
                  "CRITICAL", "Cloudflare API Token", "Rotate token immediately."),
    SecretPattern("VERCEL_TOKEN",
                  re.compile(r"(?i)vercel[_\-]?token\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"),
                  "CRITICAL", "Vercel API Token", "Rotate token immediately."),
    SecretPattern("HIGH_ENTROPY_B64",
                  re.compile(r"['\"][A-Za-z0-9+/]{40,}={0,2}['\"]"),
                  "MEDIUM", "High-entropy base64 string (possible secret)",
                  "Review this value; if it is a secret, move to vault."),
    SecretPattern("SSH_PRIVATE_KEY",
                  re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
                  "CRITICAL", "OpenSSH Private Key", "Remove from source immediately."),
]

# Binary/irrelevant extensions to skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".pyd", ".so", ".dll", ".dylib", ".exe",
    ".mp3", ".mp4", ".mov", ".avi", ".wav",
    ".lock",  # yarn.lock etc. have long hash strings
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build", ".next"}


# ─────────────────────────────────────────────
# Shannon entropy
# ─────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in counts.values())


def _high_entropy_strings(line: str, min_len: int = 20, threshold: float = 4.5) -> List[str]:
    """Extract quoted strings with high Shannon entropy (likely secrets)."""
    found = []
    for match in re.finditer(r"['\"]([A-Za-z0-9+/=_\-]{%d,})['\"]" % min_len, line):
        token = match.group(1)
        if _entropy(token) >= threshold:
            found.append(token)
    return found


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class SecretFinding:
    id: str
    severity: str
    pattern_name: str
    file: str
    line: int
    description: str
    snippet: str = ""          # redacted snippet
    entropy: float = 0.0
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class SecretScanner:
    def __init__(self, entropy_threshold: float = 4.5):
        self.entropy_threshold = entropy_threshold
        self._counter = 0

    def _next_id(self, fname: str) -> str:
        self._counter += 1
        h = hashlib.md5(f"{fname}{self._counter}".encode()).hexdigest()[:8]
        return f"SS-{h}"

    def _redact(self, line: str) -> str:
        """Lightly redact secrets from snippet for safe display."""
        redacted = line
        for pat in SECRET_PATTERNS:
            redacted = pat.pattern.sub("[REDACTED]", redacted)
        return redacted.strip()[:120]

    def scan_file(self, fpath: Path) -> List[SecretFinding]:
        if fpath.suffix.lower() in SKIP_EXTENSIONS:
            return []
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        findings: List[SecretFinding] = []
        seen: set = set()  # deduplicate per-line pattern matches
        lines = text.splitlines()

        for lineno, raw_line in enumerate(lines, 1):
            # Skip obvious comments in known file types
            stripped = raw_line.strip()
            if stripped.startswith(("#", "//", "/*", "*", "--")) and "-----BEGIN" not in stripped:
                # still check for private keys in comments
                pass

            for sp in SECRET_PATTERNS:
                if sp.pattern.search(raw_line):
                    key = (str(fpath), lineno, sp.name)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(SecretFinding(
                        id=self._next_id(str(fpath)),
                        severity=sp.severity,
                        pattern_name=sp.name,
                        file=str(fpath),
                        line=lineno,
                        description=sp.description,
                        snippet=self._redact(raw_line),
                        remediation=sp.remediation,
                    ))

            # Entropy-based detection
            for token in _high_entropy_strings(raw_line, threshold=self.entropy_threshold):
                # Skip if already caught by pattern
                already = any(f.line == lineno and str(fpath) == f.file and
                              f.pattern_name != "HIGH_ENTROPY_B64"
                              for f in findings)
                if not already:
                    e = _entropy(token)
                    key = (str(fpath), lineno, "ENTROPY", token[:12])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(SecretFinding(
                        id=self._next_id(str(fpath)),
                        severity="MEDIUM",
                        pattern_name="HIGH_ENTROPY_STRING",
                        file=str(fpath),
                        line=lineno,
                        description=f"High-entropy string (entropy={e:.2f}) – possible secret.",
                        snippet=self._redact(raw_line),
                        entropy=round(e, 3),
                        remediation="Review this value; move secrets to a vault.",
                    ))
        return findings

    def scan_directory(self, directory: str, max_file_size: int = 5 * 1024 * 1024) -> List[SecretFinding]:
        all_findings: List[SecretFinding] = []
        path = Path(directory)
        for fpath in sorted(path.rglob("*")):
            if not fpath.is_file():
                continue
            if any(d in fpath.parts for d in SKIP_DIRS):
                continue
            if fpath.stat().st_size > max_file_size:
                continue
            all_findings.extend(self.scan_file(fpath))
        return all_findings


# ─────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate_summary(findings: List[SecretFinding]) -> Dict[str, Any]:
    by_sev: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_type[f.pattern_name] = by_type.get(f.pattern_name, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_type": by_type,
        "critical_count": by_sev.get("CRITICAL", 0),
        "high_count": by_sev.get("HIGH", 0),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="BlackRoad Secret Scanner")
    p.add_argument("directory", nargs="?", default=".", help="Directory to scan")
    p.add_argument("--format", choices=["text","json","sarif"], default="text")
    p.add_argument("--output", "-o", default=None)
    p.add_argument("--severity", choices=["ALL","CRITICAL","HIGH","MEDIUM","LOW"], default="ALL")
    p.add_argument("--entropy", type=float, default=4.5, help="Entropy threshold (default 4.5)")
    p.add_argument("--no-entropy", action="store_true", help="Disable entropy scanning")
    args = p.parse_args(argv)

    scanner = SecretScanner(entropy_threshold=999.0 if args.no_entropy else args.entropy)
    findings = scanner.scan_directory(args.directory)

    if args.severity != "ALL":
        cutoff = _SEV_ORDER[args.severity]
        findings = [f for f in findings if _SEV_ORDER.get(f.severity, 99) <= cutoff]

    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))
    summary = generate_summary(findings)

    if args.format == "json":
        out = json.dumps({"summary": summary, "findings": [f.to_dict() for f in findings]}, indent=2)
        if args.output:
            Path(args.output).write_text(out)
        else:
            print(out)
    else:
        print(f"\n{'='*60}")
        print("  BlackRoad Secret Scanner")
        print(f"{'='*60}")
        print(f"  Directory : {args.directory}")
        print(f"  Findings  : {summary['total']}")
        print(f"  Critical  : {summary['critical_count']}")
        print(f"  High      : {summary['high_count']}")
        print(f"{'='*60}\n")
        for f in findings:
            print(f"  [{f.severity:<8}] {f.pattern_name}")
            print(f"             {f.file}:{f.line}")
            print(f"             {f.description}")
            print(f"             Snippet: {f.snippet[:80]}")
            print()

    return 1 if summary["critical_count"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
