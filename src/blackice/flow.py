from __future__ import annotations

import re
from dataclasses import dataclass

CREDENTIAL_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "api-token",
        re.compile(
            r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9]+[_-])*(?:api[_-]?(?:key|token)|access[_-]?token|"
            r"secret(?:[_-](?:key|value|token|access[_-]?key))?|token(?:[_-]?value)?|password|passwd|"
            r"private[_-]?key|credential)(?![A-Za-z0-9])\s*[:=]\s*['\"]?[^\s,'\";]{8,}"
        ),
    ),
    ("bearer-token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    ("generic-secret", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Classification:
    labels: tuple[str, ...]
    matched_rules: tuple[str, ...]

    @property
    def sensitive(self) -> bool:
        return bool(self.labels)


def classify_text(text: str) -> Classification:
    rules: list[str] = []
    labels: list[str] = []
    for name, pattern in CREDENTIAL_RULES:
        if pattern.search(text):
            rules.append(name)
            labels.append("credential")
    if EMAIL_RE.search(text):
        rules.append("email-address")
        labels.append("possible-pii")
    return Classification(tuple(dict.fromkeys(labels)), tuple(rules))


def redact_sensitive_text(text: str) -> tuple[str, list[str]]:
    redacted = text
    matched: list[str] = []
    for name, pattern in CREDENTIAL_RULES:
        redacted, count = pattern.subn(f"[REDACTED:{name}]", redacted)
        if count:
            matched.append(name)
    redacted, email_count = EMAIL_RE.subn("[REDACTED:email-address]", redacted)
    if email_count:
        matched.append("email-address")
    return redacted, matched
