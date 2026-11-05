"""Sensitive Credential and Secret Redaction Engine for ARGUS.

Ensures credentials, bearer tokens, private keys, and API secrets are never
persisted into raw evidence files or displayed in report outputs.
"""

import re

# High-performance compiled patterns without catastrophic backtracking
SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Bearer tokens (JWT, OAuth)
    (
        re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{20,}"),
        r"\1[REDACTED_BY_ARGUS]",
    ),
    # Passwords in URLs, headers, or parameters
    (
        re.compile(r"(?i)(password\s*[:=]\s*)[^\s&,;]{3,}"),
        r"\1[REDACTED_BY_ARGUS]",
    ),
    # API keys and secret tokens
    (
        re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)[a-zA-Z0-9_\-]{16,}"),
        r"\1[REDACTED_BY_ARGUS]",
    ),
    # Basic Authorization headers
    (
        re.compile(r"(?i)(authorization:\s*basic\s+)[a-zA-Z0-9+/=]+"),
        r"\1[REDACTED_BY_ARGUS]",
    ),
    # AWS Access Key IDs
    (
        re.compile(r"(AKIA[0-9A-Z]{16})"),
        r"[REDACTED_BY_ARGUS]",
    ),
    # Private Key blocks
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        r"[REDACTED_PRIVATE_KEY_BY_ARGUS]",
    ),
)


class SecretRedactor:
    """Detects and masks sensitive credentials in arbitrary text payloads."""

    def __init__(self) -> None:
        self._patterns = SECRET_PATTERNS

    def redact(self, text: str) -> tuple[str, bool]:
        """Redacts all known sensitive token formats from text.

        Returns:
            tuple of (redacted_text, was_redacted)
        """
        if not text:
            return text, False

        cleaned = text
        was_redacted = False

        for pattern, replacement in self._patterns:
            if pattern.search(cleaned):
                cleaned = pattern.sub(replacement, cleaned)
                was_redacted = True

        return cleaned, was_redacted
