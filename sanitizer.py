"""
sanitizer.py — PII & sensitive-data sanitization engine.

Flow:
  sanitize(text)   → replaces real values with synthetic ones, stores mapping
  desanitize(text) → reverses the mapping, restores real values

Session-scoped: each Sanitizer instance keeps its own bidirectional table,
so the same real value always maps to the same fake value within a session.
"""

import re
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Synthetic data templates
# ---------------------------------------------------------------------------

# Realistic-enough fake names so Claude can reason about them naturally
_FAKE_FIRST = [
    "Alice", "Bob", "Carol", "David", "Eva", "Frank", "Grace", "Henry",
    "Iris", "Jack", "Kate", "Leo", "Mia", "Nathan", "Olivia", "Paul",
    "Quinn", "Ruth", "Sam", "Tina", "Uma", "Victor", "Wendy", "Xander",
    "Yara", "Zoe",
]
_FAKE_LAST = [
    "Harrington", "Calloway", "Pendleton", "Whitmore", "Blackwell",
    "Fairfield", "Ashford", "Cromwell", "Holloway", "Thornton",
    "Davenport", "Kingsley", "Westbrook", "Fairbanks", "Sterling",
    "Lockwood", "Pemberton", "Waverly", "Aldridge", "Prescott",
]


def _fake_name(n: int) -> str:
    first = _FAKE_FIRST[(n - 1) % len(_FAKE_FIRST)]
    last = _FAKE_LAST[(n - 1) % len(_FAKE_LAST)]
    return f"{first} {last}"


# ---------------------------------------------------------------------------
# Detection patterns — ordered most-specific → least-specific
# ---------------------------------------------------------------------------

# Each entry: (kind, compiled_regex)
PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Full URLs first so the host inside doesn't get matched separately
    ("url", re.compile(
        r'https?://[^\s"\'<>\]]+',
        re.IGNORECASE,
    )),
    # Emails before generic hostnames
    ("email", re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    )),
    # IPv4 — strict octet ranges
    ("ipv4", re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    )),
    # IPv6 — simplified but covers the common formats
    ("ipv6", re.compile(
        r'\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b',
    )),
    # host:port  (e.g. myserver:8443)
    ("host_port", re.compile(
        r'\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)'
        r':([1-9]\d{1,4})\b',
    )),
    # Credit card (Luhn not checked — just 16-digit groups)
    ("credit_card", re.compile(
        r'\b(?:\d{4}[\s\-]?){3}\d{4}\b',
    )),
    # US SSN
    ("ssn", re.compile(
        r'\b\d{3}-\d{2}-\d{4}\b',
    )),
    # Phone numbers (US-centric but catches international too)
    ("phone", re.compile(
        r'\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b',
    )),
    # Hostnames / FQDNs with known or internal TLDs
    ("hostname", re.compile(
        r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)'
        r'+(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|es|it|ru|cn|jp|'
        r'br|au|ca|local|internal|corp|lan|localdomain|example)\b',
        re.IGNORECASE,
    )),
    # Long opaque tokens — API keys, secrets, bearer tokens (≥32 chars)
    ("token", re.compile(
        r'\b[A-Za-z0-9_\-]{32,}\b',
    )),
]


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

class MappingTable:
    """Bidirectional real ↔ fake mapping, scoped to one session."""

    def __init__(self):
        self._real_to_fake: Dict[str, str] = {}
        self._fake_to_real: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}

    def register(self, real: str, fake: str) -> None:
        self._real_to_fake[real] = fake
        self._fake_to_real[fake] = real

    def get_fake(self, real: str) -> Optional[str]:
        return self._real_to_fake.get(real)

    def get_real(self, fake: str) -> Optional[str]:
        return self._fake_to_real.get(fake)

    def next_count(self, kind: str) -> int:
        self._counters[kind] = self._counters.get(kind, 0) + 1
        return self._counters[kind]

    @property
    def fake_to_real(self) -> Dict[str, str]:
        return self._fake_to_real

    def snapshot(self) -> dict:
        """Return a human-readable snapshot for the debug endpoint."""
        return {
            "total_entries": len(self._real_to_fake),
            "counters_by_type": dict(self._counters),
            "mappings": {r: f for r, f in self._real_to_fake.items()},
        }


# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------

class Sanitizer:
    """
    One instance per session. Maintains state so the same real value always
    maps to the same synthetic value within a conversation.
    """

    def __init__(self):
        self.table = MappingTable()

    # -----------------------------------------------------------------------
    # Synthetic value generators
    # -----------------------------------------------------------------------

    def _make_fake(self, kind: str, real: str) -> str:
        n = self.table.next_count(kind)

        if kind == "ipv4":
            # Pentesting-friendly: 127.0.0.x  (RFC 5735 loopback range)
            octet = min(n, 254)
            return f"127.0.0.{octet}"

        if kind == "ipv6":
            return f"::1"

        if kind == "host_port":
            # Replace host portion with localhost, keep port visible
            m = re.match(r'^([^:]+):(\d+)$', real)
            port = m.group(2) if m else "0"
            return f"localhost.localdomain.{n}:{port}"

        if kind == "email":
            return f"user{n:03d}@fakecorp.local"

        if kind == "phone":
            return f"+1-555-000-{n:04d}"

        if kind == "ssn":
            return f"000-00-{n:04d}"

        if kind == "credit_card":
            return f"4111-1111-1111-{n:04d}"

        if kind == "hostname":
            return f"localhost.localdomain.{n}"

        if kind == "url":
            # Replace only the host, preserve scheme + path
            m = re.match(r'(https?://)([^/?#]+)(.*)', real, re.IGNORECASE)
            if m:
                scheme, _host, rest = m.groups()
                return f"{scheme}localhost.localdomain.{n}{rest}"
            return f"http://localhost.localdomain.{n}/"

        if kind == "token":
            return f"FAKE_TOKEN_{n:04d}_{'x' * 8}"

        return f"FAKE_{kind.upper()}_{n:03d}"

    # -----------------------------------------------------------------------
    # Core text operations
    # -----------------------------------------------------------------------

    def sanitize(self, text: str) -> str:
        """Replace all detected sensitive values with synthetic equivalents."""
        if not text:
            return text

        # Collect matches from every pattern
        hits: List[Tuple[int, int, str, str]] = []
        for kind, rx in PATTERNS:
            for m in rx.finditer(text):
                hits.append((m.start(), m.end(), m.group(), kind))

        if not hits:
            return text

        # Sort: left-to-right, prefer longer match on ties
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))

        # Remove overlapping matches (keep first / longest at each position)
        filtered: List[Tuple[int, int, str, str]] = []
        last_end = -1
        for start, end, value, kind in hits:
            if start >= last_end:
                filtered.append((start, end, value, kind))
                last_end = end

        # Replace right-to-left so earlier indices stay valid
        result = text
        for start, end, value, kind in reversed(filtered):
            fake = self.table.get_fake(value)
            if fake is None:
                fake = self._make_fake(kind, value)
                self.table.register(value, fake)
            result = result[:start] + fake + result[end:]

        return result

    def desanitize(self, text: str) -> str:
        """Restore all synthetic values back to the originals."""
        if not text or not self.table.fake_to_real:
            return text

        result = text
        # Replace longest fake values first to avoid partial-match collisions
        for fake, real in sorted(
            self.table.fake_to_real.items(),
            key=lambda x: len(x[0]),
            reverse=True,
        ):
            result = result.replace(fake, real)
        return result

    # -----------------------------------------------------------------------
    # Claude API-aware helpers
    # -----------------------------------------------------------------------

    def _sanitize_content_blocks(self, content) -> object:
        """Handle both string content and structured content block lists."""
        if isinstance(content, str):
            return self.sanitize(content)
        if isinstance(content, list):
            out = []
            for block in content:
                b = dict(block)
                if b.get("type") == "text":
                    b["text"] = self.sanitize(b.get("text", ""))
                out.append(b)
            return out
        return content

    def sanitize_request(self, body: dict) -> dict:
        """Sanitize a full /v1/messages request body."""
        new = dict(body)

        if "messages" in body:
            new["messages"] = [
                {**msg, "content": self._sanitize_content_blocks(msg.get("content", ""))}
                for msg in body["messages"]
            ]

        if "system" in body:
            sys = body["system"]
            if isinstance(sys, str):
                new["system"] = self.sanitize(sys)
            elif isinstance(sys, list):
                new["system"] = [
                    {**b, "text": self.sanitize(b.get("text", ""))}
                    if b.get("type") == "text" else b
                    for b in sys
                ]

        return new

    def desanitize_response(self, body: dict) -> dict:
        """Desanitize a full /v1/messages response body."""
        new = dict(body)
        if "content" in body:
            new["content"] = [
                {**b, "text": self.desanitize(b.get("text", ""))}
                if b.get("type") == "text" else b
                for b in body["content"]
            ]
        return new
