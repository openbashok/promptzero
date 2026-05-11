"""
sanitizer.py — PII & sensitive-data sanitization engine.

Detection layers (both run on every text, results merged):
  1. NLP  — Presidio + spaCy: detects PERSON, ORGANIZATION, phones, emails,
             national IDs, passports, credit cards, IBANs, SSNs, …
  2. Regex — network/infra patterns Presidio misses: IPv4/v6, hostnames,
             host:port, long tokens.

Flow:
  sanitize(text)   → real values → fake values  (stored in mapping table)
  desanitize(text) → fake values → real values  (reversed from table)

Session-scoped: one Sanitizer per conversation keeps the same fake value
for the same real value throughout the session.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Synthetic data pools
# ---------------------------------------------------------------------------

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
_FAKE_ORGS = [
    "Acme Corp", "Globex Industries", "Initech Systems", "Umbrella Tech",
    "Massive Dynamics", "Veridian Dynamics", "Soylent Corp",
    "Hooli Technologies", "Pied Piper", "Dunder Mifflin",
    "Stark Industries", "Wayne Enterprises", "Oscorp",
    "LexCorp", "Initrode", "Vandelay Industries",
    "Sterling Cooper", "Bluth Company", "Wolfram & Hart",
    "Cyberdyne Systems",
]

# ---------------------------------------------------------------------------
# Presidio — lazy global analyzer
# ---------------------------------------------------------------------------

# Entities to request from Presidio (explicit list avoids noisy detections)
_NLP_ENTITIES = [
    "PERSON",
    "ORGANIZATION",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_SSN",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "ES_NIF",       # Spanish DNI / NIF
    "NRP",          # Generic National Registration / ID number
    "URL",
]

# Maps Presidio entity type → our internal kind label
_PRESIDIO_KIND: Dict[str, str] = {
    "PERSON":             "person",
    "ORGANIZATION":       "org",
    "EMAIL_ADDRESS":      "email",
    "PHONE_NUMBER":       "phone",
    "CREDIT_CARD":        "credit_card",
    "IBAN_CODE":          "iban",
    "IP_ADDRESS":         "ipv4",
    "US_SSN":             "ssn",
    "US_PASSPORT":        "passport",
    "US_DRIVER_LICENSE":  "driver_license",
    "ES_NIF":             "national_id",
    "NRP":                "national_id",
    "URL":                "url",
}

_analyzer = None        # AnalyzerEngine instance once loaded
_nlp_available: Optional[bool] = None  # None = unchecked


def _get_analyzer():
    """Lazy-load Presidio AnalyzerEngine. Returns None if unavailable."""
    global _analyzer, _nlp_available
    if _nlp_available is not None:
        return _analyzer

    try:
        from presidio_analyzer import AnalyzerEngine  # noqa: PLC0415
        _analyzer = AnalyzerEngine()
        _nlp_available = True
        logger.info("Presidio NLP engine ready")
    except Exception as exc:
        _nlp_available = False
        logger.warning(
            "NLP detection disabled (%s). "
            "To enable: pip install presidio-analyzer && python -m spacy download en_core_web_lg",
            exc,
        )
    return _analyzer


def nlp_available() -> bool:
    _get_analyzer()
    return bool(_nlp_available)


# ---------------------------------------------------------------------------
# Regex patterns — network / infra / tokens (what Presidio misses)
# ---------------------------------------------------------------------------

_REGEX_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Full URLs first — host inside won't be matched separately
    ("url", re.compile(r'https?://[^\s"\'<>\]]+', re.IGNORECASE)),
    # Emails (backup for Presidio)
    ("email", re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),
    # IPv4 strict
    ("ipv4", re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )),
    # IPv6 simplified
    ("ipv6", re.compile(r'\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b')),
    # host:port
    ("host_port", re.compile(
        r'\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?):([1-9]\d{1,4})\b'
    )),
    # Credit card backup
    ("credit_card", re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b')),
    # SSN backup
    ("ssn", re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    # Phone backup
    ("phone", re.compile(
        r'\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b'
    )),
    # Hostnames / FQDNs
    ("hostname", re.compile(
        r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)'
        r'+(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|es|it|ru|cn|jp|'
        r'br|au|ca|local|internal|corp|lan|localdomain|example)\b',
        re.IGNORECASE,
    )),
    # Long opaque tokens — API keys, secrets (≥32 chars)
    ("token", re.compile(r'\b[A-Za-z0-9_\-]{32,}\b')),
]

# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

class MappingTable:
    """Bidirectional real ↔ fake, scoped to one session."""

    def __init__(self):
        self._r2f: Dict[str, str] = {}
        self._f2r: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}

    def register(self, real: str, fake: str) -> None:
        self._r2f[real] = fake
        self._f2r[fake] = real

    def get_fake(self, real: str) -> Optional[str]:
        return self._r2f.get(real)

    def get_real(self, fake: str) -> Optional[str]:
        return self._f2r.get(fake)

    def next_count(self, kind: str) -> int:
        self._counters[kind] = self._counters.get(kind, 0) + 1
        return self._counters[kind]

    @property
    def fake_to_real(self) -> Dict[str, str]:
        return self._f2r

    def snapshot(self) -> dict:
        return {
            "nlp_enabled": nlp_available(),
            "total_entries": len(self._r2f),
            "counters_by_type": dict(self._counters),
            "mappings": dict(self._r2f),
        }


# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------

class Sanitizer:
    """One instance per session."""

    def __init__(self):
        self.table = MappingTable()

    # -----------------------------------------------------------------------
    # Fake value generators
    # -----------------------------------------------------------------------

    def _make_fake(self, kind: str, real: str) -> str:
        n = self.table.next_count(kind)

        if kind == "person":
            first = _FAKE_FIRST[(n - 1) % len(_FAKE_FIRST)]
            last  = _FAKE_LAST[(n - 1) % len(_FAKE_LAST)]
            return f"{first} {last}"

        if kind == "org":
            return _FAKE_ORGS[(n - 1) % len(_FAKE_ORGS)]

        if kind == "national_id":
            return f"FAKE-ID-{n:06d}"

        if kind == "passport":
            return f"XX{n:07d}"

        if kind == "driver_license":
            return f"DL{n:08d}"

        if kind == "iban":
            return f"FAKEIBAN{n:016d}"

        if kind == "ipv4":
            # Pentesting-friendly: loopback range 127.0.0.x
            return f"127.0.0.{min(n, 254)}"

        if kind == "ipv6":
            return "::1"

        if kind == "host_port":
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
            m = re.match(r'(https?://)([^/?#]+)(.*)', real, re.IGNORECASE)
            if m:
                scheme, _host, rest = m.groups()
                return f"{scheme}localhost.localdomain.{n}{rest}"
            return f"http://localhost.localdomain.{n}/"

        if kind == "token":
            return f"FAKE_TOKEN_{n:04d}_{'x' * 8}"

        return f"FAKE_{kind.upper()}_{n:03d}"

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def _nlp_detect(self, text: str) -> List[Tuple[int, int, str, str]]:
        """Run Presidio NLP analysis. Returns [] if unavailable."""
        analyzer = _get_analyzer()
        if not analyzer:
            return []
        try:
            results = analyzer.analyze(text=text, language="en", entities=_NLP_ENTITIES)
            hits = []
            for r in results:
                value = text[r.start:r.end]
                kind = _PRESIDIO_KIND.get(r.entity_type, r.entity_type.lower())
                hits.append((r.start, r.end, value, kind))
            return hits
        except Exception as exc:
            logger.warning("NLP detection error: %s", exc)
            return []

    def _regex_detect(self, text: str) -> List[Tuple[int, int, str, str]]:
        hits = []
        for kind, rx in _REGEX_PATTERNS:
            for m in rx.finditer(text):
                hits.append((m.start(), m.end(), m.group(), kind))
        return hits

    @staticmethod
    def _filter_overlaps(
        hits: List[Tuple[int, int, str, str]]
    ) -> List[Tuple[int, int, str, str]]:
        """Sort hits and remove overlapping spans (keep first / longest)."""
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        filtered: List[Tuple[int, int, str, str]] = []
        last_end = -1
        for h in hits:
            if h[0] >= last_end:
                filtered.append(h)
                last_end = h[1]
        return filtered

    # -----------------------------------------------------------------------
    # Core sanitize / desanitize
    # -----------------------------------------------------------------------

    def sanitize(self, text: str) -> str:
        if not text:
            return text

        # NLP first (higher priority for person/org), then regex
        hits = self._nlp_detect(text) + self._regex_detect(text)
        filtered = self._filter_overlaps(hits)

        if not filtered:
            return text

        result = text
        for start, end, value, kind in reversed(filtered):
            fake = self.table.get_fake(value)
            if fake is None:
                fake = self._make_fake(kind, value)
                self.table.register(value, fake)
            result = result[:start] + fake + result[end:]

        return result

    def desanitize(self, text: str) -> str:
        if not text or not self.table.fake_to_real:
            return text
        result = text
        # Longest fake values first to avoid partial-match collisions
        for fake, real in sorted(
            self.table.fake_to_real.items(), key=lambda x: len(x[0]), reverse=True
        ):
            result = result.replace(fake, real)
        return result

    # -----------------------------------------------------------------------
    # Claude API-aware helpers
    # -----------------------------------------------------------------------

    def _sanitize_content(self, content) -> object:
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
        new = dict(body)
        if "messages" in body:
            new["messages"] = [
                {**msg, "content": self._sanitize_content(msg.get("content", ""))}
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
        new = dict(body)
        if "content" in body:
            new["content"] = [
                {**b, "text": self.desanitize(b.get("text", ""))}
                if b.get("type") == "text" else b
                for b in body["content"]
            ]
        return new
