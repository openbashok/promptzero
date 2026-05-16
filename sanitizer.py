"""
sanitizer.py — PII & sensitive-data sanitization engine.

Detection layers (all run on every text, results merged):
  1. NLP  — Presidio + spaCy in EN and ES: detects PERSON, ORGANIZATION,
             phones, emails, national IDs, passports, credit cards, IBANs,
             SSNs, …
  2. Regex — Spanish-speaking world ID formats (AR, CL, ES, UY, CO, MX) +
             international phone formats (+34, +52, +54, +56, +57, +598)
             that Presidio's locale-bound recognizers miss.
  3. Regex — network/infra patterns Presidio misses: IPv4/v6, hostnames,
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

# Minimum Presidio confidence score for an NLP hit to be accepted. Below
# this the noise rate on technical/JSON-heavy text is too high (PERSON /
# ORG false positives on acronyms, field names, library names).
_NLP_MIN_SCORE = 0.4

# Denylist of tokens that spaCy NER frequently mis-tags as PERSON or
# ORGANIZATION on offensive-security and DevOps text. None of these are
# secrets — they're public technology / standard names — so dropping them
# from the mapping table actually IMPROVES Claude's answer quality
# (the model can still reason about JWT, AWS, OWASP, etc.).
_NLP_DENYLIST = {
    # Cloud / infra
    "aws", "gcp", "azure", "cloudflare", "akamai", "fastly", "tor", "nvidia",
    "intel", "amd", "arm",
    # Protocols / standards
    "http", "https", "tls", "ssl", "ssh", "smtp", "imap", "pop3", "dns",
    "tcp", "udp", "ftp", "sftp", "ldap", "rdp", "smb", "ntp", "snmp",
    # Web / API
    "api", "rest", "graphql", "json", "yaml", "xml", "html", "css", "dom",
    "csrf", "xss", "cors", "csp", "saml", "oauth", "openid", "oidc", "jwt",
    "url", "uri", "urn",
    # Security
    "rce", "lfi", "rfi", "ssrf", "xxe", "ssti", "sqli", "idor", "mfa",
    "totp", "cve", "cvss", "cwe", "owasp", "pii", "gdpr", "pci", "pci-dss",
    "soc", "siem", "edr", "xdr", "mdr", "waf", "ids", "ips", "rbac",
    # Roles / titles
    "ciso", "cto", "ceo", "cfo", "coo", "cio", "vp", "dpo", "soc",
    # Servers / databases / frameworks
    "nginx", "apache", "tomcat", "jenkins", "kafka", "redis", "mongodb",
    "postgres", "postgresql", "mysql", "mariadb", "oracle", "splunk",
    "elasticsearch", "kibana", "grafana", "prometheus", "spring", "flask",
    "django", "rails", "laravel", "express", "fastapi", "node", "nodejs",
    "kerberos", "ldap", "ad", "iam",
    # Templating / payloads
    "jinja", "jinja2", "twig", "mustache", "handlebars", "ejs",
    # Misc
    "ui", "ux", "qa", "pr", "ci", "cd", "ml", "ai", "llm", "nlp", "nlu",
    "ipv4", "ipv6", "mac",
    # Windows / AD pentest terms
    "ad", "winrm", "ntlm", "ntlmv2", "kerberos", "krbtgt", "dcsync",
    "dcshadow", "domain admins", "domain admin", "domain controller",
    "active directory", "credential guard", "lsa", "lsa protection",
    "preparedstatement", "xmlconstants", "swagger", "openapi", "vue",
    "gecko", "khtml", "webkit", "blink", "fortinet", "content-security-policy",
    # Common English verbs/adjectives spaCy tags as PERSON
    "internal", "external", "accept", "domain", "forge", "engage",
    "notify", "read", "encode", "arbitrary", "unauthenticated", "thu",
    "client-provisioned", "blind", "not executed", "fictional",
    "detailed evidence", "db credentials", "read swagger", "forge golden",
    "all internal resources effectively exposed",
    "regulatory breach under argentine", "notify argentine dpa",
    "primary active directory dc", "local fortinet", "fortinet ssl vpn",
    "vp of engineering", "sql injection", "blind & union", "customer portal",
    "internal port-scan via ssrf", "summer2023", "welcomenexabank",
    "enable lsa protection", "suspected ssti",
}


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

_analyzer = None                         # AnalyzerEngine instance once loaded
_nlp_languages: List[str] = []           # Languages actually loaded (e.g. ["en", "es"])
_nlp_available: Optional[bool] = None    # None = unchecked


# Multi-language configuration. We try to load both English and Spanish so
# the proxy works for users in AR, CL, ES, UY, CO, MX, BR and elsewhere
# alongside English-language corpora. Smaller fallback models are tried if
# the larger ones aren't installed.
_NLP_MODEL_CANDIDATES: Dict[str, List[str]] = {
    "en": ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"],
    "es": ["es_core_news_lg", "es_core_news_md", "es_core_news_sm"],
}


def _resolve_installed_models() -> List[dict]:
    """Find the best installed spaCy model per language. Returns the list
    Presidio's NlpEngineProvider expects."""
    import importlib  # noqa: PLC0415

    selected: List[dict] = []
    for lang, candidates in _NLP_MODEL_CANDIDATES.items():
        for name in candidates:
            try:
                importlib.import_module(name)
            except ImportError:
                continue
            selected.append({"lang_code": lang, "model_name": name})
            break
    return selected


def _get_analyzer():
    """Lazy-load Presidio AnalyzerEngine with all available languages.

    Falls back gracefully:
      • Both en + es models present  → multilingual analyzer
      • Only one model present       → single-language analyzer
      • Neither present              → NLP disabled, regex layer still runs
    """
    global _analyzer, _nlp_available, _nlp_languages
    if _nlp_available is not None:
        return _analyzer

    try:
        from presidio_analyzer import AnalyzerEngine                    # noqa: PLC0415
        from presidio_analyzer.nlp_engine import NlpEngineProvider      # noqa: PLC0415

        models = _resolve_installed_models()
        if not models:
            raise RuntimeError(
                "No spaCy models found. Install at least one of: "
                "en_core_web_lg, es_core_news_lg "
                "(python -m spacy download <name>)."
            )

        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": models,
        })
        nlp_engine = provider.create_engine()

        supported = [m["lang_code"] for m in models]
        _analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=supported,
        )
        _nlp_languages = supported
        _nlp_available = True
        logger.info("Presidio NLP engine ready — languages: %s", supported)
    except Exception as exc:
        _nlp_available = False
        _nlp_languages = []
        logger.warning(
            "NLP detection disabled (%s). "
            "To enable: pip install presidio-analyzer && "
            "python -m spacy download en_core_web_lg && "
            "python -m spacy download es_core_news_lg",
            exc,
        )
    return _analyzer


def nlp_available() -> bool:
    _get_analyzer()
    return bool(_nlp_available)


def nlp_languages() -> List[str]:
    """Languages the NLP layer is configured for. Empty if NLP disabled."""
    _get_analyzer()
    return list(_nlp_languages)


# ---------------------------------------------------------------------------
# Regex patterns — network / infra / tokens (what Presidio misses)
# ---------------------------------------------------------------------------

_REGEX_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # ------------------------------------------------------------------
    # Network & web — broad-match patterns first so narrower ones don't
    # break them apart (the overlap filter keeps the longest hit).
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Financial — credit cards, SSN (US)
    # ------------------------------------------------------------------

    ("credit_card", re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b')),
    ("ssn", re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),

    # ------------------------------------------------------------------
    # National ID formats — Spanish-speaking world
    # Order matters: more specific (with prefix) before more generic.
    # ------------------------------------------------------------------

    # Argentina — DNI prefix: "DNI 12.345.678" or "DNI 12345678"
    ("national_id_ar_dni", re.compile(
        r'\bDNI\s?N?º?\s?\d{1,2}\.?\d{3}\.?\d{3}\b', re.IGNORECASE,
    )),
    # Argentina — CUIT/CUIL: "20-12345678-9"
    ("national_id_ar_cuit", re.compile(r'\b(?:20|23|24|27|30|33|34)-\d{8}-\d\b')),
    # Chile — RUT: "12.345.678-K" or "12345678-9"
    ("national_id_cl_rut", re.compile(
        r'\b\d{1,2}\.\d{3}\.\d{3}-[\dkK]\b'
    )),
    # Spain — DNI/NIE: 8 digits + check letter (DNI), or X/Y/Z + 7 digits + letter (NIE)
    ("national_id_es", re.compile(
        r'\b[XYZ]?\d{7,8}[A-HJ-NP-TV-Z]\b', re.IGNORECASE,
    )),
    # Uruguay — CI: "1.234.567-8"
    ("national_id_uy", re.compile(r'\b\d\.\d{3}\.\d{3}-\d\b')),
    # Colombia — Cédula: "CC 1.234.567" up to 10 digits with dot separators
    ("national_id_co_cc", re.compile(
        r'\bCC\s?\d{1,3}(?:\.\d{3}){1,3}\b', re.IGNORECASE,
    )),
    # Mexico — CURP (18 chars, well-formed)
    ("national_id_mx_curp", re.compile(
        r'\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b'
    )),
    # Mexico — RFC (13 chars person, 12 chars company) — strict suffix
    ("national_id_mx_rfc", re.compile(
        r'\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{2}[A-Z0-9\d]\b'
    )),

    # ------------------------------------------------------------------
    # Phone numbers — international formats for AR, CL, CO, ES, MX, UY,
    # BR, plus the US/CA fallback. We match the most-specific prefixed
    # formats first.
    # ------------------------------------------------------------------

    # +CC <area> <rest> — international format for LatAm + ES + BR.
    # Covers: +54 9 11 1234-5678, +56 9 1234 5678, +598 99 123 456,
    #         +57 300 123 4567, +52 1 55 1234 5678, +55 11 91234-5678,
    #         +34 612 345 678.
    # Same `phone` kind as the US fallback below so a single counter and
    # a single fake format (+1-555-000-NNNN) are used across both.
    ("phone", re.compile(
        r'(?<!\d)\+(?:34|52|54|56|57|55|598)'
        r'(?:[\s.\-]?\d){7,12}\b'
    )),
    # US / Canada fallback
    ("phone", re.compile(
        r'\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b'
    )),

    # ------------------------------------------------------------------
    # Hostnames / FQDNs — broadened TLD list incl. LATAM ccTLDs
    # ------------------------------------------------------------------

    ("hostname", re.compile(
        r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)'
        r'+(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|es|it|ru|cn|jp|'
        r'br|au|ca|mx|cl|ar|uy|pe|ve|ec|bo|py|cr|gt|hn|ni|pa|do|cu|pr|'
        r'local|internal|corp|lan|localdomain|example)\b',
        re.IGNORECASE,
    )),

    # ------------------------------------------------------------------
    # Long opaque tokens — API keys, secrets (≥32 chars)
    # ------------------------------------------------------------------

    ("token", re.compile(r'\b[A-Za-z0-9_\-]{32,}\b')),
]

# ---------------------------------------------------------------------------
# NLP false-positive filter
# ---------------------------------------------------------------------------

# 16-digit credit card pattern in 4-4-4-4 groups — used to reject
# Presidio's PHONE_NUMBER hits that actually match a credit card layout.
_CC_4x4_RE = re.compile(r"\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}")


# spaCy's NER fires on a lot of noise when given technical / JSON text:
# CVSS vector strings, CVE identifiers, English verbs in titles, library
# names, etc. This filter drops the most common false positives so that
# Claude still understands technical terms in the sanitized prompt.
_NAME_FORBIDDEN_CHARS = set("0123456789/:<>[]{}()*=+\\|`~^_;\"")


def _looks_like_real_name_or_org(value: str) -> bool:
    """Return False for strings that look like technical noise rather than
    a person's name or an organization. The aim is to keep recall on
    actual PII while filtering JSON-driven false positives.
    """
    s = value.strip(" .,;:'\"")
    if len(s) < 3:
        return False
    if s.lower() in _NLP_DENYLIST:
        return False
    if any(c in _NAME_FORBIDDEN_CHARS for c in s):
        return False
    # Real names and orgs almost always start with an uppercase letter
    if not s[0].isupper():
        return False
    # Must contain at least one lowercase letter — single uppercase tokens
    # like "DCSYNC", "DNS", "PROD" are technical, not names.
    if not any(c.islower() for c in s):
        return False
    return True


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

class MappingTable:
    """Bidirectional real ↔ fake, scoped to one session.

    Also tracks the detection kind (person, org, ipv4, …) per real value
    so callers can colour or group mappings — used by demo_html.py.
    """

    def __init__(self):
        self._r2f: Dict[str, str] = {}
        self._f2r: Dict[str, str] = {}
        self._kinds: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}

    def register(self, real: str, fake: str, kind: Optional[str] = None) -> None:
        self._r2f[real] = fake
        self._f2r[fake] = real
        if kind:
            self._kinds[real] = kind

    def get_fake(self, real: str) -> Optional[str]:
        return self._r2f.get(real)

    def get_real(self, fake: str) -> Optional[str]:
        return self._f2r.get(fake)

    def get_kind(self, real: str) -> Optional[str]:
        return self._kinds.get(real)

    def next_count(self, kind: str) -> int:
        self._counters[kind] = self._counters.get(kind, 0) + 1
        return self._counters[kind]

    @property
    def fake_to_real(self) -> Dict[str, str]:
        return self._f2r

    @property
    def kinds(self) -> Dict[str, str]:
        return self._kinds

    def snapshot(self) -> dict:
        return {
            "nlp_enabled": nlp_available(),
            "total_entries": len(self._r2f),
            "counters_by_type": dict(self._counters),
            "mappings": dict(self._r2f),
            "kinds": dict(self._kinds),
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

        if kind == "national_id_ar_dni":
            return f"DNI 11.111.{n:03d}"
        if kind == "national_id_ar_cuit":
            return f"20-11111{n:03d}-1"
        if kind == "national_id_cl_rut":
            return f"11.111.{n:03d}-1"
        if kind == "national_id_es":
            return f"X{n:07d}A"
        if kind == "national_id_uy":
            return f"1.111.{n:03d}-1"
        if kind == "national_id_co_cc":
            return f"CC 1.111.{n:03d}"
        if kind == "national_id_mx_curp":
            return f"FAKE{n:06d}HDFXXX{n%10}{n%10}"
        if kind == "national_id_mx_rfc":
            return f"FAKE{n:06d}XX{n%10}"

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
        """Run Presidio NLP analysis in every available language.

        We don't try to auto-detect the language — instead we run the
        analyzer once per loaded language and merge results. The overlap
        filter deduplicates spans found in both languages.
        Returns [] if NLP is unavailable.
        """
        analyzer = _get_analyzer()
        if not analyzer:
            return []
        hits: List[Tuple[int, int, str, str]] = []
        for lang in (_nlp_languages or ["en"]):
            try:
                results = analyzer.analyze(
                    text=text,
                    language=lang,
                    entities=_NLP_ENTITIES,
                    score_threshold=_NLP_MIN_SCORE,
                )
            except Exception as exc:
                logger.warning("NLP detection error for lang=%s: %s", lang, exc)
                continue
            for r in results:
                value = text[r.start:r.end]
                if r.entity_type in ("PERSON", "ORGANIZATION") and \
                        not _looks_like_real_name_or_org(value):
                    continue
                # Presidio's PHONE recognizer matches 16-digit credit card
                # groups (4-4-4-4). Reject those — the regex layer will
                # tag them as credit_card.
                if r.entity_type == "PHONE_NUMBER" and \
                        _CC_4x4_RE.fullmatch(value.strip()):
                    continue
                kind = _PRESIDIO_KIND.get(r.entity_type, r.entity_type.lower())
                hits.append((r.start, r.end, value, kind))
        return hits

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
                self.table.register(value, fake, kind)
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
