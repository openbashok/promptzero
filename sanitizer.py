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

# Person / org name pools.
#
# The previous pools used canonical fictional names (Alice Harrington,
# Acme Corp, Globex Industries, Initech, Umbrella, Massive Dynamics,
# …) that Claude has memorised from its training corpus and reaches
# for AS EXAMPLES when writing narrative. e.g. an unrelated reply
# would contain "what if Acme Corp has delegation rights" — even
# though we never sent Acme Corp in the prompt. desanitize() then
# matches those spontaneously-generated tokens against any real value
# we happened to map to that fake (often an NLP false positive) and
# corrupts the user-visible output.
#
# Switching to uncommon names that don't appear in Claude's canonical
# "fictional placeholder" set. They still look like real human / org
# names so the model treats them as opaque proper nouns and does NOT
# emit them as examples in its own writing.
_FAKE_FIRST = [
    "Soren", "Magnus", "Astrid", "Cyrus", "Ingrid", "Kostas",
    "Liesel", "Tarek", "Marit", "Oskar", "Saskia", "Dario",
    "Yelena", "Bjorn", "Anika", "Wojciech", "Petra", "Levente",
    "Sigrid", "Eske", "Mireille", "Anders", "Zsofia", "Henrik",
    "Lena", "Vito",
]
_FAKE_LAST = [
    "Brännström", "Kovalenko", "Halverson", "Nordmann", "Pieterson",
    "Verschueren", "Ravnsborg", "Lindqvist", "Mossberg", "Hjelmstad",
    "Skarholt", "Helgason", "Petrakis", "Lambrechts", "Vasiliou",
    "Eklund", "Bergstrom", "Stensrud", "Faulhaber", "Dziadek",
]
_FAKE_ORGS = [
    "Nordhaven Holdings", "Volken Trade Group", "Halterveld Partners",
    "Mossberg Logistics", "Skarholt Energy", "Eldenrok Industries",
    "Krisburg Capital", "Westmark Solutions", "Trovendia Networks",
    "Quadrika Technologies", "Aurnik Systems", "Bohrendal Group",
    "Cessenray Industries", "Drenholm Capital", "Ferelandt Partners",
    "Gjøvik Maritime", "Hovsund Bank", "Isenbrock Holdings",
    "Jermark Logistics", "Kvelldorf Group",
]

# Pool of visually distinct hostname stems. Each gets `.example.com`
# appended — RFC 2606 reserves example.com for documentation, which the
# model recognises as "placeholder, no real-world facts apply" without
# the localhost/loopback semantics that `.localhost` carries (RFC 6761).
# Loopback-flavoured fakes were causing Claude to downgrade the
# criticality of external pentest findings ("internal-only host, lower
# exposure") even when the real input was an internet-facing service.
_FAKE_HOST_STEMS = [
    # NATO phonetic alphabet (26)
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
    "golf", "hotel", "india", "juliet", "kilo", "lima",
    "mike", "november", "oscar", "papa", "quebec", "romeo",
    "sierra", "tango", "uniform", "victor", "whiskey", "xray",
    "yankee", "zulu",
    # Birds of prey (8)
    "falcon", "eagle", "hawk", "osprey", "kestrel", "raven", "owl", "harrier",
    # Colors (8)
    "crimson", "azure", "emerald", "amber", "indigo", "violet", "sage", "ochre",
]


def _fake_host_stem(n: int) -> str:
    """Return the n-th distinct hostname stem. Cycles with a numeric suffix
    once the pool is exhausted (e.g. alpha, bravo, …, zulu, alpha2, …)."""
    idx = (n - 1) % len(_FAKE_HOST_STEMS)
    cycle = (n - 1) // len(_FAKE_HOST_STEMS)
    base = _FAKE_HOST_STEMS[idx]
    return base if cycle == 0 else f"{base}{cycle + 1}"


# IANA-reserved documentation ranges. We mint synthetic IPs inside
# these — RFC 5737 (`198.51.100.0/24`, `203.0.113.0/24`) for IPv4 and
# RFC 3849 (`2001:db8::/32`) for IPv6 — so the model treats them as
# opaque non-existent targets. The same constants are referenced when
# DETECTING IPs to decide whether the value is already a synthetic and
# should pass through, instead of re-sanitizing our own fake range
# into a fresh fake (the model echoes the range back when discussing
# the redaction convention).
_FAKE_IPV4_PREFIXES = ("198.51.100.", "203.0.113.")
_FAKE_IPV6_PREFIX = "2001:db8:"


def _is_synthetic_ip(value: str, kind: str) -> bool:
    if kind == "ipv4":
        return any(value.startswith(p) for p in _FAKE_IPV4_PREFIXES)
    if kind == "ipv6":
        return value.lower().startswith(_FAKE_IPV6_PREFIX)
    return False

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
    # NRP (Nationality / Religious / Political) was here but Presidio's
    # default recogniser fires on technical text like "tcp" / "udp" /
    # "rdp" and assigns score 0.85, way above any threshold. The
    # detection quality is too low for our use case, and the entity
    # itself is rarely the PII people are trying to redact — drop it.
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
    "icmp", "arp", "mqtt", "sip", "rtp", "rtcp", "ipsec", "wireguard",
    # Web / API
    "api", "rest", "graphql", "json", "yaml", "xml", "html", "css", "dom",
    "csrf", "xss", "cors", "csp", "saml", "oauth", "openid", "oidc", "jwt",
    "url", "uri", "urn", "sse", "websocket", "grpc", "soap", "rpc",
    # Security
    "rce", "lfi", "rfi", "ssrf", "xxe", "ssti", "sqli", "idor", "mfa",
    "totp", "cve", "cvss", "cwe", "owasp", "pii", "gdpr", "pci", "pci-dss",
    "soc", "siem", "edr", "xdr", "mdr", "waf", "ids", "ips", "rbac",
    "tlp", "iam", "kev", "epss", "capec", "stride", "mitre", "att&ck",
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
    # Pentesting tools — the model writes these inside Bash() tool calls
    # and they MUST come through verbatim or commands break ("openssl"
    # → some-fake-name turns into invalid CLI input on the host).
    "nmap", "masscan", "rustscan", "zmap", "naabu", "amass", "subfinder",
    "assetfinder", "findomain", "dnsx", "shuffledns", "puredns", "ffuf",
    "wfuzz", "gobuster", "feroxbuster", "dirb", "dirsearch", "kiterunner",
    "nikto", "wapiti", "skipfish", "arachni", "nuclei", "httpx", "katana",
    "gospider", "gau", "waybackurls", "hakrawler", "sqlmap", "ghauri",
    "xsstrike", "xsshunter", "commix", "wpscan", "joomscan", "droopescan",
    "nessus", "openvas", "qualys", "burp", "burpsuite", "zap", "mitmproxy",
    "wireshark", "tshark", "tcpdump", "ettercap", "bettercap", "responder",
    "impacket", "crackmapexec", "netexec", "bloodhound", "rubeus", "mimikatz",
    "evilginx", "metasploit", "msfconsole", "msfvenom", "armitage", "cobalt",
    "empire", "covenant", "havoc", "sliver", "merlin", "powersploit",
    "nishang", "powerview", "adexplorer", "snaffler", "seatbelt", "winpeas",
    "linpeas", "linenum", "pspy", "chisel", "ligolo", "ssf", "frp",
    "ngrok", "rsockstun", "socat", "iodine", "dnscat", "dnscat2",
    "john", "hashcat", "hashid", "hash-identifier", "ophcrack", "hydra",
    "medusa", "patator", "ncrack", "thc-hydra",
    # General-purpose CLI tools the model invokes in Bash() calls
    "curl", "wget", "httpie", "openssl", "gpg", "ssh-keygen", "ssh-keyscan",
    "ssh-audit", "dig", "host", "nslookup", "drill", "kdig", "ping",
    "traceroute", "mtr", "fping", "hping", "hping3", "nc", "netcat",
    "ncat", "socat", "telnet", "ftp", "scp", "rsync", "sftp", "tftp",
    "testssl", "testssl.sh", "sslyze", "sslscan", "tlssled", "cipherscan",
    "jq", "yq", "xq", "fx", "fzf", "rg", "ripgrep", "ag", "ack",
    "grep", "egrep", "fgrep", "sed", "awk", "tr", "cut", "sort", "uniq",
    "head", "tail", "cat", "tac", "less", "more", "find", "fd", "tree",
    "ls", "wc", "stat", "file", "strings", "xxd", "hexdump", "od",
    "git", "svn", "hg", "fossil", "make", "cmake", "ninja", "bazel",
    "docker", "podman", "kubectl", "helm", "skopeo", "buildah", "crane",
    "terraform", "ansible", "salt", "puppet", "chef", "vault",
    # Common nmap/scanner flags that NLP sometimes tags
    "axfr", "version.bind", "version.bind.", "s_client", "s_server",
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
    # Common multi-word phrases NLP tags as ORG in security text
    "host header", "user agent", "content type", "set cookie",
    "session token", "stack trace", "race condition", "buffer overflow",
    "heap overflow", "use after free", "double free",
    # Time/date words spaCy sometimes tags as PERSON
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
    "sunday", "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug",
    "sep", "oct", "nov", "dec",
    # Common English nouns / verbs / pronouns that NER misfires on when
    # they appear capitalised (sentence starts, bullet headers, table
    # cells, markdown sections). Saw these in real validator reports
    # generated from nmap output → model reply → re-sanitization on
    # next turn, where the model writes things like "Network", "DDoS",
    # "None identified", "Investigate whether…" in narrative.
    #
    # Single words:
    "network", "networks", "system", "systems", "service", "services",
    "server", "servers", "client", "clients", "host", "hosts", "target",
    "targets", "source", "sources", "scan", "scans", "port", "ports",
    "attempt", "attempts", "attempted", "failure", "error", "errors",
    "none", "unknown", "unspecified", "undefined", "default", "custom",
    "investigate", "verify", "confirm", "check", "review", "monitor",
    "analyze", "analyse", "identify", "examine", "probe", "test",
    "recommend", "consider", "evaluate", "validate", "audit",
    "remediation", "mitigation", "exposure", "vulnerability", "severity",
    "critical", "high", "medium", "low", "info", "informational",
    "finding", "findings", "evidence", "indicator", "indicators",
    "summary", "executive", "technical", "report", "reports",
    "credentials", "credential", "session", "sessions",
    "request", "requests", "response", "responses", "header", "headers",
    "payload", "payloads", "traffic", "outbound", "inbound",
    "infrastructure", "perimeter", "boundary", "interface", "interfaces",
    # Security acronyms / classifications that NER often promotes to ORG:
    "ddos", "dos", "mitm", "rce", "lfi", "rfi", "ssrf", "xxe", "csrf",
    "xss", "sqli", "tls", "ssl", "vpn", "saas", "iaas", "paas",
    # Multi-word phrases NER fires on in pentest narrative:
    "investigate whether", "investigate further", "consider whether",
    "verify whether", "confirm whether", "check whether",
    "none identified", "none observed", "none detected", "none reported",
    "not applicable", "not available", "not observed", "not identified",
    "no findings", "no evidence", "no indication",
    "scan failed", "scan failure", "scan timed out", "scan aborted",
    "scan inconclusive", "scan interference", "scan obstruction",
    "scan incomplete", "scan blocked", "scan terminated",
    "executive summary", "key findings", "critical finding",
    "potential exploitation", "potential compromise",
    "external scan", "external assessment", "external recon",
    "external vulnerability", "external reconnaissance",
    "vulnerability assessment", "security assessment",
    # MITRE ATT&CK style tactic / sub-tactic headers — model loves to
    # use these as bullet headings in pentest reports and NER tags
    # them as ORG / PERSON.
    "initial access", "execution", "persistence", "privilege escalation",
    "defense evasion", "credential access", "discovery",
    "lateral movement", "collection", "command and control",
    "exfiltration", "impact", "reconnaissance", "follow-up",
    "follow-up reconnaissance", "service enumeration",
    "host enumeration", "port enumeration", "vulnerability scanning",
    "active reconnaissance", "passive reconnaissance",
    "post-exploitation", "post exploitation",
    "remediation steps", "next steps", "next moves", "next actions",
    "immediate action", "immediate next steps", "recommended actions",
    "tcp/udp", "tcp connect", "udp scan", "syn scan",
    # Generic report-section / pentest-narrative headers the model
    # writes that NER tags as ORG.
    "key findings", "recommended next", "follow-up actions",
    "additional checks", "additional findings", "open questions",
    "scope notes", "engagement notes", "test results", "test plan",
    # DNS record types — model writes them as "NS servers", "MX
    # records" and NER lifts them to ORG.
    "ns servers", "ns server", "ns record", "ns records",
    "mx records", "mx record", "a records", "a record",
    "aaaa record", "aaaa records", "cname", "cname records",
    "txt record", "txt records", "ptr record", "ptr records",
    "soa record", "srv record", "caa record",
    # Common third-person singular verbs spaCy promotes to PERSON
    # when capitalised at the start of a bullet.
    "suggests", "indicates", "confirms", "reveals", "exposes",
    "provides", "includes", "involves", "appears", "seems",
    "shows", "highlights", "demonstrates", "implies", "denotes",
    "represents", "describes", "explains", "depicts", "covers",
    "contains", "matches", "tracks", "monitors", "detects",
    "identifies", "discovers", "enumerates", "extracts", "captures",
    "produces", "generates", "creates", "returns", "yields",
    # Pentest-narrative subjects + adjectives the model uses as topic
    # headers or sentence subjects.
    "attacker", "attackers", "defender", "defenders", "victim",
    "intruder", "adversary", "operator", "operators",
    "subdomain enumeration", "directory enumeration",
    "service enumeration", "user enumeration",
    "direct", "indirect", "internal scan", "external scan",
    "asset inventory", "attack surface", "threat model",
    # Cert transparency / OSINT services we treat as well-known
    # infra; allowlisted in _PUBLIC_HOST_ALLOWLIST below as well.
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
    # IPv6 BEFORE IPv4 so the overlap filter picks the longer match when
    # an IPv6 like 2607:f8b0:4861:a:c9c::1 happens to contain an
    # IPv4-looking digit run. Alternation order matters: regex tries
    # branches left-to-right and accepts the first match at a given
    # position, so we list the longest-possible shapes first.
    ("ipv6", re.compile(
        r'(?<![0-9A-Fa-f:])(?:'
        r'(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}'                 # full 8 groups
        r'|(?:[0-9A-Fa-f]{1,4}:){1,6}(?::[0-9A-Fa-f]{1,4}){1,6}'     # middle ::
        r'|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}'             # leading ::
        r'|(?:[0-9A-Fa-f]{1,4}:){1,7}:'                              # trailing ::
        r'|::'                                                        # bare ::
        r')(?![0-9A-Fa-f:])'
    )),
    # IPv4 strict
    ("ipv4", re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )),
    # host:port — host portion MUST contain at least one dot, otherwise
    # we'd match arbitrary `word:number` patterns including chunks of
    # IPv6 addresses (`34e8:9239`), JSON port fragments, log artifacts,
    # etc. A hostname without a dot isn't a public hostname anyway.
    ("host_port", re.compile(
        r'\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?'
        r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)'
        r':([1-9]\d{1,4})\b'
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

    ("hostname", _HOSTNAME_RE := re.compile(
        r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)'
        r'+(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|es|it|ru|cn|jp|'
        r'br|au|ca|mx|cl|ar|uy|pe|ve|ec|bo|py|cr|gt|hn|ni|pa|do|cu|pr|'
        r'local|internal|corp|lan|localdomain|example)\b',
        re.IGNORECASE,
    )),

    # ------------------------------------------------------------------
    # Long opaque tokens — API keys, JWTs, bearer secrets.
    #
    # Generic ≥32-char alphanumeric runs were too greedy: they ate
    # filesystem paths like
    #   /Users/me/.claude/projects/-Volumes-External-...-test_docker
    # mapping them to FAKE_TOKEN_0001 and confusing the model when it
    # reads back its own memory files. Real secrets are high-entropy:
    # require at least one uppercase AND at least one digit in the run.
    # Path components are usually all-lowercase kebab-case or hex
    # hashes — neither has uppercase letters and digits both.
    #
    # Common forms still matched:
    #   • Anthropic   sk-ant-api03-XYZ...123...
    #   • OpenAI      sk-XYZ...123...
    #   • AWS access  AKIAIOSFODNN7EXAMPLE
    #   • GitHub      ghp_XYZ123...
    #   • JWTs        eyJhbG... (always has mix)
    # ------------------------------------------------------------------

    ("token", re.compile(
        r"\b(?=[A-Za-z0-9_\-]{32,}\b)(?=[A-Za-z0-9_\-]*[A-Z])"
        r"(?=[A-Za-z0-9_\-]*\d)[A-Za-z0-9_\-]+\b"
    )),
]


# ---------------------------------------------------------------------------
# Credential-key patterns
#
# The token regex only catches very long opaque strings (≥32 chars). Real
# passwords are often shorter — `S3cur3P@ss!2026`, `Tr0ub4dor&3`, etc. —
# and would reach the upstream LLM in clear if we relied on the token
# regex alone. These patterns scan for the *key* (`password=`,
# `"secret":`, `Authorization: Bearer`) and capture the value, so the
# detector can replace just the credential value with a fake token
# without mangling the surrounding key name.
#
# Stored as (kind, regex, group_name) tuples — `group_name` is the named
# capture group whose span should be replaced (the credential value
# itself, not the literal `password=` prefix).
# ---------------------------------------------------------------------------

_CREDENTIAL_KV_RE = re.compile(
    r"""
    \b
    (?:password|passwd|pwd|secret|api[_-]?key|apikey
      |access[_-]?token|auth[_-]?token|admin[_-]?token
      |client[_-]?secret|private[_-]?key)
    \s*[:=]\s*
    (?:["']?)                              # optional quote
    (?P<value>[^\s"'`,;)\}\]]{6,})         # the credential value
    """,
    re.IGNORECASE | re.VERBOSE,
)

_CREDENTIAL_HEADER_RE = re.compile(
    r"""
    \b(?:authorization|x-(?:admin|auth|api)[\-_]?(?:token|key)?)
    \s*:\s*
    (?:Bearer\s+|Token\s+|Basic\s+)?
    (?P<value>[A-Za-z0-9._+/=\-]{12,})
    """,
    re.IGNORECASE | re.VERBOSE,
)

_REGEX_PATTERNS_GROUPED = [
    ("credential", _CREDENTIAL_KV_RE, "value"),
    ("credential", _CREDENTIAL_HEADER_RE, "value"),
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


_VALID_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9][A-Za-z0-9\-]*)+$")


# Public infrastructure referenced by Claude Code's system prompt and by
# generic tool output. None of these are private to the user — sanitizing
# them just degrades the model's context with synthetic placeholders for
# well-known domains. Match is case-insensitive and covers subdomains
# (api.anthropic.com matches anthropic.com).
_PUBLIC_HOST_ALLOWLIST = {
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "openai.com",
    "github.com",
    "githubusercontent.com",
    "openbash.com",
    "google.com",
    "nmap.org",
    "python.org",
    "pypi.org",
    "docker.io",
    "ghcr.io",
    "mozilla.org",
    "wikipedia.org",
    "stackoverflow.com",
    "cloudflare.com",
    "ietf.org",
    "rfc-editor.org",
    "owasp.org",
    "mitre.org",
    "nist.gov",
    # IANA-reserved documentation domains (RFC 2606). Treating them as
    # public lets the proxy ignore self-references — without this, when
    # the model writes "example.com" in its reply we sanitize it into
    # `charlie.example.com` (a brand-new fake from our own pool), which
    # is absurd and pollutes the mapping table.
    "example.com", "example.net", "example.org",
    "example.edu", "example",
    # OSINT / cert-transparency / pentest infra that the model
    # routinely references in recon analysis — there's no privacy
    # benefit to redacting these and Claude is more useful with the
    # real name in scope.
    "crt.sh", "shodan.io", "censys.io", "virustotal.com",
    "abuseipdb.com", "haveibeenpwned.com",
}


def _is_public_host(value: str) -> bool:
    """True if the hostname is in the public allowlist (exact match or
    subdomain). These pass through sanitization untouched because they
    reference well-known public infrastructure, not the user's data."""
    v = value.strip().lower().rstrip(".")
    if v in _PUBLIC_HOST_ALLOWLIST:
        return True
    return any(v.endswith("." + suffix) for suffix in _PUBLIC_HOST_ALLOWLIST)


def _is_valid_host(value: str) -> bool:
    """Return True if `value` looks like a real hostname (alphanumeric +
    dots + hyphens, at least one dot, no garbage). Presidio's URL
    recognizer occasionally matches pathological input like a literal
    comma or punctuation — accepting that as a host would pollute the
    mapping table and reverse-replace legitimate fakes in the response."""
    return bool(_VALID_HOST_RE.match(value.strip()))


def _looks_like_real_name_or_org(value: str) -> bool:
    """Return False for strings that look like technical noise rather than
    a person's name or an organization. The aim is to keep recall on
    actual PII while filtering JSON-driven false positives.
    """
    s = value.strip(" .,;:'\"")
    if len(s) < 3:
        return False
    # Real person names and org names are short. Anything over ~60
    # chars is a sentence fragment NER mis-classified ("Direct IP-based
    # scanning if the attacker obtains the IP through other means" →
    # Nordhaven Holdings is the canonical example).
    if len(s) > 60:
        return False
    # Same intuition by word count — real names are 1–5 tokens. Beyond
    # that we're almost certainly looking at a clause, not a name.
    if len(s.split()) > 5:
        return False
    low = s.lower()
    if low in _NLP_DENYLIST:
        return False
    # Reject multi-word phrases whose FIRST token is a common English
    # word in the denylist — real names/orgs don't start with verbs
    # ("Investigate whether"), pronouns ("None reported"), or generic
    # nouns ("Network outage", "Scan blocked"). This catches the long
    # tail of NER false positives without needing every exact phrase
    # in the denylist.
    first_token = low.split(" ", 1)[0]
    if " " in low and first_token in _NLP_DENYLIST:
        return False
    # Reject single-token detections that end in -ing or -tion. These
    # are gerunds / abstract nouns ("Enumeration", "Scanning",
    # "Reconnaissance", "Mitigation") that pentest reports use as
    # bullet headers — never proper nouns.
    if " " not in s and len(s) >= 5 and (
        low.endswith("ing") or low.endswith("tion") or low.endswith("ment")
    ):
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
    # Hostname-shaped strings (`copetel.com.ar`, `vpn.acme.io`) are not
    # names or organizations. NER occasionally fires PERSON / ORG on
    # them — most often when an nmap/tool error message returned via
    # tool_result mentions the host by its bare form ("Copetel is
    # down"). Accepting them would mint a *second* fake for a value
    # that the URL/hostname pipeline already mapped, breaking the 1:1
    # invariant and silently rewriting the model's output.
    if _VALID_HOST_RE.match(s):
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

    def _label_alias_from_existing_host(self, value: str) -> Optional[str]:
        """If `value` is a bare token (one word, no dots) that matches
        the leftmost label of an already-mapped real hostname, return
        the leftmost label of the corresponding fake hostname with the
        casing of the input preserved. Used to keep `Copetel` and
        `copetel.com.ar` pointing at the same fake even when NER
        misfires PERSON / ORG on the bare brand name.

        Returns None if there is no match — caller should fall back to
        the normal fake generator.
        """
        v = value.lower()
        for real_host, fake in self.table._r2f.items():
            kind = self.table.kinds.get(real_host)
            if kind not in ("hostname", "url", "host_port"):
                continue
            # Strip scheme / path / port from both sides so we compare
            # bare hosts regardless of how the entry was registered.
            real_bare = re.sub(r"^https?://", "", real_host, flags=re.I)
            real_bare = real_bare.split("/", 1)[0].split(":", 1)[0]
            fake_bare = re.sub(r"^https?://", "", fake, flags=re.I)
            fake_bare = fake_bare.split("/", 1)[0].split(":", 1)[0]
            real_label = real_bare.split(".", 1)[0].lower()
            if real_label != v:
                continue
            fake_label = fake_bare.split(".", 1)[0]
            # Preserve the input's casing so the substitution reads
            # naturally — `Copetel` → `Alpha`, `copetel` → `alpha`.
            if value[0].isupper():
                return fake_label[:1].upper() + fake_label[1:]
            return fake_label
        return None

    def _make_fake(self, kind: str, real: str) -> str:
        # hostname / host_port / url all reduce to a "real host" entity.
        # Whatever surface form we got (bare host, host:port, full URL),
        # extract the host, look up (or mint) one fake host for it, and
        # reuse the same fake host in every other surface form in the
        # same session. This guarantees coherence: a single real hostname
        # like nike.com always sees the same fake (e.g. alpha.example.com)
        # whether it appears as a bare reference, inside a URL, or with a
        # port — which is what makes desanitize() correctly restore the
        # LLM's free-form mentions of the host alone.
        if kind in ("hostname", "host_port", "url"):
            self.table.next_count(kind)  # for stats
            if kind == "hostname":
                real_host, scheme, rest = real, "", ""
                port = None
            elif kind == "host_port":
                m = re.match(r"^([^:]+):(\d+)$", real)
                real_host = m.group(1) if m else real
                port = m.group(2) if m else "0"
                scheme, rest = "", ""
            else:  # url
                m = re.match(r"(https?://)?([^/?#:]+)(.*)", real, re.IGNORECASE)
                scheme = (m.group(1) or "") if m else ""
                real_host = (m.group(2) or real) if m else real
                rest = (m.group(3) or "") if m else ""
                port = None

            # Reject pathological host extractions. Presidio's URL
            # recognizer sometimes flags non-host punctuation, and
            # accepting them would (a) burn a hostname pool slot on
            # garbage and (b) make desanitize() reverse-replace
            # legitimate fakes in the response with the punctuation.
            if not _is_valid_host(real_host):
                return real
            # Public infrastructure passes through unchanged. Replacing
            # github.com / nmap.org / anthropic.com with a fake host
            # adds no privacy (they're public references in framework
            # text and tool banners) but degrades model context.
            if _is_public_host(real_host):
                return real

            # Get-or-create the fake hostname for this real host. We
            # register the bare-host mapping explicitly so desanitize()
            # works even when the LLM only echoes the host name (no
            # scheme, no path).
            fake_host = self.table.get_fake(real_host)
            if fake_host is None:
                host_n = self.table.next_count("_host_pool")
                fake_host = f"{_fake_host_stem(host_n)}.example.com"
                self.table.register(real_host, fake_host, "hostname")

            if kind == "hostname":
                return fake_host
            if kind == "host_port":
                return f"{fake_host}:{port}"
            # url
            return f"{scheme}{fake_host}{rest}" if scheme else f"{fake_host}{rest}"

        # Skip IPs that are already inside one of our reserved fake
        # ranges (see `_FAKE_IPV4_PREFIXES` / `_FAKE_IPV6_PREFIX`).
        # The model commonly echoes these back when discussing the
        # redaction convention, and sanitizing them again would mint
        # 198.51.100.2 → 198.51.100.3 mappings that pollute the table
        # and make desanitize cycle on its own fakes.
        if _is_synthetic_ip(real, kind):
            return real

        # Single-token person / org detections that match the leftmost
        # label of an already-mapped hostname are almost certainly
        # references to the same entity by its bare brand name
        # (`Copetel` in an nmap error message after we already mapped
        # `copetel.com.ar`). Returning a fresh `Soren Brännström`-style
        # fake here would mint a second alias for the same real entity
        # and let the desanitizer rewrite the wrong span. Reuse the
        # corresponding label of the existing fake instead.
        if kind in ("person", "org") and " " not in real and "." not in real:
            alias = self._label_alias_from_existing_host(real)
            if alias is not None:
                return alias

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
            # RFC 5737 documentation block, see _FAKE_IPV4_PREFIXES.
            # First /24 gives 254 unique fakes; if the session blows
            # past that, wrap into the second /24 (203.0.113.0/24).
            primary, fallback = _FAKE_IPV4_PREFIXES
            if n <= 254:
                return f"{primary}{n}"
            return f"{fallback}{((n - 1) % 254) + 1}"

        if kind == "ipv6":
            # RFC 3849 documentation range, see _FAKE_IPV6_PREFIX.
            return f"{_FAKE_IPV6_PREFIX}:{n:x}"

        # host_port handled in the shared block above

        if kind == "email":
            return f"user{n:03d}@example.com"

        if kind == "phone":
            return f"+1-555-000-{n:04d}"

        if kind == "ssn":
            return f"000-00-{n:04d}"

        if kind == "credit_card":
            return f"4111-1111-1111-{n:04d}"

        # hostname and url handled in the shared block above

        if kind == "token":
            return f"FAKE_TOKEN_{n:04d}_{'x' * 8}"

        if kind == "credential":
            # Render credentials as opaque strings that look like real
            # secrets so the model still treats them as sensitive (instead
            # of "the password is FAKE_CREDENTIAL_001 which is clearly a
            # placeholder, so I'll ignore it…").
            return f"sk-faux-{n:04d}-{'x' * 16}"

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
                # Universal denylist guard — applies regardless of which
                # entity type Presidio assigned. spaCy mis-tags `tcp`
                # as NRP, `Network` as ORG, `Investigate whether` as
                # PERSON; if the bare lowercase value (or its first
                # token, for multi-word phrases) is in our denylist,
                # don't sanitize it.
                low_val = value.lower().strip(" .,;:'\"")
                if low_val in _NLP_DENYLIST:
                    continue
                if " " in low_val and low_val.split(" ", 1)[0] in _NLP_DENYLIST:
                    continue
                if r.entity_type in ("PERSON", "ORGANIZATION") and \
                        not _looks_like_real_name_or_org(value):
                    continue
                # Presidio's PHONE recognizer matches 16-digit credit card
                # groups (4-4-4-4). Reject those — the regex layer will
                # tag them as credit_card.
                if r.entity_type == "PHONE_NUMBER" and \
                        _CC_4x4_RE.fullmatch(value.strip()):
                    continue
                # Same recognizer also fires on IPv4 addresses with
                # punctuation noise — saw `(168.181.187.168` matched as
                # PHONE in nmap output. Reject when stripping
                # non-digit/dot leaves a valid four-octet shape; the
                # IPv4 detector below handles it correctly.
                if r.entity_type == "PHONE_NUMBER":
                    stripped = re.sub(r"[^\d.]", "", value)
                    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", stripped):
                        continue
                # Presidio's URL recognizer is overly greedy in two
                # opposite directions:
                #
                #  1. On code like `psycopg2.connect(`, it stops at
                #     `psycopg2.co` (Colombia ccTLD) and reports a
                #     "URL" — but the next char is a letter and the
                #     whole token is an identifier, not a hostname.
                #
                #  2. On real domains like `nexabank.com`, it
                #     sometimes stops at `nexabank.co` for the same
                #     ccTLD reason, but the next char (`m`) is part
                #     of the actual `.com` TLD.
                #
                # If the next char is alphanumeric or hyphen, try to
                # extend the span to the right and accept the longer
                # value iff `_VALID_HOST_RE` says it's a real hostname.
                # Otherwise drop the hit — it's a code identifier.
                if r.entity_type == "URL":
                    # First, trim surrounding JSON / shell punctuation
                    # that Presidio sometimes swallows ("internal.vpn.com"
                    # arrives with the literal quotes attached, which
                    # breaks _is_valid_host downstream and the whole hit
                    # silently no-ops).
                    s_, e_ = r.start, r.end
                    while s_ < e_ and not (text[s_].isalnum() or text[s_] in ":/"):
                        s_ += 1
                    while e_ > s_ and not (text[e_ - 1].isalnum() or text[e_ - 1] in "/"):
                        e_ -= 1
                    # Then handle the opposite case: Presidio stops at
                    # `psycopg2.co` / `nexabank.co`, but the real string
                    # continues into a longer identifier or TLD. If it
                    # does, extend and accept iff `_HOSTNAME_RE`
                    # validates it (so code identifiers like
                    # `psycopg2.connect` get rejected).
                    if e_ < len(text) and (text[e_].isalnum() or text[e_] == "-"):
                        j = e_
                        while j < len(text) and (text[j].isalnum() or text[j] in "-."):
                            j += 1
                        while j > e_ and text[j - 1] == ".":
                            j -= 1
                        extended = text[s_:j]
                        if _HOSTNAME_RE.fullmatch(extended):
                            e_ = j
                        else:
                            continue
                    value = text[s_:e_]
                    r_start = s_
                    r_end = e_
                else:
                    r_start = r.start
                    r_end = r.end
                kind = _PRESIDIO_KIND.get(r.entity_type, r.entity_type.lower())
                hits.append((r_start, r_end, value, kind))
        return hits

    def _regex_detect(self, text: str) -> List[Tuple[int, int, str, str]]:
        hits = []
        for kind, rx in _REGEX_PATTERNS:
            for m in rx.finditer(text):
                hits.append((m.start(), m.end(), m.group(), kind))
        # Grouped patterns: replace only the named capture group span
        # (e.g. the credential VALUE, not the literal "password=" prefix).
        for kind, rx, group in _REGEX_PATTERNS_GROUPED:
            for m in rx.finditer(text):
                if m.group(group) is None:
                    continue
                s, e = m.span(group)
                hits.append((s, e, m.group(group), kind))
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
                # _make_fake returns the input verbatim when the value
                # doesn't survive validation (pathological host, public
                # allowlisted host, etc). Don't register no-op mappings:
                # they pollute the table, make /stats counters lie, and
                # they let the fuzzer's no-leak check fire spuriously.
                if fake != value:
                    self.table.register(value, fake, kind)
            if fake != value:
                result = result[:start] + fake + result[end:]

        # Final sweep: NLP doesn't always detect every occurrence of a
        # phrase that appears multiple times in the same document (the
        # underlying NER scores can vary with surrounding context).
        # Once we know a real value is sensitive (it landed in the
        # mapping table), enforce the no-leak property globally — any
        # remaining occurrence in the result text gets replaced too.
        # Longest-first to avoid partial-match collisions.
        for real, fake in sorted(
            self.table._r2f.items(), key=lambda x: -len(x[0])
        ):
            if real != fake and real in result:
                result = result.replace(real, fake)

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

    def _sanitize_value(self, val):
        """Recursively sanitize every string inside a JSON-shaped value.
        Used to walk tool_use `input` objects (the model's tool call
        arguments) and any other nested structure where sensitive
        strings might land."""
        if isinstance(val, str):
            return self.sanitize(val)
        if isinstance(val, list):
            return [self._sanitize_value(v) for v in val]
        if isinstance(val, dict):
            return {k: self._sanitize_value(v) for k, v in val.items()}
        return val

    # Tags whose content is harness-internal and must NOT be sanitized.
    # Claude Code (and similar agentic clients) embed their tool docs,
    # skill descriptions, runtime context blurbs and other boilerplate
    # inside <system-reminder>…</system-reminder> tags in regular user
    # messages — running NLP/regex over that text just generates
    # synthetic placeholders for words like "Skill", "Examples", "Bash".
    _PASSTHROUGH_TAG_RE = re.compile(
        r"<system-reminder>.*?</system-reminder>",
        re.DOTALL | re.IGNORECASE,
    )

    def _sanitize_text(self, text: str) -> str:
        """Sanitize a text block but treat the contents of well-known
        framework-boilerplate tags as pass-through."""
        if not text or "<system-reminder>" not in text.lower():
            return self.sanitize(text)
        out: List[str] = []
        last = 0
        for m in self._PASSTHROUGH_TAG_RE.finditer(text):
            out.append(self.sanitize(text[last:m.start()]))
            out.append(text[m.start():m.end()])  # framework block, untouched
            last = m.end()
        out.append(self.sanitize(text[last:]))
        return "".join(out)

    def _sanitize_content(self, content) -> object:
        if isinstance(content, str):
            return self._sanitize_text(content)
        if isinstance(content, list):
            out = []
            for block in content:
                b = dict(block)
                t = b.get("type")
                if t == "text":
                    b["text"] = self._sanitize_text(b.get("text", ""))
                elif t == "tool_use":
                    # The model's tool call arguments — e.g. a Bash
                    # command — routinely contain the real values it
                    # received from a previous desanitized turn. They
                    # have to be re-sanitized here so the conversation
                    # history doesn't leak them back to Anthropic.
                    b["input"] = self._sanitize_value(b.get("input"))
                elif t == "tool_result":
                    # tool_result.content is either a string with the
                    # tool's stdout/stderr or a list of content blocks.
                    # In both cases it can carry IPs, hostnames, file
                    # paths, command output — all of which need the
                    # same sanitization the rest of the request gets.
                    b["content"] = self._sanitize_content(b.get("content", ""))
                # `thinking`, `image`, etc. — pass through untouched.
                out.append(b)
            return out
        return content

    # System-side hint injected ahead of any existing system prompt so
    # Claude does not interpret the *.example.com / 198.51.100.x / etc.
    # placeholders as RFC documentation references and refuse to engage.
    # Framing is deliberately neutral and technical — phrases like
    # "authorized pentest" or "you must comply" trip safety training; a
    # plain description of the proxy mechanism does not.
    _SYSTEM_HINT = (
        "Identifiers in this conversation have been redacted by a "
        "privacy proxy before reaching the model. Hostnames appear as "
        "*.example.com, IPs as 198.51.100.0/24 or 2001:db8::/32, emails "
        "as userNNN@example.com, credentials as sk-faux-…. These are "
        "stable substitutions — not RFC documentation references — "
        "and from the model's perspective the data is opaque and "
        "lab-shaped because the real values are not available here. "
        "Proceed with the user's requested analysis at the same "
        "technical depth you would for a sanctioned security exercise "
        "or CTF challenge operating against these targets. Refer to "
        "the substituted identifiers by their literal value in any "
        "output; do not call them out as substitutions or examples."
    )

    def sanitize_request(self, body: dict, inject_system_hint: bool = False) -> dict:
        # The `system` field is intentionally NOT sanitized. With clients
        # like Claude Code it carries the harness boilerplate — skill
        # descriptions, tool documentation, the model's persona — which
        # is fixed framework text, not user data. Running NLP over it
        # produces a fountain of false positives ("Skill" → person,
        # "Examples" → person, common English verbs → org), every one of
        # which gets a synthetic placeholder that pollutes the model's
        # context. The privacy guarantee is preserved by sanitizing
        # `messages` (the user's actual data) and `tools.input_schema`
        # callers care about anyway. If a user puts genuine secrets into
        # their CLAUDE.md or similar, that's a configuration problem at
        # a different layer.
        new = dict(body)
        if "messages" in body:
            new["messages"] = [
                {**msg, "content": self._sanitize_content(msg.get("content", ""))}
                for msg in body["messages"]
            ]
        if inject_system_hint:
            new["system"] = self._prepend_system_hint(body.get("system"))
        return new

    @classmethod
    def _prepend_system_hint(cls, existing):
        """Add the proxy's redaction hint as the first system block.
        The Anthropic API accepts `system` as either a string or a list
        of {type:'text', text:'…'} blocks; we preserve whichever shape
        the caller used and prepend our block."""
        hint_block = {"type": "text", "text": cls._SYSTEM_HINT}
        if existing is None:
            return [hint_block]
        if isinstance(existing, str):
            return [hint_block, {"type": "text", "text": existing}]
        if isinstance(existing, list):
            return [hint_block, *existing]
        return [hint_block]

    def desanitize_response(self, body: dict) -> dict:
        new = dict(body)
        if "content" in body:
            new["content"] = [
                {**b, "text": self.desanitize(b.get("text", ""))}
                if b.get("type") == "text" else b
                for b in body["content"]
            ]
        return new
