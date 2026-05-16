# PromptZero — Proof of Concept

**Datasets ficticios + scripts de demostración para validar y mostrar la sanitización end-to-end.**

Este directorio contiene todo lo necesario para reproducir, frente a una audiencia o en
una pipeline de validación, la promesa central de PromptZero:

> *El modelo ve ficción. Vos recibís la realidad.*

Cada archivo bajo `data/` es **100% ficticio** — generado expresamente para probar la
herramienta. Nada de lo que verás (nombres, IPs, hostnames, tarjetas, DNIs, IBANs,
payloads, credenciales) corresponde a una persona, empresa o sistema real.

---

## ¿Qué demuestra esta PoC?

| Capa | Qué se ve | Qué garantiza PromptZero |
|---|---|---|
| **Personal data**   | Nombres, mails, teléfonos, DNI, IBAN, tarjetas, direcciones, claves SSH | PII no llega a la API |
| **Pentest técnico** | HTTP request/response, parámetros, payloads de inyección, credenciales obtenidas, CVEs | Infra y hallazgos siguen privados |
| **Catálogo de inyecciones** | SQLi, XSS, SSRF, XXE, LDAP, SSTI, Path Traversal, NoSQL, Deserialization, IDOR, JWT confusion, Prototype Pollution | Payloads se procesan sin filtrar tu target real |
| **Incident response** | Logs SIEM, IOCs, timeline de movimiento lateral | Identidades y red interna nunca se exponen |
| **Soporte al cliente** | Chats con DNI/tarjeta/IBAN/teléfono | Datos del cliente nunca cruzan el perímetro |

---

## Datasets ficticios

```
data/
├── 01_personal_records.json       # HR + CRM export (PII pesado)
├── 02_pentest_engagement.json     # Engagement completo, HTTP req/res, 7 findings
├── 03_injection_catalog.json      # 17 categorías de inyección con payloads
├── 04_incident_response.json      # Incidente P1 con SIEM, IOCs, timeline
└── 05_customer_support_chat.json  # Transcripciones de chat con PII
```

Detalle por archivo:

### `01_personal_records.json`
Export ficticio del área de RR.HH. y CRM de **Nexabank Financial S.A.** (empresa inventada).
Incluye empleados con DNI argentino, IBAN, tarjetas, direcciones, mails personales y
corporativos, handles de GitHub/Slack, fingerprints SSH, claves AWS de ejemplo, y tres
clientes VIP con saldos altos.

### `02_pentest_engagement.json`
Engagement completo de pentest contra Nexabank, con 7 findings detallados:

1. RCE pre-auth en SSL VPN (CVE-2024-21762)
2. Blind SQL Injection en portal de clientes
3. AS-REP Roasting + Kerberoasting → Domain Admin
4. SSRF en API REST con acceso a metadata AWS
5. XXE en upload de extractos
6. Stored XSS en chat de soporte
7. SSTI Jinja2 → RCE

Cada finding trae **request HTTP completo** (método, URL, headers, body), **response**
(status, headers, body excerpt, indicators), **payloads** listados, **steps de
explotación**, **credenciales obtenidas** y **remediación**. Es el escenario más rico
de la PoC.

### `03_injection_catalog.json`
17 categorías de inyección, cada una con:
- target URL ficticia
- parámetro vulnerable (nombre, ubicación, formato esperado)
- request template
- 4–8 payloads concretos
- evidencia/observable

Cubre SQLi (UNION + blind), XSS (refl + stored), Command Injection, SSRF, XXE,
LDAP, SSTI (Jinja2 + Twig), Path Traversal, NoSQL Injection (Mongo), Insecure
Deserialization (Java), IDOR, Open Redirect, JWT alg confusion, Prototype
Pollution.

### `04_incident_response.json`
Incidente P1: compromiso de AD detectado. Trae detección inicial (regla Splunk +
evento Sysmon crudo), IOCs (IPs, dominios, hashes, registry, tareas programadas,
cuentas), **timeline de movimiento lateral** paso a paso con timestamps reales, acciones
de contención ya ejecutadas, notificaciones regulatorias (Ley 25.326, BCRA, GDPR) y
extractos de SIEM.

### `05_customer_support_chat.json`
Cuatro transcripciones de chat de soporte (WhatsApp, web chat, mail, llamada
entrante) con DNI, IBAN, tarjetas y teléfonos por todos lados. Útil para demostrar
sanitización en texto conversacional libre.

---

## Scripts

### `demo_html.py` — Reporte visual (ideal para videos y pitches)

Genera un archivo HTML self-contained que abrís en cualquier browser. Muestra
con highlights coloreados:

- panel izquierdo: dataset **original** con cada PII marcada en color
- panel derecho: dataset **sanitizado** (exactamente lo que Claude recibe), con
  los reemplazos en el mismo color
- chips de resumen por categoría (`person · 6`, `org · 5`, `ipv4 · 14`, …)
- tabla completa real ↔ ficticio, agrupada por categoría
- opcionalmente: sección end-to-end con Claude (response cruda con valores
  sintéticos y response desanonimizada)

Al hacer hover sobre cualquier valor resaltado se ilumina su contraparte en el
otro panel. Es lo más impactante para grabar a pantalla.

```bash
# Reporte por defecto (pentest engagement)
python demo_html.py
open report.html       # macOS: abre el archivo

# Otro dataset, con --open para abrirlo solo al terminar
python demo_html.py --dataset data/01_personal_records.json --open

# End-to-end con Claude (necesita el proxy corriendo + API key)
python demo_html.py --with-claude --task triage \
  --dataset data/04_incident_response.json --out ir.html

# Chat de soporte en español → summary
python demo_html.py --dataset data/05_customer_support_chat.json \
  --with-claude --task summary --out chat.html --open
```

El HTML resultante (~50–200 KB) no depende de ningún CDN ni recurso externo —
se renderiza igual con la máquina offline.

### `demo_local.py` — Demo standalone, sin tocar Claude

Corre el `Sanitizer` localmente y muestra las 3 etapas en pantalla:

```
① ORIGINAL      — lo que hay en tu disco
② SANITIZED     — lo que Claude vería
③ DESANITIZED   — lo que tu app recibe
+ MAPPING TABLE — auditoría completa real ↔ ficticio
```

**No requiere API key ni proxy en ejecución.** Ideal para pitchear, para tests en CI
o para verificar que la herramienta cumple con tu DLP antes de habilitarla.

```bash
# Demo por defecto (pentest engagement)
python demo_local.py

# Otro dataset
python demo_local.py data/01_personal_records.json

# Más texto visible por sección
python demo_local.py data/03_injection_catalog.json --max-preview 5000

# Salida JSON (útil en CI / scripts)
python demo_local.py data/04_incident_response.json --json
```

### `demo_claude.py` — End-to-end real contra `api.anthropic.com`

Manda el dataset a Claude **a través** del proxy local y muestra las 4 etapas:

```
① ORIGINAL              — input de tu disco
② SANITIZED             — exactamente lo que recibió api.anthropic.com
③ RAW CLAUDE RESPONSE   — respuesta de Claude con valores sintéticos
④ DESANITIZED RESPONSE  — lo que tu app efectivamente ve (real restaurado)
```

**Prerequisitos:**

```bash
# 1) Proxy corriendo en localhost:8000
cd ../../ && python main.py

# 2) Dependencias
pip install -r requirements.txt

# 3) API key real (forwardeada por el proxy a api.anthropic.com)
cp ../../.env.example ../../.env  # y editar ANTHROPIC_API_KEY
```

**Uso:**

```bash
# Análisis técnico del engagement de pentest (default)
python demo_claude.py

# Summary general de PII de RR.HH.
python demo_claude.py --dataset data/01_personal_records.json --task summary

# Brief ejecutivo del incident response
python demo_claude.py --dataset data/04_incident_response.json --task executive

# Triage SOC del incidente
python demo_claude.py --dataset data/04_incident_response.json --task triage

# Guardar transcript completo a archivo
python demo_claude.py --out demo-transcript.txt
```

Tareas disponibles (`--task`): `technical` | `executive` | `summary` | `triage`.

---

## Lectura recomendada del output

Mirá las tres cosas siguientes en cualquier dataset para tener evidencia objetiva
de que la sanitización funciona:

1. **MAPPING TABLE** — cada par real ↔ ficticio. Si una sola fila tiene un nombre
   o IP real en el lado izquierdo y un valor sintético en el derecho, el proxy
   está haciendo su trabajo en ese campo.
2. **SANITIZED preview** — buscá ahí cualquier valor del original (`grep
   nexabank.com` por ejemplo). No deberías encontrarlo.
3. **DESANITIZED preview** — los valores reales aparecen perfectamente
   reconstruidos en la respuesta.

---

## Sobre la detección NLP

Sin Presidio + spaCy instalados, PromptZero detecta vía regex: IPs, hostnames,
emails, tarjetas, host:port, URLs, tokens largos, SSN, teléfonos US-format.

Con la capa NLP activa (recomendada para datos reales), suma: **PERSON,
ORGANIZATION**, teléfonos internacionales, IDs nacionales (ES_NIF, NRP),
pasaportes, drivers licenses, IBAN.

Para activar NLP localmente:

```bash
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg
```

El script `demo_local.py` reporta el estado de NLP en su header — si decís
"NLP: on" en el demo en vivo, la audiencia entiende inmediatamente por qué
los nombres también desaparecen.

---

## Aviso

Todos los valores en `data/` son **inventados**. Cualquier coincidencia con
personas, empresas, infraestructura o vulnerabilidades reales es accidental.
El propósito es exclusivamente demostrar el funcionamiento de PromptZero;
**no usar estos payloads contra sistemas que no sean propios y con autorización
escrita.**
