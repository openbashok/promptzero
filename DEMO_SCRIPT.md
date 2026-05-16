# PromptZero — Demo Script (60–90s pitch)

> Storyboard, narración y comandos para grabar el video corto de PromptZero
> en acción. Protagonista: Claude Code CLI. Prueba: Burp Suite. Dataset:
> pentest engagement (`02_pentest_engagement.json`).

---

## Pre-grabación — checklist (5 minutos)

1. **API key de demo descartable**
   - Crear una nueva en https://console.anthropic.com/settings/keys
   - Nombre: `promptzero-demo-2026-05`
   - Pegarla en `.env` reemplazando `ANTHROPIC_API_KEY=...`
   - *(Después de grabar, borrar la key en la consola)*

2. **`.env` con upstream proxy activo**

   ```bash
   ANTHROPIC_API_KEY=sk-ant-api03-...   # tu demo key
   UPSTREAM_PROXY=http://127.0.0.1:8080
   UPSTREAM_VERIFY=false                # acepta el CA self-signed de Burp
   ```

3. **Burp abierto**
   - `Proxy → Settings → Proxy listeners`: `127.0.0.1:8080` Running
   - `Proxy → Intercept`: **Intercept is off** (botón grande)
   - `Proxy → HTTP history`: tab abierta, lista vacía
   - **Filter**: desmarcá "Show only in-scope items"

4. **Pre-flight automatizado**

   ```bash
   cd /ruta/al/repo
   ./run_demo.sh --check
   ```

   Tiene que decir `Pre-flight OK — ready to record.` con los 5 checks en verde.

5. **Setup de pantalla**
   - Resolución 1920×1080 (16:9) o 2560×1440 (mejor para zoom en YouTube)
   - **Mitad izquierda**: terminal con Claude Code
   - **Mitad derecha**: Burp Suite, tab `Proxy → HTTP history`
   - Font del terminal: 16–18pt para legibilidad
   - Tema oscuro (queda mejor en video)

6. **Grabadora**
   - macOS: `QuickTime Player → File → New Screen Recording`, o **OBS Studio**
   - Audio: micrófono propio o narrar en post

---

## Timeline (90 segundos)

### `0:00 – 0:08` — Hook

**Pantalla:** terminal limpia, sólo el cursor parpadeando.

**Narración (ES):**
> "Usás Claude Code para tu trabajo de seguridad. Pero cada prompt que mandás incluye IPs reales, hostnames reales, nombres de clientes reales — y todo eso le llega a un servidor de terceros. PromptZero arregla eso."

**Alt (EN):** *"You use Claude Code for security work. Every prompt you send has real IPs, real hostnames, real client names — and all of that lands on a third-party server. PromptZero fixes that."*

**Texto en pantalla (overlay):**
> `your prompts → api.anthropic.com → ⚠️`

---

### `0:08 – 0:20` — Setup reveal

**Pantalla:** lado izquierdo terminal, lado derecho Burp HTTP history (vacío).

**Comando en pantalla:**
```bash
./run_demo.sh
```

**Lo que se ve:**
- El pre-flight pasa con sus ✓ verdes
- El banner del proxy aparece:
  ```
  ──────────────────────────────────────────────────
   PromptZero — upstream config
  ──────────────────────────────────────────────────
    upstream_proxy   : http://127.0.0.1:8080
    upstream_verify  : DISABLED  (insecure — demo only)
    → All traffic to api.anthropic.com will route through
      http://127.0.0.1:8080 — watch it land in your
      interception proxy.
  ──────────────────────────────────────────────────
  ```

**Narración:**
> "PromptZero local en `localhost:8000`, con Burp como upstream para que veamos todo lo que sale."

---

### `0:20 – 0:35` — Setup Claude Code

**Pantalla:** abrís una segunda terminal (la principal del recording).

**Comandos en pantalla (uno por uno, tipeados en vivo):**

```bash
export ANTHROPIC_BASE_URL=http://localhost:8000
claude
```

**Narración:**
> "Apunto Claude Code al proxy con una variable de entorno. Punto. Listo."

---

### `0:35 – 0:55` — El prompt con PII real

**Pantalla:** dentro de Claude Code. Pegás (pre-copiado) este prompt:

```
Acabo de terminar un pentest interno en Nexabank Financial S.A.
Encontré un RCE pre-auth en vpn.nexabank.com (203.0.113.10) explotando
CVE-2024-21762. Conseguí admin:Nexabank2024! y pivoteé a
dc01.nexabank.local (10.10.1.5). Ayudame a redactar el correo de
comunicación a Roberto Carlos Silva (r.silva@nexabank.com), CISO
del cliente, en 4 líneas.
```

**Lo que se ve mientras Claude piensa:**
- Burp HTTP history → aparece **una nueva fila**: `POST api.anthropic.com /v1/messages` con status 200

**Narración:**
> "Le paso un finding real: empresa, hostname, IP, CVE, credencial, contacto del CISO. Mientras Claude responde, miren Burp."

---

### `0:55 – 1:15` — The proof

**Pantalla:** zoom en Burp → click en el row del request → tab **Request**.

**Lo que se ve en el body (resaltar con cursor mientras hablás):**
```json
{
  "messages": [{
    "content": "Acabo de terminar un pentest interno en Acme Corp.
                Encontré un RCE pre-auth en localhost.localdomain.1
                (127.0.0.13) explotando CVE-2024-21762.
                Conseguí admin:Nexabank2024! y pivoteé a
                localhost.localdomain.2 (127.0.0.5).
                Ayudame a redactar el correo de comunicación a
                Alice Harrington (user001@fakecorp.local), CISO
                del cliente, en 4 líneas."
  }]
}
```

**Narración mientras señalás:**
> "Anthropic recibió **Acme Corp**, no Nexabank.
> **localhost.localdomain.1**, no vpn.nexabank.com.
> **Alice Harrington**, no Roberto Silva.
> **user001@fakecorp.local**, no el email real."

**Ctrl+F en Burp**, escribís `nexabank` → **0 results**.

**Narración:**
> "Cero resultados. El cliente real no salió de mi máquina."

> *Nota: el CVE-2024-21762 sí aparece sin modificar — es información pública. La password corta `Nexabank2024!` tampoco se sanitiza (regex de tokens captura ≥32 chars). Si querés proteger contraseñas cortas usá `--protect` (ver `examples/pentest_report/`).*

---

### `1:15 – 1:25` — El pay-off

**Pantalla:** volvés a la terminal de Claude Code. Claude ya respondió con un correo perfecto que **menciona los valores reales**:

```
Estimado Roberto Carlos Silva,
Le escribo para informar el hallazgo crítico del pentest en
vpn.nexabank.com (203.0.113.10)…
```

**Narración:**
> "Y yo recibo la respuesta con los **valores reales** restaurados. Claude le habló a 'Alice Harrington', pero PromptZero deshace el mapping en la respuesta. La tabla queda local."

---

### `1:25 – 1:30` — Cierre

**Pantalla:** overlay grande sobre Burp + terminal:

```
PromptZero
Zero trace. Full answer.
github.com/openbashok/promptzero
```

**Narración:**
> "PromptZero. Cero rastro, respuesta completa. Link en la descripción."

---

## Cleanup post-recording

1. **Rotar la API key**
   - https://console.anthropic.com/settings/keys → Delete `promptzero-demo-2026-05`
   - Restaurar tu key normal en `.env`

2. **Limpiar Burp HTTP history** (opcional)
   - `Proxy → HTTP history` → click derecho → Clear history

3. **Editar el video**
   - Cortar las pausas largas
   - Subtítulos opcionales (mismas líneas de narración)
   - Si tu API key aparece en algún frame, blureala (aunque ya esté rotada, da imagen profesional)

---

## Variantes / B-roll opcional (no son los 90s principales)

Si querés piezas extra para landing page o redes:

### B1 — Reporte HTML visual (~30s extra)

```bash
source .venv/bin/activate
python examples/poc/demo_html.py \
    --dataset examples/poc/data/02_pentest_engagement.json \
    --with-claude --task technical \
    --out /tmp/demo-video.html --open
```

Se abre el browser con el reporte coloreado side-by-side. Quedan capturas
buenísimas para LinkedIn / Twitter.

### B2 — Multilenguaje

Repetí el flow con dataset `05_customer_support_chat.json` (chat en español
con DNIs, IBANs, tarjetas) para mostrar que aplica fuera de pentest.

### B3 — La mapping table local

```bash
curl -s http://localhost:8000/sessions/<session-id>/mappings | jq
```

Para mostrar que la tabla real ↔ ficticio nunca sale de la máquina.

---

## Comandos de emergencia (si algo falla en vivo)

```bash
# Re-verificar pre-flights
./run_demo.sh --check

# Matar PromptZero y volver a arrancar
lsof -i :8000 -t | xargs kill -9
./run_demo.sh

# Diagnóstico completo
python examples/poc/diagnose_upstream.py

# Verificar que Burp ve tráfico
curl -x http://127.0.0.1:8080 -k https://api.anthropic.com/v1/models \
    -H "x-api-key: $(grep ANTHROPIC_API_KEY .env | cut -d= -f2)" \
    -H "anthropic-version: 2023-06-01"
```
