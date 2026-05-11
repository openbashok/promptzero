# document_summary

Summarize any document (PDF, DOCX, TXT, log, CSV) via the api-pii proxy.
All PII and sensitive data is anonymized before reaching Claude and restored
in the final summary — the real data never leaves your environment.

## Setup

```bash
# api-pii must be running first
cd ../../ && python main.py &

# Install this example's dependencies
pip install -r requirements.txt
```

## Usage

```bash
# General summary
python summarize.py contrato.pdf

# Executive summary in Spanish
python summarize.py informe.docx --mode executive --lang es

# Technical summary of a log file
python summarize.py access.log --mode technical

# Reuse an existing session (same mapping table across calls)
python summarize.py report.pdf --session my-project-42
```

## What gets anonymized

The proxy automatically handles everything before the text reaches Claude:

| Found in document | Sent to Claude as |
|---|---|
| `Juan García` | `Bob Calloway` |
| `Empresa S.A.` | `Acme Corp` |
| `juan@empresa.com` | `user001@fakecorp.local` |
| `+54 11 4444-5555` | `+1-555-000-0001` |
| `DNI 28.456.123` | `FAKE-ID-000001` |
| `192.168.1.45` | `127.0.0.1` |
| `db.prod.empresa.com` | `localhost.localdomain.1` |

The summary comes back with **all real values restored**.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `API_PII_URL` | `http://localhost:8000` | api-pii proxy address |
| `ANTHROPIC_API_KEY` | — | Your Claude API key |
| `MODEL` | `claude-opus-4-6` | Claude model to use |
| `MAX_TOKENS` | `2048` | Max tokens in the summary |
