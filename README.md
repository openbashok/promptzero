# api-pii

Transparent proxy for the Claude API that sanitizes PII and sensitive data **before** any request leaves your environment, then reverses the substitution on the response.

Real data never hits the wire.

## How it works

```
Your app  →  api-pii (localhost:8000)  →  Claude API
              ↑                              ↓
         desanitize ←————————————————— sanitized response
```

1. Request arrives → **detect** sensitive data via regex patterns
2. **Replace** each real value with a consistent synthetic equivalent and store the mapping
3. Forward the sanitized request to Claude
4. On response → **reverse** all substitutions using the session mapping table
5. Return the restored response to the caller

The mapping is **session-scoped**: pass the same `x-session-id` header across requests to keep synthetic values consistent throughout a conversation.

## What gets sanitized

| Type | Example real | Example fake |
|------|-------------|-------------|
| IPv4 | `192.168.1.50` | `127.0.0.1` |
| IPv6 | `2001:db8::1` | `::1` |
| Hostname / FQDN | `prod.mycompany.com` | `localhost.localdomain.1` |
| URL | `https://api.mycompany.com/v2/users` | `https://localhost.localdomain.2/v2/users` |
| host:port | `db.internal:5432` | `localhost.localdomain.3:5432` |
| Email | `john.doe@company.com` | `user001@fakecorp.local` |
| Phone | `+1-415-555-1234` | `+1-555-000-0001` |
| SSN | `123-45-6789` | `000-00-0001` |
| Credit card | `4111 1111 1111 1234` | `4111-1111-1111-0001` |
| Long token / API key | `sk-ant-api03-...` | `FAKE_TOKEN_0001_xxxxxxxx` |

> **Pentesting context:** IPs and hostnames are mapped to `127.0.0.x` / `localhost.localdomain.x` — this contextualizes tests as local and avoids WAF/IDS blocks on external infrastructure disclosure.

## Quickstart

```bash
# 1. Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# edit .env and set ANTHROPIC_API_KEY

# 3. Run
python main.py
```

## Usage

Just change your SDK base URL from `https://api.anthropic.com` to `http://localhost:8000`.

### Python SDK

```python
import anthropic

client = anthropic.Anthropic(
    api_key="your-key",
    base_url="http://localhost:8000",
)

# Use x-session-id to keep mappings consistent across a conversation
message = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Analyze traffic from 10.0.1.42 to db.prod.corp:5432"}],
    extra_headers={"x-session-id": "my-session-42"},
)
print(message.content[0].text)  # Real IPs restored here
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
    "messages": [{"role": "user", "content": "Review the payload targeting 203.0.113.5"}]
  }'
```

## Management endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check + active session count |
| `GET /sessions/{id}/mappings` | Inspect the mapping table for a session |
| `DELETE /sessions/{id}` | Reset a session (clears all mappings) |

## Known limitations

- **Person names**: not auto-detected (no NLP dependency). Add them manually to the session context or use the custom pattern hook (future).
- **Streaming**: synthetic values are replaced per complete SSE event. Edge case: a fake value split across two events would not be restored (extremely unlikely given typical chunk sizes).
- **Sessions are in-memory**: restarting the server clears all mappings. Persistent sessions (file/Redis) are a future enhancement.
